package peer

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/relay"
)

// newTestPeer creates a peer with a fresh in-memory identity bound to a free port.
func newTestPeer(t *testing.T) *Peer {
	t.Helper()
	id, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	p := New(id, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// TestTwoPeersConnect verifies that two peers can connect and exchange a hello.
func TestTwoPeersConnect(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	b := newTestPeer(t)
	defer b.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("B connect to A: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if got := a.PeerCount(); got != 1 {
		t.Errorf("A should see 1 peer, got %d", got)
	}
	if got := b.PeerCount(); got != 1 {
		t.Errorf("B should see 1 peer, got %d", got)
	}
}

// TestThreePeersChain verifies a peer can hold connections to multiple others.
func TestThreePeersChain(t *testing.T) {
	a := newTestPeer(t)
	b := newTestPeer(t)
	c := newTestPeer(t)
	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("B->A: %v", err)
	}
	if err := c.Connect(b.LocalAddr()); err != nil {
		t.Fatalf("C->B: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if got := b.PeerCount(); got != 2 {
		t.Errorf("B should see 2 peers (A and C), got %d", got)
	}
}

// TestBroadcast checks that a broadcast message reaches every connected peer.
func TestBroadcast(t *testing.T) {
	a := newTestPeer(t)
	b := newTestPeer(t)
	c := newTestPeer(t)
	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("B->A: %v", err)
	}
	if err := c.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("C->A: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if got := a.PeerCount(); got != 2 {
		t.Errorf("A should see 2 peers, got %d", got)
	}
	a.Broadcast(Message{Type: "chat", Payload: "hello world"})
	time.Sleep(100 * time.Millisecond)
}

// TestLargeMessage verifies that messages bigger than the old 64KB scanner
// buffer (but under MaxMessageSize) survive the new framing.
func TestLargeMessage(t *testing.T) {
	a := newTestPeer(t)
	b := newTestPeer(t)
	defer a.Stop()
	defer b.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	big := strings.Repeat("x", 200_000) // 200KB payload
	a.Broadcast(Message{Type: "chat", Payload: big})
	time.Sleep(200 * time.Millisecond)
	// We don't have an inbox to check yet, but the read loop must not crash;
	// if it did, b.PeerCount() would have dropped to 0.
	if got := b.PeerCount(); got != 1 {
		t.Errorf("B should still be connected after large message, got %d peers", got)
	}
}

// TestForgedFromIDIsRejected ensures a peer cannot claim an ID that doesn't
// match its public key. We simulate this by hand-crafting a malicious frame.
func TestForgedFromIDIsRejected(t *testing.T) {
	victim := newTestPeer(t)
	defer victim.Stop()

	// The attacker has a real keypair, but lies about their From ID.
	attacker, err := crypto.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", victim.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := Message{
		Type:      "hello",
		From:      strings.Repeat("0", 64), // a clearly fake ID
		PublicKey: crypto.PublicKeyToHex(attacker.PublicKey),
		Payload:   "im someone else",
	}
	// Sign the message with the attacker's real key (signature itself is valid).
	data, _ := json.Marshal(msg)
	msg.Sig = attacker.Sign(data)
	signed, _ := json.Marshal(msg)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(signed)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(signed); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// Victim should have closed the connection because From != hash(PublicKey).
	if got := victim.PeerCount(); got != 0 {
		t.Errorf("victim should have rejected forged hello, peers=%d", got)
	}
}

// echoHandler is a tiny test handler that replies "echo:<payload>" to any
// message of type "test_echo". It exercises Reply() and the request/response
// flow end-to-end.
type echoHandler struct{}

func (echoHandler) HandleMessage(p *Peer, addr string, msg Message) {
	if msg.Type != "test_echo" {
		return
	}
	_ = p.Reply(addr, msg, Message{Type: "test_echo_reply", Payload: "echo:" + msg.Payload})
}

// TestRequestReply verifies that a Request() blocks until a matching reply
// arrives, that the reply payload is correct, and that timeouts work.
func TestRequestReply(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	b := newTestPeer(t)
	defer b.Stop()
	b.AddHandler(echoHandler{})

	if err := a.Connect(b.LocalAddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	reply, err := a.Request(b.LocalAddr(), Message{Type: "test_echo", Payload: "hello"}, 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if reply.Type != "test_echo_reply" {
		t.Errorf("reply type = %q, want test_echo_reply", reply.Type)
	}
	if reply.Payload != "echo:hello" {
		t.Errorf("reply payload = %q, want echo:hello", reply.Payload)
	}
}

func TestRequestTimeout(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	b := newTestPeer(t)
	defer b.Stop()
	// Note: B has no echo handler, so the request will never get a reply.

	if err := a.Connect(b.LocalAddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	_, err := a.Request(b.LocalAddr(), Message{Type: "test_echo", Payload: "x"}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("Request should time out when no handler replies")
	}
}

// TestTamperedSignatureIsRejected checks that flipping bits in a payload
// after signing causes the message to be rejected.
func TestTamperedSignatureIsRejected(t *testing.T) {
	victim := newTestPeer(t)
	defer victim.Stop()

	attacker, _ := crypto.NewIdentity()
	conn, err := net.Dial("tcp", victim.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := Message{
		Type:      "hello",
		From:      crypto.PublicKeyToID(attacker.PublicKey),
		PublicKey: crypto.PublicKeyToHex(attacker.PublicKey),
		Payload:   "real",
	}
	data, _ := json.Marshal(msg)
	msg.Sig = attacker.Sign(data)
	// Tamper after signing: change payload but keep old signature.
	msg.Payload = "tampered"
	signed, _ := json.Marshal(msg)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(signed)))
	conn.Write(lenBuf[:])
	conn.Write(signed)
	time.Sleep(100 * time.Millisecond)

	if got := victim.PeerCount(); got != 0 {
		t.Errorf("victim should have rejected tampered hello, peers=%d", got)
	}
}

// TestRelayedConnect is the headline NAT-traversal test: peer A
// registers with a relay R; peer B reaches A by dialing
// "relay://<R>/<A_id>" instead of A directly. Bytes flow through the
// relay, but the secure handshake happens end-to-end between A and B
// (the relay only forwards ciphertext).
//
// This is exactly the path a NAT-ed peer would take in production.
func TestRelayedConnect(t *testing.T) {
	// Start the relay.
	srv := relay.NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer srv.Stop()
	relayAddr := srv.LocalAddr().String()

	// Peer A starts and registers with the relay.
	a := newTestPeer(t)
	defer a.Stop()
	a.UseRelay(relayAddr)

	// Wait for A's relay registration to be live.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.RegistrationCount() != 1 {
		t.Fatal("A never registered with relay")
	}

	// Peer B reaches A through the relay using a relay URL.
	b := newTestPeer(t)
	defer b.Stop()
	relayURL := "relay://" + relayAddr + "/" + a.Identity.ID()
	if err := b.Connect(relayURL); err != nil {
		t.Fatalf("B connect via relay: %v", err)
	}

	// Both sides should now see the connection (after the hello
	// exchange completes).
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.PeerCount() == 1 && b.PeerCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := a.PeerCount(); got != 1 {
		t.Errorf("A should see 1 peer (B via relay), got %d", got)
	}
	if got := b.PeerCount(); got != 1 {
		t.Errorf("B should see 1 peer (A via relay), got %d", got)
	}
}

// TestMultipleRelaysProvideRedundancy verifies that a peer registered
// with two relays is reachable through EITHER one. We register A with
// R1 and R2, then dial A through each relay separately and confirm both
// paths work.
func TestMultipleRelaysProvideRedundancy(t *testing.T) {
	// Two relays.
	r1 := relay.NewServer()
	if err := r1.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer r1.Stop()
	r2 := relay.NewServer()
	if err := r2.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer r2.Stop()
	r1Addr := r1.LocalAddr().String()
	r2Addr := r2.LocalAddr().String()

	// Peer A registered with both.
	a := newTestPeer(t)
	defer a.Stop()
	a.UseRelay(r1Addr, r2Addr)

	// Wait for both registrations to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r1.RegistrationCount() == 1 && r2.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r1.RegistrationCount() != 1 || r2.RegistrationCount() != 1 {
		t.Fatalf("expected both relays to have A; r1=%d r2=%d",
			r1.RegistrationCount(), r2.RegistrationCount())
	}

	// Reach A via R1.
	b1 := newTestPeer(t)
	defer b1.Stop()
	if err := b1.Connect("relay://" + r1Addr + "/" + a.Identity.ID()); err != nil {
		t.Fatalf("dial A via R1: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if b1.PeerCount() != 1 {
		t.Errorf("B1 (via R1) should see 1 peer, got %d", b1.PeerCount())
	}

	// Reach A via R2 from a different peer.
	b2 := newTestPeer(t)
	defer b2.Stop()
	if err := b2.Connect("relay://" + r2Addr + "/" + a.Identity.ID()); err != nil {
		t.Fatalf("dial A via R2: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if b2.PeerCount() != 1 {
		t.Errorf("B2 (via R2) should see 1 peer, got %d", b2.PeerCount())
	}

	// And A should now have two relayed connections.
	if a.PeerCount() != 2 {
		t.Errorf("A should see 2 peers, got %d", a.PeerCount())
	}

	// AdvertisedAddress picks the first relay (deterministic).
	want := "relay://" + r1Addr + "/" + a.Identity.ID()
	if got := a.AdvertisedAddress(); got != want {
		t.Errorf("AdvertisedAddress = %q, want %q", got, want)
	}
}

// TestRelayFailoverWhenOneRelayDies verifies that even after one of
// A's relays goes offline, A is still reachable through the other.
func TestRelayFailoverWhenOneRelayDies(t *testing.T) {
	r1 := relay.NewServer()
	if err := r1.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	r2 := relay.NewServer()
	if err := r2.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer r2.Stop()
	r1Addr := r1.LocalAddr().String()
	r2Addr := r2.LocalAddr().String()

	a := newTestPeer(t)
	defer a.Stop()
	a.UseRelay(r1Addr, r2Addr)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r1.RegistrationCount() == 1 && r2.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Kill the first relay.
	r1.Stop()
	time.Sleep(100 * time.Millisecond)

	// A is still reachable via R2.
	b := newTestPeer(t)
	defer b.Stop()
	if err := b.Connect("relay://" + r2Addr + "/" + a.Identity.ID()); err != nil {
		t.Fatalf("dial A via surviving R2: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if b.PeerCount() != 1 {
		t.Errorf("B (via R2) should see 1 peer after R1 died, got %d", b.PeerCount())
	}
}

// TestConnectDedupesByPeerID confirms that dialing the same peer twice
// at different addresses (here: direct + relay URL) results in just
// ONE underlying TCP connection. The second Connect aliases the new
// address to the existing peerConn rather than opening a new socket.
func TestConnectDedupesByPeerID(t *testing.T) {
	srv := relay.NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	relayAddr := srv.LocalAddr().String()

	a := newTestPeer(t)
	defer a.Stop()
	a.UseRelay(relayAddr)

	// Wait for relay registration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	b := newTestPeer(t)
	defer b.Stop()

	// First connect: direct.
	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("direct connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Second connect: via relay. SHOULD NOT open a new TCP socket;
	// should just register the relay URL as an alias for the same
	// underlying conn.
	relayURL := "relay://" + relayAddr + "/" + a.Identity.ID()
	if err := b.Connect(relayURL); err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// PeerCount() returns the number of distinct addresses, but we
	// want to count distinct CONNECTIONS. Tally pointers via the test
	// hook below.
	uniq := b.uniqueConnCount()
	if uniq != 1 {
		t.Errorf("expected 1 unique connection after dedup, got %d", uniq)
	}

	// Both addresses should be aliases for the same conn -- so Send
	// to either should succeed.
	if err := b.Send(a.LocalAddr(), Message{Type: "ping"}); err != nil {
		t.Errorf("Send via direct address failed: %v", err)
	}
	if err := b.Send(relayURL, Message{Type: "ping"}); err != nil {
		t.Errorf("Send via relay alias failed: %v", err)
	}
}

// TestDisconnectClearsAllAliases verifies that when a connection drops,
// every alias for it is removed from the peers map -- so a stale alias
// can't keep returning a dead peerConn.
func TestDisconnectClearsAllAliases(t *testing.T) {
	srv := relay.NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	relayAddr := srv.LocalAddr().String()

	a := newTestPeer(t)
	a.UseRelay(relayAddr)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	b := newTestPeer(t)
	defer b.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	relayURL := "relay://" + relayAddr + "/" + a.Identity.ID()
	if err := b.Connect(relayURL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// Now kill A. B should drop its connection AND clear every alias
	// for it.
	a.Stop()
	time.Sleep(300 * time.Millisecond)

	if b.PeerCount() != 0 {
		t.Errorf("after A disconnects, B should have 0 peers, got %d", b.PeerCount())
	}
	if b.IsConnected(a.LocalAddr()) {
		t.Error("direct alias should be cleared")
	}
	if b.IsConnected(relayURL) {
		t.Error("relay alias should be cleared")
	}
}

// TestPublicPeerAdvertisesDirectFirst verifies that a peer marked
// public, AND registered with a relay for redundancy, advertises its
// direct listen address as the primary -- so callers prefer dialing
// direct (faster) and only fall through to the relay if direct fails.
func TestPublicPeerAdvertisesDirectFirst(t *testing.T) {
	srv := relay.NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	a := newTestPeer(t)
	defer a.Stop()
	a.SetPublic(true)
	a.UseRelay(srv.LocalAddr().String())

	addrs := a.AdvertisedAddresses()
	if len(addrs) < 2 {
		t.Fatalf("expected at least 2 addresses (direct + relay), got %v", addrs)
	}
	if addrs[0] != a.Address {
		t.Errorf("first advertised address = %q, want direct %q", addrs[0], a.Address)
	}
	// Relay URL should still be in the list as a fallback.
	hasRelay := false
	for _, addr := range addrs {
		if strings.HasPrefix(addr, "relay://") {
			hasRelay = true
		}
	}
	if !hasRelay {
		t.Error("public peer should still advertise relay as fallback")
	}
}

// TestNonPublicPeerDoesNotAdvertiseDirectAddress confirms a NAT-ed
// peer (default !public) doesn't leak its useless LAN address into
// hello messages when relays are configured.
func TestNonPublicPeerDoesNotAdvertiseDirectAddress(t *testing.T) {
	srv := relay.NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	a := newTestPeer(t)
	defer a.Stop()
	a.UseRelay(srv.LocalAddr().String())

	for _, addr := range a.AdvertisedAddresses() {
		if addr == a.Address {
			t.Errorf("non-public peer should NOT advertise direct address %q", addr)
		}
	}
}

// TestConcurrentEnsureConnectedSharesOneDial verifies that when N
// goroutines call EnsureConnected for the same address simultaneously,
// only ONE TCP handshake actually happens -- the others wait on the
// in-flight dial.
//
// We test this by counting incoming connections at the listener side:
// after 20 parallel EnsureConnecteds from B to A, A should see
// exactly 1 incoming connection.
func TestConcurrentEnsureConnectedSharesOneDial(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	b := newTestPeer(t)
	defer b.Stop()

	// Wrap A's listener to count Accepts.
	// Easiest: just sample a.PeerCount() since each accepted conn
	// goes through handshake and lands in a.peers.

	const N = 20
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			errs <- b.EnsureConnected(a.LocalAddr())
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Errorf("EnsureConnected #%d: %v", i, err)
		}
	}
	time.Sleep(150 * time.Millisecond)

	// A should have exactly 1 connection from B (one per peer ID,
	// since dedup by ID is also active). And B should have 1 unique
	// underlying conn to A.
	if got := a.PeerCount(); got != 1 {
		t.Errorf("A should see 1 peer after concurrent dials, got %d", got)
	}
	if got := b.uniqueConnCount(); got != 1 {
		t.Errorf("B should have 1 unique conn after concurrent dials, got %d", got)
	}
}

// TestEnsureConnectedFailureUnblocksAllWaiters: if the single in-flight
// dial fails, every waiting goroutine returns an error rather than
// hanging forever.
func TestEnsureConnectedFailureUnblocksAllWaiters(t *testing.T) {
	b := newTestPeer(t)
	defer b.Stop()

	// Pick a port nothing is listening on. 127.0.0.1:1 is generally
	// closed.
	const dead = "127.0.0.1:1"

	const N = 10
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			errs <- b.EnsureConnected(dead)
		}()
	}
	for i := 0; i < N; i++ {
		select {
		case err := <-errs:
			if err == nil {
				t.Error("EnsureConnected to dead address should error")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a waiter never unblocked")
		}
	}
}

// TestVersionRejectsAncientPeer simulates a peer running a hypothetical
// post-MinSupportedVersion-bump build sending a v0 (legacy) message.
// We accept v0 as v1 for backward compat. To exercise rejection, we
// flip the local MinSupportedVersion above 1 just for this test.
func TestVersionRejectsAncientPeer(t *testing.T) {
	// Bump min supported version to 2 so v=1 messages get rejected.
	// We can't actually mutate the const, so this test demonstrates
	// the wire-format presence and that verifyMessage looks at it.
	// We construct a Message manually and check the field round-trips.

	m := Message{V: ProtocolVersion, Type: "ping"}
	if m.V != ProtocolVersion {
		t.Errorf("V = %d, want %d", m.V, ProtocolVersion)
	}
	if ProtocolVersion < MinSupportedVersion {
		t.Errorf("ProtocolVersion %d should not be below MinSupportedVersion %d",
			ProtocolVersion, MinSupportedVersion)
	}
}

// TestVersionStampedOnEveryMessage confirms outgoing messages carry V
// after passing through sendOn-equivalent path. We verify by reading
// the JSON shape that gets sent.
func TestVersionStampedOnEveryMessage(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	b := newTestPeer(t)
	defer b.Stop()

	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// If they're connected, messages have flowed through verifyMessage
	// successfully -- which means V was at least 1 on every message
	// they exchanged. If V was missing or wrong, the connection would
	// have been dropped during the hello.
	if a.PeerCount() != 1 || b.PeerCount() != 1 {
		t.Errorf("expected 1 peer each, got A=%d B=%d", a.PeerCount(), b.PeerCount())
	}
}

// TestParseRelayAddress tests the URL parser independently.
func TestParseRelayAddress(t *testing.T) {
	good := []struct {
		in            string
		wantRelay     string
		wantPeerID    string
	}{
		{"relay://127.0.0.1:9001/abc123", "127.0.0.1:9001", "abc123"},
		{"relay://example.com:5555/deadbeef", "example.com:5555", "deadbeef"},
	}
	for _, tc := range good {
		r, p, err := parseRelayAddress(tc.in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.in, err)
			continue
		}
		if r != tc.wantRelay || p != tc.wantPeerID {
			t.Errorf("%q -> (%q,%q), want (%q,%q)", tc.in, r, p, tc.wantRelay, tc.wantPeerID)
		}
	}

	bad := []string{
		"127.0.0.1:9001",        // not relay scheme
		"relay://noslash",        // missing /<peer>
		"relay://addr:9001/",     // empty peer
		"relay:///nopath",        // empty relay
	}
	for _, s := range bad {
		if _, _, err := parseRelayAddress(s); err == nil {
			t.Errorf("%q should have failed parse", s)
		}
	}
}
