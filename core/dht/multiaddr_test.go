package dht

import (
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/peer"
	"altnet/core/relay"
)

// TestObserveHelloRecordsMultipleAddresses verifies that a hello payload
// carrying a comma-separated address list ends up in the routing table
// with a primary plus alts.
func TestObserveHelloRecordsMultipleAddresses(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, _ := newNode(t)
	defer pb.Stop()

	if err := pb.Connect(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// Synthesize a hello on top of the live connection by faking what
	// peer.go does. We can't easily inject a custom payload through
	// the public API without going through Connect, so instead we
	// directly call observeHello with a synthesized message and
	// verify the routing table updates as expected.
	msg := peer.Message{
		PublicKey: crypto.PublicKeyToHex(pb.Identity.PublicKey),
		Payload:   "relay://r1.example:9100/" + pb.Identity.ID() + "," + "relay://r2.example:9100/" + pb.Identity.ID() + "," + pb.LocalAddr(),
	}
	da.observeHello("ignored", msg)

	contacts := da.RoutingTable().All()
	var got Contact
	for _, c := range contacts {
		if c.ID.Hex() == pb.Identity.ID() {
			got = c
		}
	}
	if got.Address == "" {
		t.Fatal("contact for B not found in A's routing table")
	}
	if got.Address != "relay://r1.example:9100/"+pb.Identity.ID() {
		t.Errorf("primary address = %q, want first relay URL", got.Address)
	}
	if len(got.AltAddresses) < 2 {
		t.Errorf("AltAddresses = %v, want at least 2 fallbacks", got.AltAddresses)
	}
}

// TestRequestContactFallsThroughDeadAddresses puts a Contact whose
// primary address is unreachable but whose alt is reachable, and
// verifies the request succeeds against the alt.
func TestRequestContactFallsThroughDeadAddresses(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	// First, connect them so each knows the other.
	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// Build a synthetic Contact for B with a dead primary address and
	// B's real address as an alt. Ping it -- it should succeed by
	// falling through to the alt.
	bID, _ := IDFromHex(pb.Identity.ID())
	c := Contact{
		ID:           bID,
		Address:      "127.0.0.1:1", // dead
		AltAddresses: []string{pb.LocalAddr()},
	}
	if err := da.Ping(c); err != nil {
		t.Fatalf("Ping should have succeeded via alt address: %v", err)
	}
}

// TestFindNodePropagatesAltAddresses verifies that wireContact carries
// AltAddresses on the wire so peers can learn ALL of a contact's
// reachability paths through the DHT (not just one).
func TestFindNodePropagatesAltAddresses(t *testing.T) {
	// Topology: A knows B with two addresses (one real, one fake alt).
	//           C asks A for nodes and should learn both.
	pa, da := newNode(t)
	defer pa.Stop()
	pb, _ := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	// Manually plant a multi-address contact for B in A's RT.
	bID, _ := IDFromHex(pb.Identity.ID())
	da.RoutingTable().Update(Contact{
		ID:           bID,
		Address:      pb.LocalAddr(),
		AltAddresses: []string{"relay://fake.example:9100/" + pb.Identity.ID()},
	})

	// C bootstraps via A; A's reply to C's first FindNode must carry
	// both addresses.
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	contacts := dc.RoutingTable().All()
	var bContact Contact
	for _, c := range contacts {
		if c.ID.Equal(bID) {
			bContact = c
		}
	}
	if bContact.Address == "" {
		t.Fatal("C did not learn about B through bootstrap")
	}
	// C should know about both of B's addresses now (one as primary,
	// one as alt -- the order depends on which arrived first).
	all := bContact.AllAddresses()
	hasReal := false
	hasFake := false
	for _, addr := range all {
		if addr == pb.LocalAddr() {
			hasReal = true
		}
		if addr == "relay://fake.example:9100/"+pb.Identity.ID() {
			hasFake = true
		}
	}
	if !hasReal || !hasFake {
		t.Errorf("C should have learned both addresses for B, got %v", all)
	}
}

// TestRoutingTableMergesAlts verifies that observing the same peer
// twice with different addresses results in a single contact whose
// AltAddresses is the union.
func TestRoutingTableMergesAlts(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)
	other := idFromString("other")

	rt.Update(Contact{ID: other, Address: "10.0.0.1:9000"})
	rt.Update(Contact{ID: other, Address: "relay://r1:9100/x", AltAddresses: []string{"relay://r2:9100/x"}})

	all := rt.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(all))
	}
	got := all[0]
	if got.Address != "relay://r1:9100/x" {
		t.Errorf("Address = %q, want most recent primary", got.Address)
	}
	addrs := got.AllAddresses()
	want := map[string]bool{
		"relay://r1:9100/x": true,
		"relay://r2:9100/x": true,
		"10.0.0.1:9000":     true,
	}
	for _, a := range addrs {
		if !want[a] {
			t.Errorf("unexpected address %q", a)
		}
		delete(want, a)
	}
	for missing := range want {
		t.Errorf("missing address %q after merge", missing)
	}
}

// TestGoodbyeRemovesPeerFromRoutingTable confirms that a peer's
// shutdown announcement causes its contacts to remove it from their
// routing tables immediately, instead of waiting for a future ping to
// fail.
func TestGoodbyeRemovesPeerFromRoutingTable(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	// don't defer pb.Stop -- the test calls it explicitly mid-test

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// Sanity: A's routing table has B.
	bID, _ := IDFromHex(pb.Identity.ID())
	found := false
	for _, c := range da.RoutingTable().All() {
		if c.ID.Equal(bID) {
			found = true
		}
	}
	if !found {
		t.Fatal("A doesn't have B in routing table; setup broken")
	}

	// B leaves cleanly. The goodbye in Stop() should reach A and A
	// should drop B from the routing table immediately.
	pb.Stop()
	time.Sleep(200 * time.Millisecond)

	for _, c := range da.RoutingTable().All() {
		if c.ID.Equal(bID) {
			t.Error("A should have dropped B after goodbye, but B is still in RT")
		}
	}
}

// TestRelayedPeerStaysReachableViaAltAfterPrimaryRelayDies is the
// integration test that ties everything together: A registers with R1
// AND R2, propagates both through the DHT, R1 dies, and B can still
// reach A via the alt (R2) without manual intervention.
func TestRelayedPeerStaysReachableViaAltAfterPrimaryRelayDies(t *testing.T) {
	r1 := relay.NewServer()
	if err := r1.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	r2 := relay.NewServer()
	if err := r2.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer r2.Stop()

	pBoot, dBoot := newNode(t)
	defer pBoot.Stop()

	pa, _ := newNode(t)
	defer pa.Stop()
	pa.UseRelay(r1.LocalAddr().String(), r2.LocalAddr().String())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r1.RegistrationCount() == 1 && r2.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A bootstraps so the bootstrap node learns about A with both relays.
	if err := pa.Connect(pBoot.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// Sanity: bootstrap's RT has A with primary+alt.
	var contactForA Contact
	for _, c := range dBoot.RoutingTable().All() {
		if c.ID.Hex() == pa.Identity.ID() {
			contactForA = c
		}
	}
	if contactForA.Address == "" {
		t.Fatal("bootstrap doesn't have A in its RT")
	}
	if len(contactForA.AltAddresses) == 0 {
		t.Fatalf("bootstrap should have at least one alt for A, got addresses %v", contactForA.AllAddresses())
	}

	// Kill the primary relay (R1).
	r1.Stop()
	time.Sleep(100 * time.Millisecond)

	// Bootstrap pings A. Primary (R1) is dead, but alt (R2) is alive,
	// so requestContact should succeed via the alt.
	if err := dBoot.Ping(contactForA); err != nil {
		t.Errorf("Ping A via multi-address contact should have succeeded after R1 died: %v", err)
	}
}
