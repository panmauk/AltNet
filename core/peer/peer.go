// Package peer implements a single node in the P2P network.
// Each peer has a cryptographic identity, listens for connections,
// and exchanges signed, length-prefixed messages with other peers.
package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"altnet/core/crypto"
	"altnet/core/relay"
	"altnet/core/secure"
)

// MaxMessageSize is the largest single message accepted (1 MiB).
// Messages larger than this are rejected to avoid memory exhaustion.
const MaxMessageSize = 1 << 20

// DefaultMaxConnections caps the total number of simultaneous peer
// connections (inbound + outbound) we'll keep open. Without a cap, an
// attacker can exhaust our file descriptors / goroutines by opening
// thousands of TCP connections, even ones that never finish the
// secure handshake (those get killed by HandshakeTimeout but during
// the window they consume resources).
//
// 1024 is generous for a home node and well below typical OS FD
// limits (1024 soft, 65k hard on Linux). Operators can override via
// SetMaxConnections.
const DefaultMaxConnections = 1024

// ProtocolVersion is the wire protocol major version of this build.
// Every outgoing Message stamps this in V; on receive we reject any
// message whose V is incompatible with our MinSupportedVersion. The
// number is bumped only on breaking wire changes (new mandatory field
// semantics, signature scheme change, framing change, etc.).
//
// We START at 1, not 0, so a bare-zero V on an old daemon is clearly
// distinguishable from "compatible with v1".
const ProtocolVersion uint32 = 1

// MinSupportedVersion is the oldest version we'll accept messages
// from. Bumped when we drop backwards compatibility. A peer that
// stamps V < MinSupportedVersion gets its connection closed.
const MinSupportedVersion uint32 = 1

// Message is the basic unit of communication between peers.
// On the wire each message is framed as:
//
//	[4-byte big-endian length][JSON-encoded Message]
//
// The signature is computed over the canonical JSON of the message
// with Sig set to the empty string, so the signature itself doesn't
// need to be excluded by name.
type Message struct {
	V         uint32 `json:"v,omitempty"`     // protocol version; 0 means "pre-versioned" (legacy v1 in practice)
	Type      string `json:"type"`            // e.g. "hello", "ping", "pong", "chat", "dht_find_node"
	From      string `json:"from"`            // sender peer ID (hash of public key)
	PublicKey string `json:"pk,omitempty"`    // sender's public key (hex). Required in "hello", optional after.
	ReqID     string `json:"reqid,omitempty"` // optional correlation ID. A reply copies the requester's ReqID.
	Payload   string `json:"payload"`         // arbitrary message body (often nested JSON)
	Sig       string `json:"sig,omitempty"`   // hex Ed25519 signature over the rest of the message
}

// Handler is implemented by code that wants to react to incoming messages.
// Handlers are called for every verified, non-builtin, non-reply message.
//
// A Handler can call p.Send / p.Request / p.Reply on the passed Peer to
// react. The DHT package implements one such Handler.
type Handler interface {
	HandleMessage(p *Peer, addr string, msg Message)
}

// Peer represents one node in the network.
type Peer struct {
	Identity *crypto.Identity
	Address  string

	log *slog.Logger

	listener net.Listener

	// peers is many-to-one: any number of remote addresses can alias
	// the same underlying peerConn. peersByID is the canonical map
	// (one entry per remote peer identity), used to dedupe redundant
	// connections that arose from dialing the same peer via different
	// addresses (direct + relay, for example).
	mu        sync.Mutex
	peers     map[string]*peerConn // remote-address -> conn (alias map)
	peersByID map[string]*peerConn // remote peer-id -> conn (canonical)

	handlersMu sync.RWMutex
	handlers   []Handler

	pendingMu sync.Mutex
	pending   map[string]chan Message // requests waiting for a reply, keyed by ReqID

	// Optional outbound relays. Each entry is a live registration with
	// one relay; we close them all on Stop. A peer can register with
	// several relays for redundancy -- if any one stays up, the peer
	// remains reachable.
	relayMu        sync.Mutex
	relays         []*relay.Client
	RelayAddresses []string // raw relay host:port list, in registration order
	public         bool     // if true, advertise direct address first (see SetPublic)

	// In-flight dial coordination: when several goroutines call
	// EnsureConnected for the same address at the same time, only ONE
	// of them actually opens a TCP socket. The rest wait on the
	// channel here and find the connection ready (or the error)
	// when the dialer completes.
	dialMu  sync.Mutex
	dialing map[string]chan struct{}

	// maxConnections caps total simultaneous peer connections.
	// 0 = unlimited (not recommended in production).
	maxConnections int
}

// peerConn holds the live connection to a remote peer plus what we know
// about them: their advertised public key (verified during the secure
// handshake) and stable peer ID. addresses is the set of remote
// addresses currently aliased to this connection -- multiple entries
// arise when we dial the same peer through more than one address (e.g.
// direct + relay) and dedupe to a single TCP socket.
type peerConn struct {
	conn      net.Conn
	remoteID  string            // verified peer ID (hash of pubkey)
	remotePub ed25519.PublicKey // verified public key
	addresses []string          // every map key in Peer.peers that points here
	writeMu   sync.Mutex        // serializes writes on this connection
}

// New creates a peer with the given identity that will listen on address.
func New(id *crypto.Identity, address string) *Peer {
	return &Peer{
		Identity:       id,
		Address:        address,
		log:            slog.With("subsystem", "peer", "self", id.ShortID()),
		peers:          make(map[string]*peerConn),
		peersByID:      make(map[string]*peerConn),
		pending:        make(map[string]chan Message),
		dialing:        make(map[string]chan struct{}),
		maxConnections: DefaultMaxConnections,
	}
}

// SetMaxConnections overrides the per-peer connection cap. Set to 0
// for unlimited (only safe in tests). New connections beyond the cap
// are refused at accept/dial time.
func (p *Peer) SetMaxConnections(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConnections = n
}

// atConnectionLimit reports whether we'd refuse another connection.
// Caller need not hold p.mu; this acquires it internally.
func (p *Peer) atConnectionLimit() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxConnections > 0 && len(p.peersByID) >= p.maxConnections
}

// AddHandler registers a Handler that will receive every verified incoming
// message that is not a built-in type and is not a reply to a pending Request.
// Multiple handlers can be added; they are called in registration order.
func (p *Peer) AddHandler(h Handler) {
	p.handlersMu.Lock()
	p.handlers = append(p.handlers, h)
	p.handlersMu.Unlock()
}

// IsConnected reports whether we currently hold an open connection to addr.
func (p *Peer) IsConnected(addr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.peers[addr]
	return ok
}

// EnsureConnected opens a connection to addr if we don't already have one.
// It's a no-op (returns nil) if we are already connected.
//
// Concurrent EnsureConnected calls for the same address share a single
// in-flight dial: only one goroutine actually opens a TCP socket and
// runs the secure handshake; the others wait on the same wakeup
// channel and pick up the result. Without this coordination, N
// parallel RPCs to a peer we hadn't dialed yet would each open their
// own TCP connection and waste N-1 of them through the dedup logic.
func (p *Peer) EnsureConnected(addr string) error {
	if p.IsConnected(addr) {
		return nil
	}

	p.dialMu.Lock()
	if wait, inflight := p.dialing[addr]; inflight {
		// Another goroutine is already dialing this address.
		p.dialMu.Unlock()
		<-wait
		if p.IsConnected(addr) {
			return nil
		}
		return fmt.Errorf("concurrent dial to %s did not establish a connection", addr)
	}
	wakeup := make(chan struct{})
	p.dialing[addr] = wakeup
	p.dialMu.Unlock()

	err := p.Connect(addr)

	p.dialMu.Lock()
	delete(p.dialing, addr)
	p.dialMu.Unlock()
	close(wakeup) // wake every goroutine that was waiting for our result

	return err
}

// Start begins listening for incoming connections.
func (p *Peer) Start() error {
	ln, err := net.Listen("tcp", p.Address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.Address, err)
	}
	p.listener = ln
	// Update Address with the actual bound address (resolves :0).
	p.Address = ln.Addr().String()
	p.log.Info("listening", "addr", p.Address)

	go p.acceptLoop()
	return nil
}

// Stop announces our departure to every peer ("goodbye" message), then
// closes the listener, all relay registrations, and all open peer
// connections.
//
// The goodbye is best-effort -- if it doesn't reach everyone, the
// regular peer-check loop on each remote will detect us as dead within
// a minute or two. But when it does reach a peer, that peer can drop
// us from its routing table immediately, which keeps lookups from
// wasting time on a stale address.
func (p *Peer) Stop() {
	p.Broadcast(Message{Type: "goodbye"})
	// Tiny grace period so the writes flush before the listener closes.
	time.Sleep(50 * time.Millisecond)

	if p.listener != nil {
		p.listener.Close()
	}
	p.relayMu.Lock()
	relays := p.relays
	p.relays = nil
	p.relayMu.Unlock()
	for _, c := range relays {
		c.Stop()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, pc := range p.peers {
		pc.conn.Close()
		delete(p.peers, addr)
	}
}

// UseRelay registers this peer with one or more public relays so peers
// behind NAT can be reached at "relay://<relayAddr>/<peer-id>". Tunnels
// created by any relay are accepted as inbound connections, just like
// direct listener accepts.
//
// Call this once after Start. Multiple addresses may be passed for
// redundancy; the peer will register with all of them and remain
// reachable as long as any one stays up. Each registration runs in the
// background and reconnects with backoff if its relay restarts.
//
// Repeated calls APPEND new relays; existing registrations are kept.
func (p *Peer) UseRelay(relayAddrs ...string) {
	for _, addr := range relayAddrs {
		if addr == "" {
			continue
		}
		c := relay.NewClient(addr, p.Identity.ID())
		p.relayMu.Lock()
		p.relays = append(p.relays, c)
		p.RelayAddresses = append(p.RelayAddresses, addr)
		p.relayMu.Unlock()
		go c.Run()
		go p.acceptRelayedTunnels(c, addr)
		p.log.Info("registered with relay",
			"relay", addr,
			"reachable_at", "relay://"+addr+"/"+p.Identity.ID())
	}
}

// AdvertisedAddresses returns every address other peers can use to
// reach this peer, in preference order. With one or more relays
// configured, the list is the relay URLs in registration order.
// Without relays, it's just the local listen address.
//
// If SetPublic(true) was called, the local listen address is prepended
// to the list -- callers will try direct first (faster, no relay
// overhead) and only fall through to a relay URL if direct fails. This
// is the "direct connection preference" that lets two publicly
// reachable peers skip the relay tunnel even when both happen to be
// registered with one for fault tolerance.
//
// The hello message advertises this whole list so consumers know every
// reachability path and can fail over between them when any single one
// dies. The first entry is the "primary" path we'd prefer they use.
func (p *Peer) AdvertisedAddresses() []string {
	p.relayMu.Lock()
	defer p.relayMu.Unlock()
	addrs := make([]string, 0, 1+len(p.RelayAddresses))
	if p.public && p.Address != "" {
		addrs = append(addrs, p.Address)
	}
	for _, ra := range p.RelayAddresses {
		addrs = append(addrs, "relay://"+ra+"/"+p.Identity.ID())
	}
	if len(addrs) == 0 {
		// No relay and not public -- advertise the local listen
		// address as a last resort. Mostly useful in single-host
		// tests where everyone is on 127.0.0.1.
		addrs = append(addrs, p.Address)
	}
	return addrs
}

// SetPublic flags this peer as publicly reachable -- meaning its
// listen address can be dialed directly by any peer on the internet.
// When set, AdvertisedAddresses prepends the direct address before any
// relay URLs, so other peers prefer the faster direct path.
//
// Default is false; a peer behind NAT should leave it false so peers
// don't waste time dialing an unroutable LAN IP before falling through
// to a relay.
func (p *Peer) SetPublic(public bool) {
	p.relayMu.Lock()
	defer p.relayMu.Unlock()
	p.public = public
}

// AdvertisedAddress returns the primary advertised address, kept for
// callers that don't need the full list (e.g. log messages).
func (p *Peer) AdvertisedAddress() string {
	addrs := p.AdvertisedAddresses()
	if len(addrs) == 0 {
		return p.Address
	}
	return addrs[0]
}

// encodeAddresses joins a list of addresses into the wire format used
// in hello payloads -- comma-separated, no spaces.
func encodeAddresses(addrs []string) string {
	return strings.Join(addrs, ",")
}

// KeepAlivePeriod is how often the OS sends a TCP keep-alive probe on
// idle peer connections. With this set, silently-dead links (NAT
// timed out, peer's machine slept, ISP severed) are detected within
// roughly KeepAlivePeriod * (a few retries), instead of waiting for
// our application-level peer-check loop to notice (10 min by default).
//
// 30 seconds is a balance: short enough to detect dead conns quickly
// without flooding the network; long enough that a brief network
// hiccup doesn't kill an otherwise-healthy connection.
const KeepAlivePeriod = 30 * time.Second

// enableKeepAlive turns on TCP keep-alive on c if it's a *net.TCPConn.
// Returns the conn unchanged on non-TCP types (e.g. relay tunnels
// which are themselves TCP underneath but wrapped, or test pipes).
// Best-effort: keep-alive failures are logged but do not abort.
func enableKeepAlive(c net.Conn) net.Conn {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return c
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(KeepAlivePeriod)
	return c
}

// decodeAddresses splits a hello payload back into a list of addresses,
// dropping empty entries.
func decodeAddresses(payload string) []string {
	if payload == "" {
		return nil
	}
	parts := strings.Split(payload, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// acceptRelayedTunnels turns each tunnel surfaced by the relay client
// into an incoming connection that goes through the same secure
// handshake + hello flow as a direct accept.
func (p *Peer) acceptRelayedTunnels(c *relay.Client, relayAddr string) {
	for tunnel := range c.Tunnels {
		go p.handleIncomingFromRelay(tunnel, relayAddr)
	}
}

// dialAddress resolves either a direct "host:port" or a relay URL into
// a live net.Conn. The caller treats the returned conn the same in
// either case: secure handshake, then peer protocol.
func dialAddress(address string) (net.Conn, error) {
	if strings.HasPrefix(address, "relay://") {
		relayAddr, peerID, err := parseRelayAddress(address)
		if err != nil {
			return nil, err
		}
		return relay.DialVia(relayAddr, peerID)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return enableKeepAlive(conn), nil
}

// parseRelayAddress splits "relay://<host:port>/<peer-id-hex>" into its
// components. Returns an error if the URL is malformed.
func parseRelayAddress(address string) (relayAddr, peerID string, err error) {
	const prefix = "relay://"
	if !strings.HasPrefix(address, prefix) {
		return "", "", errors.New("not a relay address")
	}
	rest := address[len(prefix):]
	slash := strings.Index(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return "", "", errors.New("relay address must be relay://<host:port>/<peer-id>")
	}
	return rest[:slash], rest[slash+1:], nil
}

// LocalAddr returns the address the peer is actually bound to.
// Useful in tests where Address may be "127.0.0.1:0".
func (p *Peer) LocalAddr() string {
	if p.listener == nil {
		return p.Address
	}
	return p.listener.Addr().String()
}

// Connect dials another peer, performs the encryption handshake, and
// exchanges a hello. address may be either a normal "host:port" or a
// relay URL of the form "relay://<relay-host:port>/<peer-id>" -- in the
// relay case we open a tunnel through the relay to reach a NAT-ed peer.
//
// If we already have a live connection to the same peer (reached via
// some other address), the new TCP socket is closed and the new
// address is aliased to the existing conn -- so two parallel paths to
// the same peer never burn two TCP connections.
func (p *Peer) Connect(address string) error {
	if p.atConnectionLimit() {
		return fmt.Errorf("refusing dial to %s: at connection limit", address)
	}
	raw, err := dialAddress(address)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, err)
	}

	// Upgrade to an encrypted, authenticated channel. We're the
	// initiator (we dialed). We don't yet know the remote identity, so
	// pass nil for expectedRemote -- any peer is acceptable here.
	sec, err := secure.Handshake(raw, p.Identity.PrivateKey, true, nil)
	if err != nil {
		raw.Close()
		return fmt.Errorf("secure handshake with %s: %w", address, err)
	}

	pc := &peerConn{
		conn:      sec,
		remotePub: sec.RemotePublicKey(),
		remoteID:  crypto.PublicKeyToID(sec.RemotePublicKey()),
	}

	if existing := p.registerConn(pc, address); existing != nil {
		// Dedup: we already have a connection to this peer. Close the
		// new one and let the caller use the alias we just registered.
		sec.Close()
		p.log.Debug("dedup outbound: aliased to existing conn",
			"remote", shortID(existing.remoteID),
			"new_alias", address)
		return nil
	}

	p.log.Info("connected", "addr", address, "remote", shortID(pc.remoteID))

	hello := Message{
		Type:      "hello",
		PublicKey: crypto.PublicKeyToHex(p.Identity.PublicKey),
		Payload:   encodeAddresses(p.AdvertisedAddresses()),
	}
	if err := p.sendOn(pc, hello); err != nil {
		sec.Close()
		p.removeConn(pc)
		return fmt.Errorf("send hello: %w", err)
	}

	go p.readLoop(pc, address)
	return nil
}

// Send dispatches a message to a specific connected peer.
func (p *Peer) Send(address string, msg Message) error {
	p.mu.Lock()
	pc, ok := p.peers[address]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("not connected to %s", address)
	}
	return p.sendOn(pc, msg)
}

// Request sends a message tagged with a fresh ReqID and waits for a reply
// carrying the same ReqID, or until timeout. Returns the reply on success.
//
// This is the building block for synchronous RPC-style protocols (DHT
// queries, etc.). Multiple concurrent Requests on the same peer are safe.
func (p *Peer) Request(address string, msg Message, timeout time.Duration) (Message, error) {
	if err := p.EnsureConnected(address); err != nil {
		return Message{}, err
	}

	reqID, err := newReqID()
	if err != nil {
		return Message{}, err
	}
	msg.ReqID = reqID

	ch := make(chan Message, 1)
	p.pendingMu.Lock()
	p.pending[reqID] = ch
	p.pendingMu.Unlock()
	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, reqID)
		p.pendingMu.Unlock()
	}()

	if err := p.Send(address, msg); err != nil {
		return Message{}, err
	}

	select {
	case reply := <-ch:
		return reply, nil
	case <-time.After(timeout):
		return Message{}, fmt.Errorf("request %s timed out after %s", msg.Type, timeout)
	}
}

// Reply sends a response message back on the same connection that delivered
// the request. The ReqID is copied so the requester can correlate.
func (p *Peer) Reply(address string, request Message, reply Message) error {
	reply.ReqID = request.ReqID
	return p.Send(address, reply)
}

// Broadcast sends a message to every connected peer.
func (p *Peer) Broadcast(msg Message) {
	p.mu.Lock()
	conns := make([]*peerConn, 0, len(p.peers))
	addrs := make([]string, 0, len(p.peers))
	for addr, pc := range p.peers {
		conns = append(conns, pc)
		addrs = append(addrs, addr)
	}
	p.mu.Unlock()

	for i, pc := range conns {
		if err := p.sendOn(pc, msg); err != nil {
			p.log.Warn("broadcast failed", "addr", addrs[i], "err", err)
		}
	}
}

// PeerCount returns how many peers we are currently connected to.
func (p *Peer) PeerCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.peers)
}

// PeerCountByAddr returns a snapshot of all current peer connections,
// keyed by remote address. Useful for tests/debugging that want to
// inspect what kind of address (direct vs relay://) each connection
// uses.
func (p *Peer) PeerCountByAddr() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.peers))
	for addr, pc := range p.peers {
		out[addr] = pc.remoteID
	}
	return out
}

// uniqueConnCount returns the number of distinct underlying peerConns
// (not counting aliases). Useful for tests asserting that dedup
// actually collapsed multiple addresses to one TCP socket.
func (p *Peer) uniqueConnCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.peersByID)
}

// UniqueConnCount is the exported form of uniqueConnCount, used by
// the metrics endpoint and operator tooling to distinguish "address
// aliases" from "actual TCP sockets."
func (p *Peer) UniqueConnCount() int { return p.uniqueConnCount() }

// IsPublic reports whether SetPublic(true) was called -- i.e.
// whether this peer advertises its direct address as the primary
// reachability path.
func (p *Peer) IsPublic() bool {
	p.relayMu.Lock()
	defer p.relayMu.Unlock()
	return p.public
}

// sendOn signs the message and writes it on a specific connection.
func (p *Peer) sendOn(pc *peerConn, msg Message) error {
	msg.V = ProtocolVersion
	msg.From = p.Identity.ID()
	// PublicKey is mandatory only in hello, but including it always is
	// cheap and makes signature verification simpler for the receiver.
	msg.PublicKey = crypto.PublicKeyToHex(p.Identity.PublicKey)
	msg.Sig = "" // ensure unsigned canonical form before signing

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	msg.Sig = p.Identity.Sign(data)

	signed, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal signed: %w", err)
	}
	if len(signed) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(signed))
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(signed)))
	if _, err := pc.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := pc.conn.Write(signed); err != nil {
		return err
	}
	return nil
}

// acceptLoop runs in the background, accepting new incoming connections.
// Each accepted connection is handed to a goroutine that performs the
// secure handshake -- handshake is non-trivial (signature verification,
// ECDH) so we don't want a slow peer to block other accepts.
func (p *Peer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handleIncoming(enableKeepAlive(conn))
	}
}

// handleIncoming runs the secure handshake on a freshly-accepted
// connection, then sends our hello and starts the read loop.
func (p *Peer) handleIncoming(raw net.Conn) {
	addr := raw.RemoteAddr().String()
	p.log.Debug("incoming connection", "addr", addr)

	// Refuse if we're at the connection cap. Done BEFORE the secure
	// handshake so we don't burn signature-verification cycles on
	// connections we'd reject anyway.
	if p.atConnectionLimit() {
		p.log.Warn("refusing inbound: at connection limit", "addr", addr)
		raw.Close()
		return
	}

	sec, err := secure.Handshake(raw, p.Identity.PrivateKey, false, nil)
	if err != nil {
		p.log.Warn("incoming handshake failed", "addr", addr, "err", err)
		raw.Close()
		return
	}

	pc := &peerConn{
		conn:      sec,
		remotePub: sec.RemotePublicKey(),
		remoteID:  crypto.PublicKeyToID(sec.RemotePublicKey()),
	}
	if existing := p.registerConn(pc, addr); existing != nil {
		// Already have a connection to this peer (probably we dialed
		// them around the same moment). Drop the inbound dup.
		sec.Close()
		p.log.Debug("dedup inbound: already connected",
			"addr", addr,
			"remote", shortID(existing.remoteID))
		return
	}

	p.log.Info("incoming verified", "addr", addr, "remote", shortID(pc.remoteID))

	hello := Message{Type: "hello", Payload: encodeAddresses(p.AdvertisedAddresses())}
	if err := p.sendOn(pc, hello); err != nil {
		sec.Close()
		p.removeConn(pc)
		return
	}

	p.readLoop(pc, addr)
}

// handleIncomingFromRelay is the relay-tunnel analogue of handleIncoming.
// The wire-level remote address is the relay's, which is useless as a
// peer identity, so once we know who's on the other side (after the
// secure handshake), we key the connection by a synthetic
// "relay://<relayAddr>/<peer-id>" address. Other peers can reach this
// peer back by dialing that same string.
func (p *Peer) handleIncomingFromRelay(raw net.Conn, relayAddr string) {
	if p.atConnectionLimit() {
		p.log.Warn("refusing relay tunnel: at connection limit", "relay", relayAddr)
		raw.Close()
		return
	}
	sec, err := secure.Handshake(raw, p.Identity.PrivateKey, false, nil)
	if err != nil {
		raw.Close()
		return
	}
	remoteID := crypto.PublicKeyToID(sec.RemotePublicKey())
	addr := "relay://" + relayAddr + "/" + remoteID

	pc := &peerConn{
		conn:      sec,
		remotePub: sec.RemotePublicKey(),
		remoteID:  remoteID,
	}
	if existing := p.registerConn(pc, addr); existing != nil {
		sec.Close()
		p.log.Debug("dedup relay tunnel: already connected",
			"remote", shortID(remoteID),
			"relay", relayAddr)
		return
	}

	p.log.Info("incoming via relay verified",
		"relay", relayAddr,
		"remote", shortID(remoteID))

	// We tell the remote our complete list of advertised addresses so
	// they can dial us back through any of them. With multiple relays
	// the list includes one URL per relay; without relays it's just the
	// local listen address.
	hello := Message{Type: "hello", Payload: encodeAddresses(p.AdvertisedAddresses())}
	if err := p.sendOn(pc, hello); err != nil {
		sec.Close()
		p.removeConn(pc)
		return
	}
	p.readLoop(pc, addr)
}

// PreHelloTimeout caps how long a freshly-connected peer can sit
// silent before sending its first message. Without this, a peer that
// completes the secure handshake but never sends a hello holds a
// goroutine + socket until TCP keepalive notices (~2 minutes). With
// thousands of half-connect attempts an attacker can DoS our peer
// table via FD exhaustion.
const PreHelloTimeout = 30 * time.Second

// readLoop reads framed messages from a peer connection, verifies them, and dispatches.
func (p *Peer) readLoop(pc *peerConn, address string) {
	defer func() {
		pc.conn.Close()
		p.removeConn(pc)
		p.log.Info("disconnected", "addr", address)
	}()

	// First message has a tight deadline. After that, the steady-state
	// liveness check is TCP keepalive (30s) plus the maintenance ping
	// loop (10min). We don't keep the per-message deadline because a
	// healthy peer can legitimately go quiet between RPCs.
	_ = pc.conn.SetReadDeadline(time.Now().Add(PreHelloTimeout))
	firstMessageSeen := false

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(pc.conn, lenBuf[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(lenBuf[:])
		if size == 0 || size > MaxMessageSize {
			p.log.Warn("invalid message size from peer", "addr", address, "size", size)
			return
		}

		buf := make([]byte, size)
		if _, err := io.ReadFull(pc.conn, buf); err != nil {
			return
		}

		var msg Message
		if err := json.Unmarshal(buf, &msg); err != nil {
			p.log.Warn("bad message, closing connection", "addr", address, "err", err)
			return
		}

		if err := p.verifyMessage(pc, &msg); err != nil {
			// Any verification failure drops the connection.
			// Otherwise an attacker can retry indefinitely.
			p.log.Warn("rejected message, closing connection", "addr", address, "err", err)
			return
		}

		// First valid message: the peer is alive and behaving. Clear
		// the pre-hello read deadline so subsequent RPCs can be quiet
		// for arbitrary stretches without the connection dying.
		// Liveness from this point on is TCP keepalive + maintenance
		// pings.
		if !firstMessageSeen {
			_ = pc.conn.SetReadDeadline(time.Time{})
			firstMessageSeen = true
		}

		p.handleMessage(msg, pc, address)
	}
}

// verifyMessage checks the protocol version, the signature, the
// public key, and (for non-hello messages) that the public key matches
// the one established during hello.
func (p *Peer) verifyMessage(pc *peerConn, msg *Message) error {
	// Version check first -- a future-protocol or ancient peer should
	// be rejected before we waste cycles on signature verification.
	// V == 0 means "pre-versioning"; we accept those as effectively v1
	// for backward compatibility with the very first builds.
	v := msg.V
	if v == 0 {
		v = 1
	}
	if v < MinSupportedVersion {
		return fmt.Errorf("unsupported protocol version %d (min supported %d)",
			msg.V, MinSupportedVersion)
	}
	// Note: we DO accept v > ProtocolVersion (future peers). They might
	// be sending us forward-compatible messages. If we can't parse the
	// payload, that's a different error path. This matches HTTP's
	// "unknown headers ignored" robustness principle.

	if msg.PublicKey == "" {
		return errors.New("missing public key")
	}
	pub, err := crypto.PublicKeyFromHex(msg.PublicKey)
	if err != nil {
		return fmt.Errorf("bad public key: %w", err)
	}

	// Claimed ID must match the hash of the claimed public key.
	if msg.From != "" && msg.From != crypto.PublicKeyToID(pub) {
		return errors.New("from-ID does not match public key")
	}

	// Once we've seen a hello, the public key on this connection is locked.
	if pc.remotePub != nil && string(pc.remotePub) != string(pub) {
		return errors.New("public key changed mid-connection")
	}

	// Verify signature: recompute the canonical JSON with Sig empty.
	sig := msg.Sig
	msg.Sig = ""
	data, err := json.Marshal(msg)
	msg.Sig = sig
	if err != nil {
		return fmt.Errorf("re-marshal: %w", err)
	}
	if err := crypto.Verify(pub, data, sig); err != nil {
		return err
	}

	// First good message on this connection establishes the remote identity.
	if pc.remotePub == nil {
		pc.remotePub = pub
		pc.remoteID = crypto.PublicKeyToID(pub)
	}
	return nil
}

// handleMessage decides what to do with a verified message.
//
// Order of dispatch:
//  1. If the message has a ReqID matching a pending Request, deliver the
//     reply to the waiting goroutine. This intercepts replies before any
//     other handling.
//  2. Built-in types (hello, ping, pong, chat) are still printed for
//     backward compatibility with the simple chat CLI.
//  3. All registered Handlers are called. They can react to any type they
//     care about, e.g. dht_*.
func (p *Peer) handleMessage(msg Message, pc *peerConn, from string) {
	// 1. Reply to a pending Request?
	if msg.ReqID != "" {
		p.pendingMu.Lock()
		ch, ok := p.pending[msg.ReqID]
		if ok {
			delete(p.pending, msg.ReqID)
		}
		p.pendingMu.Unlock()
		if ok {
			ch <- msg
			return
		}
	}

	// 2. Built-in chat-style behavior.
	short := shortID(msg.From)
	switch msg.Type {
	case "hello":
		p.log.Debug("hello received", "from", short, "advertised", msg.Payload)
	case "ping":
		p.log.Debug("ping received", "from", short)
		_ = p.sendOn(pc, Message{Type: "pong", Payload: "alive"})
	case "pong":
		p.log.Debug("pong received", "from", short)
	case "chat":
		p.log.Info("chat", "from", short, "msg", msg.Payload)
	}

	// 3. Dispatch to user-registered handlers.
	p.handlersMu.RLock()
	handlers := append([]Handler(nil), p.handlers...)
	p.handlersMu.RUnlock()
	for _, h := range handlers {
		h.HandleMessage(p, from, msg)
	}
}

// newReqID returns a fresh, cryptographically random request ID.
func newReqID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// registerConn installs pc into the peer maps, OR returns the existing
// connection for the same peer ID if one was already there. The caller
// uses the return to decide whether to keep the new connection or
// discard it as a duplicate.
//
// The dedup happens by remoteID (set during the secure handshake), so
// dialing the same peer at multiple addresses (direct + relay, two
// different relays, etc.) collapses to a single live TCP socket.
//
// On dedup, the new address is registered as an alias of the existing
// conn, so future Send(addr, ...) on either address Just Works.
func (p *Peer) registerConn(pc *peerConn, addr string) (existing *peerConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pc.remoteID != "" {
		if cur, ok := p.peersByID[pc.remoteID]; ok && cur != pc {
			p.peers[addr] = cur
			cur.addresses = appendUnique(cur.addresses, addr)
			return cur
		}
		p.peersByID[pc.remoteID] = pc
	}
	p.peers[addr] = pc
	pc.addresses = appendUnique(pc.addresses, addr)
	return nil
}

// removeConn drops every alias and the by-ID entry for pc. Called when
// the readLoop exits because the underlying connection has closed.
func (p *Peer) removeConn(pc *peerConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pc.remoteID != "" {
		// Only remove the by-ID entry if it still points to THIS pc.
		// A reconnect could have replaced it with a fresh one already.
		if cur, ok := p.peersByID[pc.remoteID]; ok && cur == pc {
			delete(p.peersByID, pc.remoteID)
		}
	}
	for _, a := range pc.addresses {
		if cur, ok := p.peers[a]; ok && cur == pc {
			delete(p.peers, a)
		}
	}
}

// AddPeerAddress registers an additional address as an alias for an
// already-connected peer. Useful when the peer's hello reveals an
// address (its advertised one) that we didn't dial it through, so
// subsequent Send(advertisedAddr, ...) finds the existing connection
// instead of opening a redundant one.
//
// Returns true if the alias was added (peer is connected and the
// address wasn't already an alias), false if not.
func (p *Peer) AddPeerAddress(peerID, addr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc, ok := p.peersByID[peerID]
	if !ok {
		return false
	}
	if cur, ok := p.peers[addr]; ok && cur == pc {
		return false // already aliased
	}
	p.peers[addr] = pc
	pc.addresses = appendUnique(pc.addresses, addr)
	return true
}

// appendUnique adds s to slice if not already present.
func appendUnique(slice []string, s string) []string {
	for _, x := range slice {
		if x == s {
			return slice
		}
	}
	return append(slice, s)
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
