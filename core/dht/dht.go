package dht

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"altnet/core/crypto"
	"altnet/core/peer"
)

// Alpha is the Kademlia parallelism factor: how many peers to query in
// parallel during a lookup. The classic paper recommends 3.
const Alpha = 3

// DefaultRequestTimeout caps how long any single dht_* RPC will wait for a
// reply before giving up.
const DefaultRequestTimeout = 5 * time.Second

// DHT is a Kademlia-style distributed hash table for the local peer.
//
// It owns the routing table and a local key/value store, and registers
// itself as a peer.Handler so it can react to dht_* messages and to hello
// messages (which establish fresh contacts).
type DHT struct {
	p     *peer.Peer
	self  NodeID
	rt    *RoutingTable
	store *localStore

	// blocklist holds chunk hashes the node refuses to accept or serve
	// (CSAM, abuse-reported content the registrar revoked, etc.). nil
	// means "no blocklist configured" — Contains always returns false.
	// Wired via SetBlocklist; reads use the Blocklist's own RWMutex.
	blocklist *Blocklist

	// trustedRevokers is the set of Ed25519 pubkeys whose signed
	// dht_revoke messages this node honours. nil = revokes disabled.
	trustedRevokers *TrustedRevokers

	// revokeSeen dedups already-applied revokes by their canonical
	// content hash, so propagation gossip can't loop forever. Lazily
	// pruned in handleRevoke when the map exceeds 1024 entries.
	revokeSeenMu sync.Mutex
	revokeSeen   map[string]time.Time

	// inflightGets coalesces parallel Get/GetUnverified calls for the
	// same key into a single network walk. Without this, ten parallel
	// gateway requests for the same video each run the full iterative
	// lookup -- N redundant fan-outs into the network. With this, the
	// first caller does the work; the others block on its done channel
	// and pick up the same result.
	inflightMu  sync.Mutex
	inflightGet map[string]*inflightGet
}

// SetBlocklist installs a chunk-hash blocklist on the DHT. From this
// point forward, dht_store messages for blocked hashes are silently
// dropped at the receiving side, Get/GetUnverified for blocked hashes
// return ErrNotFound, and Store() for blocked hashes is a no-op
// returning 0 replicas without an error. Idempotent — calling with
// nil disables blocking. Safe to call at any time, but in practice
// callers set it once at daemon startup.
func (d *DHT) SetBlocklist(bl *Blocklist) {
	d.blocklist = bl
}

// IsBlocked reports whether key is on the active blocklist. Cheap;
// the gateway / files layer check this before publishing or serving.
func (d *DHT) IsBlocked(key NodeID) bool {
	return d.blocklist != nil && d.blocklist.Contains(key)
}

// inflightGet tracks one in-flight lookup so concurrent callers can
// share its result.
type inflightGet struct {
	done  chan struct{}
	value []byte
	err   error
}

// New creates an in-memory DHT for the given peer and starts handling
// messages. The peer must already be Started.
//
// Use NewWithDataDir if you want stored values to persist across restarts.
func New(p *peer.Peer) (*DHT, error) {
	return NewWithDataDir(p, "")
}

// NewWithDataDir creates a DHT whose local store is backed by disk at
// dataDir with no size cap. Equivalent to NewWithLimit(p, dataDir, 0).
func NewWithDataDir(p *peer.Peer, dataDir string) (*DHT, error) {
	return NewWithLimit(p, dataDir, 0)
}

// NewWithLimit creates a DHT whose local store is backed by disk at
// dataDir, capped at maxBytes total with DefaultPerPeerBudgetBytes
// per remote peer. maxBytes=0 means unlimited total budget. Use
// NewWithFullLimit to override the per-peer cap too.
//
// When the budget would be exceeded, the least-recently-accessed
// entries are evicted to make room. This is what keeps a long-running
// node from filling its disk.
func NewWithLimit(p *peer.Peer, dataDir string, maxBytes int64) (*DHT, error) {
	return NewWithFullLimit(p, dataDir, maxBytes, DefaultPerPeerBudgetBytes)
}

// NewWithFullLimit is NewWithLimit plus an explicit per-peer byte cap.
// perPeerMax=0 disables per-peer accounting (any peer may store up to
// the total budget).
func NewWithFullLimit(p *peer.Peer, dataDir string, maxBytes, perPeerMax int64) (*DHT, error) {
	selfID, err := IDFromHex(p.Identity.ID())
	if err != nil {
		return nil, fmt.Errorf("dht: parse self id: %w", err)
	}
	store, err := newLocalStoreWithLimit(dataDir, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("dht: open store: %w", err)
	}
	store.SetPerPeerMax(perPeerMax)
	d := &DHT{
		p:           p,
		self:        selfID,
		rt:          NewRoutingTable(selfID),
		store:       store,
		inflightGet: make(map[string]*inflightGet),
	}
	// Install head-of-bucket eviction: when a bucket is full and a
	// new contact arrives, the routing table will ping the head and
	// only evict it if it's actually dead.
	d.rt.SetEvictionPing(func(c Contact) bool {
		return d.Ping(c) == nil
	})
	p.AddHandler(d)
	return d, nil
}

// LocalStoreSize returns the number of (key,value) pairs this peer is
// currently holding. Useful for tests/debug.
func (d *DHT) LocalStoreSize() int { return d.store.Size() }

// LocalStoreBytes returns the total bytes currently held in the
// local store across all entries.
func (d *DHT) LocalStoreBytes() int64 { return d.store.TotalBytes() }

// LocalStoreBudget returns the configured byte budget for the local
// store (0 = unlimited).
func (d *DHT) LocalStoreBudget() int64 {
	d.store.mu.RLock()
	defer d.store.mu.RUnlock()
	return d.store.maxBytes
}

// Self returns the local node's ID.
func (d *DHT) Self() NodeID { return d.self }

// RoutingTable exposes the routing table (read-only access for tests/debug).
func (d *DHT) RoutingTable() *RoutingTable { return d.rt }

// HandleMessage implements peer.Handler.
func (d *DHT) HandleMessage(p *peer.Peer, addr string, msg peer.Message) {
	switch msg.Type {
	case "hello":
		d.observeHello(addr, msg)
	case "goodbye":
		d.observeGoodbye(msg)
	case "dht_ping":
		d.handlePing(p, addr, msg)
	case "dht_find_node":
		d.handleFindNode(p, addr, msg)
	case "dht_store":
		d.handleStore(p, addr, msg)
	case "dht_find_value":
		d.handleFindValue(p, addr, msg)
	case "dht_revoke":
		d.handleRevoke(p, addr, msg)
	}
}

// observeGoodbye removes the sender from our routing table immediately
// instead of waiting for a future ping to fail. The signature on the
// message has already been verified by peer.go before this handler runs,
// so we know the goodbye actually came from the claimed peer.
func (d *DHT) observeGoodbye(msg peer.Message) {
	pub, err := crypto.PublicKeyFromHex(msg.PublicKey)
	if err != nil {
		return
	}
	id, err := IDFromHex(crypto.PublicKeyToID(pub))
	if err != nil {
		return
	}
	d.rt.Remove(id)
}

// observeHello extracts the sender's identity and listening address(es)
// from a hello message and records them in the routing table.
//
// The connection-level remote address (addr) is the dialer's *ephemeral*
// port and is useless for dialing them back, so we use the listening
// address(es) advertised in the hello payload. The payload is a
// comma-separated list (direct host:port and/or relay URLs); we record
// the first as primary and keep the rest as alternates so the dialer
// can fail over between them when any one is dead.
func (d *DHT) observeHello(addr string, msg peer.Message) {
	pub, err := crypto.PublicKeyFromHex(msg.PublicKey)
	if err != nil {
		return
	}
	id, err := IDFromHex(crypto.PublicKeyToID(pub))
	if err != nil {
		return
	}
	addrs := decodeAddressesPayload(msg.Payload)
	if len(addrs) == 0 {
		addrs = []string{addr}
	}
	c := Contact{ID: id, Address: addrs[0]}
	if len(addrs) > 1 {
		c.AltAddresses = append(c.AltAddresses, addrs[1:]...)
	}
	d.rt.Update(c)

	// Tell the peer layer that every advertised address now aliases the
	// existing connection to this peer. Without this, a later RPC that
	// dials by an advertised address would open a redundant TCP socket
	// instead of reusing the conn we already have.
	for _, a := range addrs {
		d.p.AddPeerAddress(crypto.PublicKeyToID(pub), a)
	}
}

// decodeAddressesPayload parses a comma-separated address list from a
// hello payload. Whitespace is tolerated; empty entries are dropped.
// Lives here in dht (rather than calling out to peer) to keep the
// import graph one-way.
func decodeAddressesPayload(payload string) []string {
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

// --- Contact-aware request helper ---

// requestContact sends msg to c, trying each of c's addresses in order
// (primary first, then alts) until one succeeds. Returns the reply
// from the first reachable address. If every address fails, returns
// the last error.
//
// This is what makes multi-address contacts useful: a peer that
// advertised both a direct address and a relay URL stays reachable
// even if the direct address stops working.
func (d *DHT) requestContact(c Contact, msg peer.Message, timeout time.Duration) (peer.Message, error) {
	addrs := c.AllAddresses()
	if len(addrs) == 0 {
		return peer.Message{}, errors.New("dht: contact has no addresses")
	}
	var lastErr error
	for _, addr := range addrs {
		reply, err := d.p.Request(addr, msg, timeout)
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return peer.Message{}, lastErr
}

// --- Ping ---

// Ping sends a dht_ping to a contact. Returns nil if the peer replies
// before timeout, error otherwise. On success the contact is refreshed
// in the routing table (moved to most-recently-seen).
func (d *DHT) Ping(c Contact) error {
	reply, err := d.requestContact(c, peer.Message{Type: "dht_ping"}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	if reply.Type != "dht_pong" {
		return fmt.Errorf("dht_ping: unexpected reply %q", reply.Type)
	}
	d.rt.Update(c)
	return nil
}

func (d *DHT) handlePing(p *peer.Peer, addr string, msg peer.Message) {
	_ = p.Reply(addr, msg, peer.Message{Type: "dht_pong"})
}

// --- FindNode ---

// findNodePayload is the JSON body of a dht_find_node request.
type findNodePayload struct {
	Target string `json:"target"`
}

// nodesPayload is the JSON body of a dht_nodes reply.
type nodesPayload struct {
	Contacts []wireContact `json:"contacts"`
}

type wireContact struct {
	ID      string   `json:"id"`
	Address string   `json:"address"`
	Alt     []string `json:"alt,omitempty"` // additional addresses (relays etc.)
}

// FindNode asks a remote contact for its K closest known peers to target.
// On success the contact is refreshed in our routing table.
func (d *DHT) FindNode(c Contact, target NodeID) ([]Contact, error) {
	body, err := json.Marshal(findNodePayload{Target: target.Hex()})
	if err != nil {
		return nil, err
	}
	reply, err := d.requestContact(c, peer.Message{
		Type:    "dht_find_node",
		Payload: string(body),
	}, DefaultRequestTimeout)
	if err != nil {
		return nil, err
	}
	if reply.Type != "dht_nodes" {
		return nil, fmt.Errorf("dht_find_node: unexpected reply %q", reply.Type)
	}
	var np nodesPayload
	if err := json.Unmarshal([]byte(reply.Payload), &np); err != nil {
		return nil, fmt.Errorf("decode dht_nodes: %w", err)
	}
	out := make([]Contact, 0, len(np.Contacts))
	for _, wc := range np.Contacts {
		id, err := IDFromHex(wc.ID)
		if err != nil {
			continue
		}
		out = append(out, Contact{
			ID:           id,
			Address:      wc.Address,
			AltAddresses: append([]string(nil), wc.Alt...),
		})
	}
	d.rt.Update(c)
	return out, nil
}

func (d *DHT) handleFindNode(p *peer.Peer, addr string, msg peer.Message) {
	var fnp findNodePayload
	if err := json.Unmarshal([]byte(msg.Payload), &fnp); err != nil {
		return
	}
	target, err := IDFromHex(fnp.Target)
	if err != nil {
		return
	}
	closest := d.rt.Closest(target, K)
	out := nodesPayload{Contacts: make([]wireContact, 0, len(closest))}
	for _, c := range closest {
		out.Contacts = append(out.Contacts, wireContact{
			ID:      c.ID.Hex(),
			Address: c.Address,
			Alt:     append([]string(nil), c.AltAddresses...),
		})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return
	}
	_ = p.Reply(addr, msg, peer.Message{Type: "dht_nodes", Payload: string(body)})
}

// --- Bootstrap & Lookup ---

// Bootstrap connects to a known peer at addr, waits for the hello exchange
// to populate the routing table, then runs a Lookup of our own ID. The
// lookup pulls in nearby peers known to the bootstrap node.
//
// Returns an error if the bootstrap peer never sends a valid hello within
// a couple of seconds.
func (d *DHT) Bootstrap(addr string) error {
	if err := d.p.EnsureConnected(addr); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.rt.Size() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d.rt.Size() == 0 {
		return errors.New("dht: no hello from bootstrap peer " + addr)
	}
	d.Lookup(d.self)
	return nil
}

// Lookup runs the Kademlia iterative lookup for target. It returns the K
// closest contacts found across the network, ordered by XOR distance.
//
// The algorithm:
//  1. Pick the Alpha closest known contacts from the routing table.
//  2. Send dht_find_node to all of them in parallel.
//  3. Merge their replies into the candidate set.
//  4. Recompute the K closest known contacts. If we found a closer one
//     this round, repeat. Otherwise we have converged.
//
// This is a simplified version of the original paper's algorithm.
// We don't yet do strict Î±-parallel-with-K-closest-fallback; we just
// loop until no progress.
func (d *DHT) Lookup(target NodeID) []Contact {
	queried := make(map[string]bool)
	shortlist := d.rt.Closest(target, K)

	for {
		var batch []Contact
		for _, c := range shortlist {
			if queried[c.ID.Hex()] {
				continue
			}
			batch = append(batch, c)
			if len(batch) >= Alpha {
				break
			}
		}
		if len(batch) == 0 {
			break
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var learned []Contact
		for _, c := range batch {
			queried[c.ID.Hex()] = true
			wg.Add(1)
			go func(c Contact) {
				defer wg.Done()
				nodes, err := d.FindNode(c, target)
				if err != nil {
					return
				}
				mu.Lock()
				learned = append(learned, nodes...)
				mu.Unlock()
			}(c)
		}
		wg.Wait()

		before := closestHex(target, shortlist)
		for _, c := range learned {
			if c.ID.Equal(d.self) {
				continue
			}
			// Hint, not Update: these contacts came secondhand from a
			// peer's find_node reply. They get into the table as
			// untrusted (oldest LastSeen), and only get promoted to
			// trusted entries after we successfully RPC them ourselves.
			d.rt.Hint(c)
		}
		shortlist = d.rt.Closest(target, K)
		after := closestHex(target, shortlist)
		if before == after {
			break // no progress, converged
		}
	}

	sort.SliceStable(shortlist, func(i, j int) bool {
		return DistanceLess(target, shortlist[i].ID, shortlist[j].ID)
	})
	if len(shortlist) > K {
		shortlist = shortlist[:K]
	}
	return shortlist
}

// closestHex returns the hex ID of the contact closest to target.
// Returns empty string if contacts is empty.
func closestHex(target NodeID, contacts []Contact) string {
	if len(contacts) == 0 {
		return ""
	}
	best := contacts[0]
	for _, c := range contacts[1:] {
		if DistanceLess(target, c.ID, best.ID) {
			best = c
		}
	}
	return best.ID.Hex()
}

// --- STORE / FIND_VALUE ---

type storePayload struct {
	Key   string `json:"key"`
	Value string `json:"value"` // base64-encoded
}

type findValuePayload struct {
	Key string `json:"key"`
}

type valuePayload struct {
	Value string `json:"value"` // base64-encoded
}

func (d *DHT) handleStore(p *peer.Peer, addr string, msg peer.Message) {
	var sp storePayload
	if err := json.Unmarshal([]byte(msg.Payload), &sp); err != nil {
		return
	}
	key, err := IDFromHex(sp.Key)
	if err != nil {
		return
	}
	value, err := base64.StdEncoding.DecodeString(sp.Value)
	if err != nil {
		return
	}
	if len(value) > MaxValueSize {
		return // silently drop oversized values
	}
	// Blocklist gate: refuse to accept chunks whose hash is on the
	// local blocklist (CSAM, revoked content). Silent drop — we don't
	// want to confirm to the sender whether we'd otherwise have stored
	// it. We also acknowledge the store (to avoid leaking which nodes
	// have a populated blocklist) but skip the actual write.
	if d.IsBlocked(key) {
		_ = p.Reply(addr, msg, peer.Message{Type: "dht_stored"})
		return
	}
	// Attribute the bytes to the sender so the per-peer quota can
	// limit any single remote from filling our store. msg.From is
	// the verified peer ID (set by peer.go before we see this).
	if !d.store.PutAttributed(key, value, msg.From) {
		// Quota exceeded -- silently drop. We could reply with an
		// explicit error, but that just gives an attacker confirmation.
		return
	}
	_ = p.Reply(addr, msg, peer.Message{Type: "dht_stored"})
}

func (d *DHT) handleFindValue(p *peer.Peer, addr string, msg peer.Message) {
	var fvp findValuePayload
	if err := json.Unmarshal([]byte(msg.Payload), &fvp); err != nil {
		return
	}
	key, err := IDFromHex(fvp.Key)
	if err != nil {
		return
	}

	// Blocklist gate: never serve blocked content to other peers, even
	// if we happen to have it cached locally (e.g. from before the
	// hash got added to the blocklist). Behave exactly as if we'd
	// never heard of the key — fall through to find_node behaviour.
	if d.IsBlocked(key) {
		closest := d.rt.Closest(key, K)
		out := nodesPayload{Contacts: make([]wireContact, 0, len(closest))}
		for _, c := range closest {
			out.Contacts = append(out.Contacts, wireContact{
				ID:      c.ID.Hex(),
				Address: c.Address,
			})
		}
		body, _ := json.Marshal(out)
		_ = p.Reply(addr, msg, peer.Message{Type: "dht_nodes", Payload: string(body)})
		return
	}

	// If we have it, return the value directly.
	if value, ok := d.store.Get(key); ok {
		body, _ := json.Marshal(valuePayload{Value: base64.StdEncoding.EncodeToString(value)})
		_ = p.Reply(addr, msg, peer.Message{Type: "dht_value", Payload: string(body)})
		return
	}

	// Otherwise behave like find_node: return our K closest known peers.
	closest := d.rt.Closest(key, K)
	out := nodesPayload{Contacts: make([]wireContact, 0, len(closest))}
	for _, c := range closest {
		out.Contacts = append(out.Contacts, wireContact{
			ID:      c.ID.Hex(),
			Address: c.Address,
		})
	}
	body, _ := json.Marshal(out)
	_ = p.Reply(addr, msg, peer.Message{Type: "dht_nodes", Payload: string(body)})
}

// sendStore tells one specific peer to store (key, value).
func (d *DHT) sendStore(c Contact, key NodeID, value []byte) error {
	body, err := json.Marshal(storePayload{
		Key:   key.Hex(),
		Value: base64.StdEncoding.EncodeToString(value),
	})
	if err != nil {
		return err
	}
	reply, err := d.requestContact(c, peer.Message{
		Type:    "dht_store",
		Payload: string(body),
	}, DefaultRequestTimeout)
	if err != nil {
		return err
	}
	if reply.Type != "dht_stored" {
		return fmt.Errorf("dht_store: unexpected reply %q", reply.Type)
	}
	d.rt.Update(c)
	return nil
}

// sendFindValue asks one peer for the value at key.
//
// Returns one of three outcomes:
//   - (value, nil, nil) -- peer had the value
//   - (nil, contacts, nil) -- peer didn't have it; here are closer peers
//   - (nil, nil, err) -- RPC failed
func (d *DHT) sendFindValue(c Contact, key NodeID) ([]byte, []Contact, error) {
	body, err := json.Marshal(findValuePayload{Key: key.Hex()})
	if err != nil {
		return nil, nil, err
	}
	reply, err := d.requestContact(c, peer.Message{
		Type:    "dht_find_value",
		Payload: string(body),
	}, DefaultRequestTimeout)
	if err != nil {
		return nil, nil, err
	}
	d.rt.Update(c)

	switch reply.Type {
	case "dht_value":
		var vp valuePayload
		if err := json.Unmarshal([]byte(reply.Payload), &vp); err != nil {
			return nil, nil, err
		}
		value, err := base64.StdEncoding.DecodeString(vp.Value)
		if err != nil {
			return nil, nil, err
		}
		return value, nil, nil

	case "dht_nodes":
		var np nodesPayload
		if err := json.Unmarshal([]byte(reply.Payload), &np); err != nil {
			return nil, nil, err
		}
		out := make([]Contact, 0, len(np.Contacts))
		for _, wc := range np.Contacts {
			id, err := IDFromHex(wc.ID)
			if err != nil {
				continue
			}
			out = append(out, Contact{
				ID:           id,
				Address:      wc.Address,
				AltAddresses: append([]string(nil), wc.Alt...),
			})
		}
		return nil, out, nil

	default:
		return nil, nil, fmt.Errorf("dht_find_value: unexpected reply %q", reply.Type)
	}
}

// Store distributes (key, value) to the K closest known peers to key.
// Also stores locally so that this node serves as a cache.
//
// Returns the number of peers that successfully acknowledged the STORE.
// Returns an error only if the value is oversized; partial replication is
// reported via the count, not as an error.
func (d *DHT) Store(key NodeID, value []byte) (int, error) {
	if err := d.StoreLocal(key, value); err != nil {
		return 0, err
	}
	// Blocklist gate: refuse to publish content whose hash is blocked.
	// Returns no error (the publisher gets a 0-replicas success rather
	// than a confusing failure) — combined with the find_value gate,
	// this means a blocked chunk simply does not exist on the network.
	if d.IsBlocked(key) {
		return 0, nil
	}
	return d.Replicate(key, value), nil
}

// StoreLocal writes (key, value) into this node's local store only — no
// network Lookup, no store RPCs. The value is immediately retrievable from
// this node and answerable to peers' find_value, but it is not pushed to
// the K-closest peers. Pair it with Replicate (typically in a background
// goroutine) when a caller needs to return promptly and can let network
// propagation catch up — e.g. bulk site publishing, where a synchronous
// per-chunk Lookup serializes into minutes on a node with slow or stale
// peers.
func (d *DHT) StoreLocal(key NodeID, value []byte) error {
	if len(value) > MaxValueSize {
		return fmt.Errorf("value too large: %d bytes (max %d)", len(value), MaxValueSize)
	}
	if d.IsBlocked(key) {
		return nil
	}
	d.store.Put(key, value)
	return nil
}

// Replicate pushes an (already locally stored) value out to the K-closest
// peers, best effort, and returns how many accepted it. It performs a
// network Lookup and parallel store RPCs, so it can take seconds on a slow
// network — it is safe to call from a background goroutine.
func (d *DHT) Replicate(key NodeID, value []byte) int {
	if d.IsBlocked(key) {
		return 0
	}
	targets := d.Lookup(key)

	var wg sync.WaitGroup
	var successes int32
	for _, c := range targets {
		if c.ID.Equal(d.self) {
			continue
		}
		wg.Add(1)
		go func(c Contact) {
			defer wg.Done()
			if err := d.sendStore(c, key, value); err == nil {
				atomic.AddInt32(&successes, 1)
			}
		}(c)
	}
	wg.Wait()
	return int(successes)
}

// Get retrieves the value for a content-addressed key from the DHT.
//
// "Content-addressed" means the key is the SHA-256 hash of the value
// (i.e. produced by ContentAddress). On retrieval we recompute the hash
// of every value returned by the network and DISCARD any value whose
// hash does not match the requested key. This makes the lookup
// self-verifying: a malicious peer cannot convince us to accept a value
// that has been tampered with, because doing so would require finding a
// SHA-256 collision.
//
// If the network has only the wrong value (no peer has the real one)
// Get returns ErrNotFound rather than the corrupt data.
//
// For non-content-addressed keys (e.g. name-based or arbitrary keys) use
// GetUnverified.
func (d *DHT) Get(key NodeID) ([]byte, error) {
	return d.get(key, true)
}

// GetUnverified is like Get but skips the content-hash check. Use only
// when the key is not a content address (e.g. DNS-style name -> record
// mappings where value has its own signature for authenticity).
func (d *DHT) GetUnverified(key NodeID) ([]byte, error) {
	return d.get(key, false)
}

// GetAllUnverified collects EVERY distinct value seen for key across the
// network, by querying peers iteratively (like get) but never
// short-circuiting on first response.
//
// This is what mutable-record callers (e.g. the name layer) use to
// pick the freshest record across replicas: peers that hold a stale
// copy don't get to win just by responding first. The caller is
// responsible for verifying each returned value and picking the
// authoritative one (highest version, valid signature, matching name,
// etc.).
//
// Returns ErrNotFound if no peer at all returned a value.
func (d *DHT) GetAllUnverified(key NodeID) ([][]byte, error) {
	results := make(map[string][]byte) // dedupe by raw bytes

	// Local copy first.
	if v, ok := d.store.Get(key); ok {
		results[string(v)] = append([]byte(nil), v...)
	}

	queried := make(map[string]bool)
	shortlist := d.rt.Closest(key, K)
	if len(shortlist) == 0 && len(results) == 0 {
		return nil, errors.New("dht: routing table empty; bootstrap first")
	}

	for {
		var batch []Contact
		for _, c := range shortlist {
			if queried[c.ID.Hex()] {
				continue
			}
			batch = append(batch, c)
			if len(batch) >= Alpha {
				break
			}
		}
		if len(batch) == 0 {
			break
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var learned []Contact
		for _, c := range batch {
			queried[c.ID.Hex()] = true
			wg.Add(1)
			go func(c Contact) {
				defer wg.Done()
				value, contacts, err := d.sendFindValue(c, key)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if value != nil {
					results[string(value)] = append([]byte(nil), value...)
					return
				}
				learned = append(learned, contacts...)
			}(c)
		}
		wg.Wait()

		before := closestHex(key, shortlist)
		for _, c := range learned {
			if c.ID.Equal(d.self) {
				continue
			}
			d.rt.Hint(c) // secondhand contact from GetAllUnverified
		}
		shortlist = d.rt.Closest(key, K)
		after := closestHex(key, shortlist)
		if before == after {
			break
		}
	}

	if len(results) == 0 {
		return nil, ErrNotFound
	}
	out := make([][]byte, 0, len(results))
	for _, v := range results {
		out = append(out, v)
	}
	return out, nil
}

// ErrNotFound is returned by Get/GetUnverified when no peer holds a
// value for the requested key (or all returned values failed verification).
var ErrNotFound = errors.New("dht: value not found")

// get coalesces concurrent calls for the same (key, verify) into a
// single in-flight lookup. The first caller for a given pair runs the
// network walk; subsequent callers wait on its done channel and pick
// up the same result. This is the dedup that prevents ten parallel
// gateway requests for one video from each fanning out a full
// iterative lookup.
func (d *DHT) get(key NodeID, verify bool) ([]byte, error) {
	cacheKey := key.Hex()
	if verify {
		cacheKey += ":v"
	} else {
		cacheKey += ":u"
	}

	d.inflightMu.Lock()
	if existing, ok := d.inflightGet[cacheKey]; ok {
		d.inflightMu.Unlock()
		<-existing.done
		return existing.value, existing.err
	}
	inf := &inflightGet{done: make(chan struct{})}
	d.inflightGet[cacheKey] = inf
	d.inflightMu.Unlock()

	inf.value, inf.err = d.getInner(key, verify)

	d.inflightMu.Lock()
	delete(d.inflightGet, cacheKey)
	d.inflightMu.Unlock()
	close(inf.done)

	return inf.value, inf.err
}

// getInner is the non-coalesced lookup body. Don't call this directly
// from package-external code -- use get() so concurrent calls share
// a single network walk.
func (d *DHT) getInner(key NodeID, verify bool) ([]byte, error) {
	// Blocklist gate: blocked keys behave as if they never existed.
	// We do this before checking the local cache so a node that
	// inherited a now-revoked chunk before the blocklist was updated
	// still won't return it.
	if d.IsBlocked(key) {
		return nil, ErrNotFound
	}
	// Local cache check (still verified -- we may have cached corrupt data
	// from an earlier malicious STORE).
	if v, ok := d.store.Get(key); ok {
		if !verify || ContentAddress(v).Equal(key) {
			return v, nil
		}
		// Local cache holds tampered data; pretend we don't have it
		// and let the network search find a good copy.
	}

	queried := make(map[string]bool)
	shortlist := d.rt.Closest(key, K)
	if len(shortlist) == 0 {
		return nil, errors.New("dht: routing table empty; bootstrap first")
	}

	for {
		var batch []Contact
		for _, c := range shortlist {
			if queried[c.ID.Hex()] {
				continue
			}
			batch = append(batch, c)
			if len(batch) >= Alpha {
				break
			}
		}
		if len(batch) == 0 {
			break
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var foundValue []byte
		var learned []Contact
		for _, c := range batch {
			queried[c.ID.Hex()] = true
			wg.Add(1)
			go func(c Contact) {
				defer wg.Done()
				value, contacts, err := d.sendFindValue(c, key)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if value != nil {
					if verify && !ContentAddress(value).Equal(key) {
						// Peer served data that doesn't match the
						// requested content key. Drop it; keep looking.
						return
					}
					if foundValue == nil {
						foundValue = value
					}
					return
				}
				learned = append(learned, contacts...)
			}(c)
		}
		wg.Wait()

		if foundValue != nil {
			// Cache locally so future Get(key) requests are served from
			// us. This is what makes "visitors become nodes": anyone who
			// views a piece of content automatically begins hosting it.
			// We only cache verified content because storing unverified
			// (mutable) values like name records would freeze stale data.
			if verify {
				d.store.Put(key, foundValue)
			}
			return foundValue, nil
		}

		before := closestHex(key, shortlist)
		for _, c := range learned {
			if c.ID.Equal(d.self) {
				continue
			}
			d.rt.Hint(c) // secondhand contact from find_value reply
		}
		shortlist = d.rt.Closest(key, K)
		after := closestHex(key, shortlist)
		if before == after {
			break
		}
	}

	return nil, ErrNotFound
}
