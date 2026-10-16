package dht

import (
	"sync"
	"time"
)

// K is the maximum number of contacts kept in each bucket.
// 20 is the value used by the original Kademlia paper and BitTorrent's DHT.
// It is a tradeoff: bigger K is more robust against churn, smaller K uses
// less memory and bandwidth.
const K = 20

// Contact is what we know about a remote peer in the DHT.
//
// A peer can be reachable through multiple paths: a direct host:port
// AND/OR one or more relay URLs. Address is the primary (first one we
// learned about) and AltAddresses are the fallbacks the dialer tries
// if the primary fails. This is how a peer registered with several
// relays stays reachable when any single relay dies.
type Contact struct {
	ID            NodeID
	Address       string    // primary network address
	AltAddresses  []string  // additional addresses to try on dial failure
	LastSeen      time.Time // updated whenever we successfully exchange a message
}

// AllAddresses returns Address followed by AltAddresses as a single
// slice, so callers can iterate over every dialing option.
func (c Contact) AllAddresses() []string {
	out := make([]string, 0, 1+len(c.AltAddresses))
	if c.Address != "" {
		out = append(out, c.Address)
	}
	out = append(out, c.AltAddresses...)
	return out
}

// bucket holds up to K contacts, ordered from least-recently-seen (head)
// to most-recently-seen (tail). This eviction-by-staleness is what gives
// Kademlia its resilience: long-lived peers tend to stay long-lived, so
// preferring them over newcomers makes the table robust.
type bucket struct {
	contacts []Contact
}

// RoutingTable is the per-peer view of the DHT. It groups known contacts
// by how many leading bits their ID shares with our own ID.
//
//	bucket[i] holds contacts whose ID has common-prefix-length == i with self
//
// Bucket 0 covers half the keyspace (peers that differ in the very first
// bit), bucket 1 covers a quarter, and so on. So we know lots about peers
// far from us in keyspace and very few peers close to us — the opposite is
// also true: a target lookup converges fast because every hop halves the
// remaining distance.
type RoutingTable struct {
	self    NodeID
	buckets [IDSize * 8]bucket
	mu      sync.Mutex

	// evictionPing, if set, is called when a bucket is full and a new
	// contact arrives. The head of the bucket (least-recently-seen) is
	// pinged: if the ping returns true, the head is alive, so we keep
	// it and drop the candidate. If the ping returns false, the head
	// is dead, we evict it, and add the candidate instead.
	//
	// This is the proper Kademlia eviction: long-lived stable peers
	// stay in the table over flaky newcomers, but a long-lived peer
	// that has actually died finally gets replaced. Without this hook,
	// a bucket full of dead peers would permanently lock out fresh
	// contacts.
	//
	// The ping is run in a goroutine outside the routing-table lock.
	evictionPing func(c Contact) bool
}

// NewRoutingTable creates an empty routing table for the given local ID.
func NewRoutingTable(self NodeID) *RoutingTable {
	return &RoutingTable{self: self}
}

// Self returns the local node's ID.
func (rt *RoutingTable) Self() NodeID { return rt.self }

// Update records that we just heard from a peer. If the contact is already
// in the right bucket, it is moved to the tail (most-recently-seen). If the
// bucket has room, the contact is appended. Otherwise the contact is
// dropped (real Kademlia would ping the head of the bucket and only evict
// if that ping fails -- a refinement we'll add in a later iteration).
//
// When a contact for the same ID is already present, the new contact's
// addresses are MERGED with the existing ones. The new primary Address
// takes precedence; the previous primary is demoted into AltAddresses
// if it's not already there. This is what keeps a peer reachable when
// any single relay it advertises happens to be down.
func (rt *RoutingTable) Update(c Contact) {
	if c.ID.Equal(rt.self) {
		return // never store ourselves in our own table
	}
	idx := rt.self.CommonPrefixLen(c.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b := &rt.buckets[idx]

	c.LastSeen = time.Now()

	// If already present, merge addresses and move to the tail.
	for i, existing := range b.contacts {
		if existing.ID.Equal(c.ID) {
			merged := mergeAddresses(c, existing)
			b.contacts = append(b.contacts[:i], b.contacts[i+1:]...)
			b.contacts = append(b.contacts, merged)
			return
		}
	}

	if len(b.contacts) < K {
		b.contacts = append(b.contacts, c)
		return
	}

	// Bucket full. If we have a ping callback, run the head-ping
	// eviction protocol asynchronously: alive head -> drop candidate;
	// dead head -> evict head, add candidate. Without a callback, fall
	// back to the simpler "drop the candidate" behavior.
	if rt.evictionPing == nil {
		return
	}
	candidate := c
	head := b.contacts[0]
	go rt.maybeEvictHead(idx, head, candidate)
}

// SetEvictionPing installs the head-of-bucket ping callback. Calling
// it with nil disables the eviction protocol.
func (rt *RoutingTable) SetEvictionPing(fn func(c Contact) bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.evictionPing = fn
}

// maybeEvictHead is the async tail of a full-bucket Update: it pings
// the head and either refreshes it (alive) or replaces it with the
// candidate (dead).
func (rt *RoutingTable) maybeEvictHead(idx int, head, candidate Contact) {
	rt.mu.Lock()
	ping := rt.evictionPing
	rt.mu.Unlock()
	if ping == nil {
		return
	}

	alive := ping(head)

	rt.mu.Lock()
	defer rt.mu.Unlock()
	b := &rt.buckets[idx]

	if alive {
		// Move head to tail to refresh its position; drop the candidate.
		if len(b.contacts) > 0 && b.contacts[0].ID.Equal(head.ID) {
			h := b.contacts[0]
			h.LastSeen = time.Now()
			b.contacts = append(b.contacts[1:], h)
		}
		return
	}

	// Head is dead: evict and let the candidate in.
	for i, c := range b.contacts {
		if c.ID.Equal(head.ID) {
			b.contacts = append(b.contacts[:i], b.contacts[i+1:]...)
			break
		}
	}
	if len(b.contacts) < K {
		candidate.LastSeen = time.Now()
		b.contacts = append(b.contacts, candidate)
	}
}

// Hint adds a contact we've LEARNED ABOUT secondhand (from another
// peer's FindNode reply, for example) but haven't actually heard from
// directly. Compared to Update, Hint:
//
//   - Sets LastSeen to the zero value, marking the contact as "untrusted
//     until proven" -- it's the oldest entry in any bucket and will be
//     the first one our maintenance ping probes / evicts.
//   - Is a no-op if the contact is already in the table (we don't want
//     a third-party hint to refresh a contact we directly verified).
//
// This is the routing-table-poisoning defense: a malicious peer can
// stuff our table by returning fake contacts in find_node replies,
// but those entries enter as the LEAST-trusted bucket members and
// get pushed out by genuine direct interactions before they can
// dominate routing.
func (rt *RoutingTable) Hint(c Contact) {
	if c.ID.Equal(rt.self) {
		return
	}
	idx := rt.self.CommonPrefixLen(c.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b := &rt.buckets[idx]

	// Already present? Don't refresh -- a direct interaction earned
	// its current LastSeen, and we don't want a third-party hint
	// (possibly malicious) to refresh that.
	for _, existing := range b.contacts {
		if existing.ID.Equal(c.ID) {
			return
		}
	}

	if len(b.contacts) < K {
		// Insert at the HEAD of the bucket with zero LastSeen. The
		// head position means head-of-bucket eviction will probe it
		// first if a new candidate arrives.
		c.LastSeen = time.Time{}
		// Prepend.
		b.contacts = append([]Contact{c}, b.contacts...)
	}
	// Bucket full and contact unknown: drop. We refuse to evict a
	// direct-contact entry to make room for an unverified hint.
}

// Remove deletes a contact from whatever bucket it lives in.
// Used when we know a peer is dead.
func (rt *RoutingTable) Remove(id NodeID) {
	idx := rt.self.CommonPrefixLen(id)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b := &rt.buckets[idx]
	for i, c := range b.contacts {
		if c.ID.Equal(id) {
			b.contacts = append(b.contacts[:i], b.contacts[i+1:]...)
			return
		}
	}
}

// Size returns the total number of contacts across all buckets.
func (rt *RoutingTable) Size() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	total := 0
	for i := range rt.buckets {
		total += len(rt.buckets[i].contacts)
	}
	return total
}

// Closest returns up to n contacts ordered by XOR distance to target,
// closest first. This is the operation that powers iterative lookups:
// "give me the n peers most likely to know more about this ID."
func (rt *RoutingTable) Closest(target NodeID, n int) []Contact {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Gather all contacts. With at most 256 buckets * K contacts each, the
	// total size is bounded. Sorting them all is fine for now.
	all := make([]Contact, 0, K*4)
	for i := range rt.buckets {
		all = append(all, rt.buckets[i].contacts...)
	}

	// Selection sort the first n by distance. n is small (typically <=K=20)
	// so this is faster and simpler than a full sort.
	if n > len(all) {
		n = len(all)
	}
	for i := 0; i < n; i++ {
		minIdx := i
		for j := i + 1; j < len(all); j++ {
			if DistanceLess(target, all[j].ID, all[minIdx].ID) {
				minIdx = j
			}
		}
		all[i], all[minIdx] = all[minIdx], all[i]
	}
	return all[:n]
}

// All returns a snapshot of every contact currently in the table.
// Useful for debugging and tests.
func (rt *RoutingTable) All() []Contact {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]Contact, 0, K)
	for i := range rt.buckets {
		out = append(out, rt.buckets[i].contacts...)
	}
	return out
}

// mergeAddresses returns a Contact whose primary Address is the new
// contact's, and whose AltAddresses is the deduplicated union of every
// address from both sides. The point: keep every reachability path the
// network has ever told us about, in case any individual one dies.
func mergeAddresses(fresh, prior Contact) Contact {
	out := fresh
	out.AltAddresses = nil

	seen := map[string]bool{}
	if fresh.Address != "" {
		seen[fresh.Address] = true
	}

	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out.AltAddresses = append(out.AltAddresses, s)
	}
	for _, a := range fresh.AltAddresses {
		add(a)
	}
	if prior.Address != "" {
		add(prior.Address)
	}
	for _, a := range prior.AltAddresses {
		add(a)
	}
	return out
}
