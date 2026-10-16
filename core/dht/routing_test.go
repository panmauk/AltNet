package dht

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// contactsForBucket generates `count` distinct contacts whose IDs all
// have common-prefix-length with `self` of exactly `prefixLen`. The
// `seedStart` lets callers produce DIFFERENT contacts on subsequent
// invocations -- two calls with the same seedStart would generate
// the same IDs and accidentally merge instead of populate.
func contactsForBucket(t *testing.T, self NodeID, prefixLen, count int, seedStart uint64) []Contact {
	t.Helper()
	out := make([]Contact, 0, count)
	seed := seedStart
	for len(out) < count {
		seed++
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], seed)
		id := NodeID(sha256.Sum256(buf[:]))
		if self.CommonPrefixLen(id) != prefixLen {
			continue
		}
		if id.Equal(self) {
			continue
		}
		out = append(out, Contact{
			ID:      id,
			Address: fmt.Sprintf("10.0.0.%d:9000", len(out)+1),
		})
		if seed-seedStart > 1_000_000 {
			t.Fatalf("couldn't find %d contacts for prefix %d", count, prefixLen)
		}
	}
	return out
}

// TestEvictionPingKeepsAliveHead: when the head of a full bucket is
// alive (ping returns true), a new candidate is dropped and the head
// is moved to the tail to refresh its position.
func TestEvictionPingKeepsAliveHead(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	// Find a bucket index that we can populate.
	const targetPrefix = 0
	contacts := contactsForBucket(t, self, targetPrefix, K, 0)
	for _, c := range contacts {
		rt.Update(c)
	}
	if rt.Size() != K {
		t.Fatalf("setup: expected K contacts in table, got %d", rt.Size())
	}

	// Install ping that always says head is alive.
	pinged := int32(0)
	rt.SetEvictionPing(func(c Contact) bool {
		atomic.AddInt32(&pinged, 1)
		return true
	})

	// Add one more candidate -- bucket is full, so eviction protocol fires.
	extra := contactsForBucket(t, self, targetPrefix, 1, 1_000_000)[0]
	rt.Update(extra)

	// Wait for the async ping decision.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&pinged) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let post-ping mutex acquire complete

	// Candidate should NOT be in the table.
	for _, c := range rt.All() {
		if c.ID.Equal(extra.ID) {
			t.Error("candidate should have been dropped because head was alive")
		}
	}
	if rt.Size() != K {
		t.Errorf("table size = %d, want K=%d", rt.Size(), K)
	}
}

// TestEvictionPingReplacesDeadHead: when the head's ping fails (head is
// dead), the head is evicted and the candidate takes its place.
func TestEvictionPingReplacesDeadHead(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	const targetPrefix = 0
	contacts := contactsForBucket(t, self, targetPrefix, K, 0)
	for _, c := range contacts {
		rt.Update(c)
	}
	headID := contacts[0].ID

	// Ping that always fails.
	rt.SetEvictionPing(func(c Contact) bool { return false })

	extra := contactsForBucket(t, self, targetPrefix, 1, 1_000_000)[0]
	rt.Update(extra)

	deadline := time.Now().Add(2 * time.Second)
	var hasExtra, hasHead bool
	for time.Now().Before(deadline) {
		hasExtra = false
		hasHead = false
		for _, c := range rt.All() {
			if c.ID.Equal(extra.ID) {
				hasExtra = true
			}
			if c.ID.Equal(headID) {
				hasHead = true
			}
		}
		if hasExtra && !hasHead {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasExtra {
		t.Error("candidate should have replaced the dead head")
	}
	if hasHead {
		t.Error("dead head should have been evicted")
	}
	if rt.Size() != K {
		t.Errorf("table size = %d, want K=%d (one in, one out)", rt.Size(), K)
	}
}

// TestHintInsertsAtHeadAsUntrusted: a Hinted contact (learned
// secondhand) goes in with stale LastSeen so it's the first thing
// head-of-bucket eviction probes when a new candidate arrives.
func TestHintInsertsAtHeadAsUntrusted(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	// Direct contact via Update.
	direct := contactsForBucket(t, self, 0, 1, 0)[0]
	rt.Update(direct)

	// Hinted contact afterward -- should land at the HEAD of the
	// bucket (older position) even though it arrived later in time.
	hinted := contactsForBucket(t, self, 0, 1, 1_000_000)[0]
	rt.Hint(hinted)

	contacts := rt.All()
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(contacts))
	}

	// Find the hinted entry; its LastSeen should be the zero value.
	var hintedEntry *Contact
	for i := range contacts {
		if contacts[i].ID.Equal(hinted.ID) {
			hintedEntry = &contacts[i]
		}
	}
	if hintedEntry == nil {
		t.Fatal("hinted contact missing from table")
	}
	if !hintedEntry.LastSeen.IsZero() {
		t.Errorf("hinted contact should have zero LastSeen, got %v", hintedEntry.LastSeen)
	}
}

// TestHintIsNoOpForExistingContact: a malicious peer sending us a
// hint for a contact we ALREADY directly verified shouldn't reset
// that contact's LastSeen (which would make us doubt a known-good
// peer for no reason).
func TestHintIsNoOpForExistingContact(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	c := contactsForBucket(t, self, 0, 1, 0)[0]
	rt.Update(c) // directly verified
	priorLastSeen := rt.All()[0].LastSeen
	if priorLastSeen.IsZero() {
		t.Fatal("Update should set LastSeen to non-zero")
	}

	// Now someone hints the same contact. Should NOT touch our entry.
	rt.Hint(c)

	got := rt.All()[0]
	if !got.LastSeen.Equal(priorLastSeen) {
		t.Errorf("Hint mutated LastSeen of an existing entry: was %v, now %v",
			priorLastSeen, got.LastSeen)
	}
}

// TestHintRefusesToEvictTrustedContacts: when the bucket is full,
// Hint must NOT replace anyone -- a malicious peer flooding us with
// hints should not be able to push out direct-contact entries.
func TestHintRefusesToEvictTrustedContacts(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	contacts := contactsForBucket(t, self, 0, K, 0)
	for _, c := range contacts {
		rt.Update(c) // bucket full, all directly verified
	}
	if rt.Size() != K {
		t.Fatalf("setup: bucket should be full, got %d", rt.Size())
	}

	// Try to inject K hints. None should land.
	hints := contactsForBucket(t, self, 0, K, 1_000_000)
	for _, h := range hints {
		rt.Hint(h)
	}

	if rt.Size() != K {
		t.Errorf("Hint flood pushed out trusted contacts: size = %d", rt.Size())
	}
	// And none of the hinted IDs should appear.
	for _, h := range hints {
		for _, c := range rt.All() {
			if c.ID.Equal(h.ID) {
				t.Errorf("hint %s evicted a direct contact", h.ID.Hex()[:8])
			}
		}
	}
}

// TestNoEvictionWithoutPingCallback: with no ping callback installed
// (the legacy/default behaviour), a full-bucket Update silently drops
// the candidate and leaves the bucket alone.
func TestNoEvictionWithoutPingCallback(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)
	const targetPrefix = 0
	contacts := contactsForBucket(t, self, targetPrefix, K, 0)
	for _, c := range contacts {
		rt.Update(c)
	}

	extra := contactsForBucket(t, self, targetPrefix, 1, 1_000_000)[0]
	rt.Update(extra)
	time.Sleep(50 * time.Millisecond)

	for _, c := range rt.All() {
		if c.ID.Equal(extra.ID) {
			t.Error("candidate should have been dropped silently")
		}
	}
	if rt.Size() != K {
		t.Errorf("table size = %d, want K=%d", rt.Size(), K)
	}
}
