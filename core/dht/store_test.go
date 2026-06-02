package dht

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalStorePutGet(t *testing.T) {
	s := newLocalStore()
	key := ContentAddress([]byte("hi"))
	if _, ok := s.Get(key); ok {
		t.Fatal("empty store should not have key")
	}
	s.Put(key, []byte("world"))
	v, ok := s.Get(key)
	if !ok || string(v) != "world" {
		t.Errorf("Get returned %q, ok=%v", v, ok)
	}
}

func TestLocalStoreReturnsCopy(t *testing.T) {
	// Mutating the slice returned by Get must not change the stored value.
	s := newLocalStore()
	key := ContentAddress([]byte("k"))
	s.Put(key, []byte("original"))
	v, _ := s.Get(key)
	v[0] = 'X'
	v2, _ := s.Get(key)
	if string(v2) != "original" {
		t.Errorf("store value mutated through returned slice: got %q", v2)
	}
}

func TestContentAddressIsDeterministic(t *testing.T) {
	a := ContentAddress([]byte("hello world"))
	b := ContentAddress([]byte("hello world"))
	if !a.Equal(b) {
		t.Error("ContentAddress should be deterministic")
	}
	c := ContentAddress([]byte("hello world!"))
	if a.Equal(c) {
		t.Error("different content should hash to different keys")
	}
}

// TestStoreAndGetAcrossNetwork is the milestone test for content-addressable
// storage: peer B stores a value into the DHT, and peer C -- which never
// directly stored it -- retrieves it through peer A.
func TestStoreAndGetAcrossNetwork(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("B bootstrap: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("C bootstrap: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	value := []byte("the network remembers")
	key := ContentAddress(value)

	stores, err := db.Store(key, value)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if stores == 0 {
		t.Fatal("Store should have replicated to at least one remote peer")
	}

	got, err := dc.Get(key)
	if err != nil {
		t.Fatalf("C.Get: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("C.Get returned %q, want %q", got, value)
	}
}

// TestGetUnknownKeyReturnsError checks that Get fails cleanly when nobody
// in the network knows the value.
func TestGetUnknownKeyReturnsError(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	missing := ContentAddress([]byte("never stored"))
	_, err := db.Get(missing)
	if err == nil {
		t.Fatal("Get should return error for unknown key")
	}
}

// TestStoreRejectsOversizedValue confirms the size cap is enforced.
func TestStoreRejectsOversizedValue(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	huge := make([]byte, MaxValueSize+1)
	key := ContentAddress(huge)
	_, err := da.Store(key, huge)
	if err == nil {
		t.Fatal("Store should reject values larger than MaxValueSize")
	}
}

// TestGetUsesLocalStoreFirst verifies that a Put-then-Get on the same node
// doesn't even hit the network.
func TestGetUsesLocalStoreFirst(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	value := []byte("local-only")
	key := ContentAddress(value)
	if _, err := da.Store(key, value); err != nil {
		t.Fatal(err)
	}
	got, err := da.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("got %q, want %q", got, value)
	}
}

// TestGetRejectsTamperedValue is the security milestone for
// content-addressable storage: a peer that returns a value that does not
// hash to the requested key must be ignored, not trusted.
//
// We simulate a malicious peer A by directly planting (key, fakeValue)
// in A's local store. B then asks the network for the value at key.
// Since A is the only peer holding anything for that key, A serves the
// fake value. B must reject it because hash(fakeValue) != key, and Get
// must return ErrNotFound rather than handing the caller bad data.
func TestGetRejectsTamperedValue(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	realValue := []byte("the truth")
	realKey := ContentAddress(realValue)
	fakeValue := []byte("a lie")

	// Plant a value that does NOT match the key on peer A.
	da.store.Put(realKey, fakeValue)

	got, err := db.Get(realKey)
	if err == nil {
		t.Fatalf("Get should have rejected tampered value, got %q", got)
	}
	if got != nil {
		t.Fatalf("Get returned %q despite error %v", got, err)
	}
}

// TestGetUnverifiedAcceptsAnyValue documents the escape hatch for
// non-content-addressed keys. We plant data on A under a key that is
// NOT its hash; verified Get rejects it, GetUnverified accepts it.
func TestGetUnverifiedAcceptsAnyValue(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	value := []byte("DNS-style record")
	// Use a key derived from a NAME, not from the value.
	key := ContentAddress([]byte("alice.alt"))
	da.store.Put(key, value)

	if _, err := db.Get(key); err == nil {
		t.Fatal("verified Get should reject non-content-addressed value")
	}

	got, err := db.GetUnverified(key)
	if err != nil {
		t.Fatalf("GetUnverified: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("got %q, want %q", got, value)
	}
}

// TestDiskStoreRoundTrip verifies that Put writes to disk and a fresh
// store loads what was written.
func TestDiskStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := newLocalStoreWithDir(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	value := []byte("survives restarts")
	key := ContentAddress(value)
	s.Put(key, value)

	// Open a NEW store at the same path; it should find the value.
	s2, err := newLocalStoreWithDir(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	got, ok := s2.Get(key)
	if !ok {
		t.Fatal("reopened store should contain previously-put key")
	}
	if !bytes.Equal(got, value) {
		t.Errorf("got %q, want %q", got, value)
	}
	if s2.Size() != 1 {
		t.Errorf("Size = %d, want 1", s2.Size())
	}
}

// TestDiskStoreSkipsTempFiles makes sure half-written files (.tmp) don't
// get mistakenly loaded as real entries on startup.
func TestDiskStoreSkipsTempFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := newLocalStoreWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Plant a stray .tmp file in the store directory.
	tmpPath := filepath.Join(dir, "store", "abcd.tmp")
	if err := os.WriteFile(tmpPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	// And a non-hex file (random other thing in the dir).
	if err := os.WriteFile(filepath.Join(dir, "store", "not-a-key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Real entry.
	value := []byte("real data")
	key := ContentAddress(value)
	s.Put(key, value)

	// Reopen.
	s2, err := newLocalStoreWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Size() != 1 {
		t.Errorf("Size = %d, want 1 (tmp/junk should be skipped)", s2.Size())
	}
}

// TestDiskStoreAtomicWrite verifies that a Put writes via .tmp + rename so
// readers can never see a partially-written file.
func TestDiskStoreAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := newLocalStoreWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("hello atomic")
	key := ContentAddress(value)
	s.Put(key, value)

	// After Put completes, exactly one file should exist with the key
	// name; no .tmp leftovers.
	entries, err := os.ReadDir(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("found leftover tmp file: %s", e.Name())
		}
	}
}

// TestStoreEvictsLRUWhenOverBudget is the headline test for the
// capacity manager: when adding a new value would overflow the budget,
// the least-recently-accessed entries get evicted first, and frequently
// accessed entries stay.
func TestStoreEvictsLRUWhenOverBudget(t *testing.T) {
	dir := t.TempDir()
	// Budget = 30 bytes total. Each value below is 10 bytes.
	s, err := newLocalStoreWithLimit(dir, 30)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	v1 := bytes.Repeat([]byte("a"), 10)
	v2 := bytes.Repeat([]byte("b"), 10)
	v3 := bytes.Repeat([]byte("c"), 10)
	k1 := ContentAddress(v1)
	k2 := ContentAddress(v2)
	k3 := ContentAddress(v3)

	s.Put(k1, v1)
	// Sleep slightly so timestamps differ; we don't sub-millisecond
	// granularity on every OS.
	time.Sleep(5 * time.Millisecond)
	s.Put(k2, v2)
	time.Sleep(5 * time.Millisecond)

	// Touch k1 so it's NOT the LRU.
	if _, ok := s.Get(k1); !ok {
		t.Fatal("k1 should be present")
	}
	time.Sleep(5 * time.Millisecond)

	// Now add k3. Budget is full (20/30). k3 fits without eviction.
	s.Put(k3, v3)

	// Add a fourth value. Now we're at 30 bytes; adding 10 more should
	// evict ONE entry. The LRU at this point is k2 (oldest untouched).
	v4 := bytes.Repeat([]byte("d"), 10)
	k4 := ContentAddress(v4)
	s.Put(k4, v4)

	if _, ok := s.Get(k2); ok {
		t.Error("k2 should have been evicted (it was the LRU)")
	}
	if _, ok := s.Get(k1); !ok {
		t.Error("k1 should still be present (it was touched)")
	}
	if _, ok := s.Get(k3); !ok {
		t.Error("k3 should still be present")
	}
	if _, ok := s.Get(k4); !ok {
		t.Error("k4 should be present (it was just added)")
	}
	if total := s.TotalBytes(); total > 30 {
		t.Errorf("TotalBytes = %d, should be <= 30", total)
	}
}

// TestStoreEvictionRemovesFromDisk verifies that evicted entries are
// also removed from the on-disk directory, so the disk doesn't fill up
// with orphaned files.
func TestStoreEvictionRemovesFromDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := newLocalStoreWithLimit(dir, 15)
	if err != nil {
		t.Fatal(err)
	}
	v1 := bytes.Repeat([]byte("a"), 10)
	v2 := bytes.Repeat([]byte("b"), 10)
	k1 := ContentAddress(v1)
	k2 := ContentAddress(v2)

	s.Put(k1, v1)
	s.Put(k2, v2) // budget is 15, so this evicts k1

	// k1's file should be gone from disk.
	storeDir := filepath.Join(dir, "store")
	if _, err := os.Stat(filepath.Join(storeDir, k1.Hex())); !os.IsNotExist(err) {
		t.Errorf("k1 disk file should be gone, stat err = %v", err)
	}
	// k2's file should be present.
	if _, err := os.Stat(filepath.Join(storeDir, k2.Hex())); err != nil {
		t.Errorf("k2 disk file should exist: %v", err)
	}
}

// TestStoreUnlimitedBudgetByDefault: with maxBytes=0, no eviction
// should ever happen, even with many entries.
func TestStoreUnlimitedBudgetByDefault(t *testing.T) {
	s, err := newLocalStoreWithLimit("", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		v := []byte{byte(i)}
		k := ContentAddress(v)
		s.Put(k, v)
	}
	if s.Size() != 50 {
		t.Errorf("expected 50 entries, got %d", s.Size())
	}
}

// TestPerPeerQuotaRejectsExcessFromOnePeer is the spam-defense
// milestone: one malicious peer can't fill our store. After they hit
// their per-peer cap, further STOREs from them are rejected even
// though our overall budget would still accept the bytes.
func TestPerPeerQuotaRejectsExcessFromOnePeer(t *testing.T) {
	s := newLocalStore()
	s.SetPerPeerMax(30)

	attacker := "evil-peer-id"
	v1 := bytes.Repeat([]byte("x"), 10)
	v2 := bytes.Repeat([]byte("y"), 10)
	v3 := bytes.Repeat([]byte("z"), 10)
	v4 := bytes.Repeat([]byte("a"), 10)

	if !s.PutAttributed(ContentAddress(v1), v1, attacker) {
		t.Fatal("first PutAttributed should be accepted (10/30)")
	}
	if !s.PutAttributed(ContentAddress(v2), v2, attacker) {
		t.Fatal("second PutAttributed should be accepted (20/30)")
	}
	if !s.PutAttributed(ContentAddress(v3), v3, attacker) {
		t.Fatal("third PutAttributed should be accepted (30/30 -- equals cap)")
	}
	// Fourth would push us to 40/30. Reject.
	if s.PutAttributed(ContentAddress(v4), v4, attacker) {
		t.Error("fourth PutAttributed should have been rejected (40 > 30 cap)")
	}

	if usage := s.PerPeerUsage(attacker); usage != 30 {
		t.Errorf("PerPeerUsage = %d, want 30", usage)
	}
}

// TestPerPeerQuotaIsolatesPeers verifies the cap is per-peer, not
// shared. Peer A maxing out their quota doesn't block peer B from
// using their own.
func TestPerPeerQuotaIsolatesPeers(t *testing.T) {
	s := newLocalStore()
	s.SetPerPeerMax(20)

	a := "peer-a"
	b := "peer-b"
	v1 := bytes.Repeat([]byte("a"), 20)
	v2 := bytes.Repeat([]byte("b"), 20)

	if !s.PutAttributed(ContentAddress(v1), v1, a) {
		t.Fatal("a's first store should be accepted")
	}
	v1b := bytes.Repeat([]byte("c"), 1)
	if s.PutAttributed(ContentAddress(v1b), v1b, a) {
		t.Error("a should be over cap, store should reject")
	}
	if !s.PutAttributed(ContentAddress(v2), v2, b) {
		t.Error("b should be unaffected by a's cap")
	}
}

// TestPerPeerQuotaUsageDecrementsOnEviction: when an LRU eviction
// removes a peer's entry, that peer's usage counter must decrement
// so they don't permanently lose budget for evicted bytes.
func TestPerPeerQuotaUsageDecrementsOnEviction(t *testing.T) {
	dir := t.TempDir()
	s, err := newLocalStoreWithLimit(dir, 30)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPerPeerMax(100)

	attacker := "p"
	v1 := bytes.Repeat([]byte("a"), 10)
	v2 := bytes.Repeat([]byte("b"), 10)
	v3 := bytes.Repeat([]byte("c"), 10)
	v4 := bytes.Repeat([]byte("d"), 10)

	s.PutAttributed(ContentAddress(v1), v1, attacker)
	time.Sleep(2 * time.Millisecond)
	s.PutAttributed(ContentAddress(v2), v2, attacker)
	time.Sleep(2 * time.Millisecond)
	s.PutAttributed(ContentAddress(v3), v3, attacker)
	if usage := s.PerPeerUsage(attacker); usage != 30 {
		t.Fatalf("usage before eviction = %d, want 30", usage)
	}

	s.PutAttributed(ContentAddress(v4), v4, attacker)
	if usage := s.PerPeerUsage(attacker); usage != 30 {
		t.Errorf("usage after eviction = %d, want 30 (eviction must refund)", usage)
	}
}

// TestPerPeerQuotaIgnoresLocalStores: local Put (no peerID) should
// never count against any peer's quota.
func TestPerPeerQuotaIgnoresLocalStores(t *testing.T) {
	s := newLocalStore()
	s.SetPerPeerMax(10)

	v := bytes.Repeat([]byte("x"), 100)
	s.Put(ContentAddress(v), v)
	got, ok := s.Get(ContentAddress(v))
	if !ok || len(got) != 100 {
		t.Errorf("local Put should always succeed regardless of per-peer cap")
	}
}

// TestLargeValueBelowCap verifies that values close to (but under) the cap
// round-trip across the network correctly.
func TestLargeValueBelowCap(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// 32 KiB of repeating content (well under MaxValueSize).
	value := []byte(strings.Repeat("abcd", 32*1024/4))
	key := ContentAddress(value)

	if _, err := db.Store(key, value); err != nil {
		t.Fatal(err)
	}
	got, err := dc.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("value mismatch: got %d bytes, want %d", len(got), len(value))
	}
}
