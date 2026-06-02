package dht

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MaxValueSize caps the size of any single value the DHT will accept,
// to keep individual messages well under MaxMessageSize on the wire.
// 64 KiB is a starting point; can be raised after we add chunking.
const MaxValueSize = 64 * 1024

// DefaultStoreBudgetBytes is the default total disk budget if none is
// specified -- 1 GiB. Plenty for a single peer; small enough to not
// surprise a user who runs the daemon casually.
const DefaultStoreBudgetBytes = 1 << 30

// DefaultPerPeerBudgetBytes caps how much a single remote peer can
// have stored at us via dht_store messages. A malicious peer cannot
// exceed this even if our overall budget is much larger, so spam from
// one bad actor cannot push out everyone else's content. 64 MiB is a
// reasonable default; an active publisher pushing a large site
// distributes its content across many peers, not piling onto one.
const DefaultPerPeerBudgetBytes = 64 << 20

// ContentAddress returns the SHA-256 of value as a NodeID. This is the
// natural key for content-addressable storage: "the key for a piece of
// data is just its hash." The peer storing it can prove the data hasn't
// been tampered with by re-hashing on retrieval.
func ContentAddress(value []byte) NodeID {
	h := sha256.Sum256(value)
	var id NodeID
	copy(id[:], h[:])
	return id
}

// localStore is a per-peer key-value store backed by an in-memory map
// for fast reads, optionally mirrored to disk so values survive process
// restarts.
//
// A peer keeps the values that have been stored at it (because, in DHT
// terms, it was one of the K nodes "closest" to the key when someone
// called STORE) plus values it has fetched from the network (cache —
// "visitors become nodes").
//
// Disk layout (when persistence is enabled):
//
//	<dataDir>/store/
//	  9c1f...ab/   <- 64-char hex of the key
//
// Each file is the raw value bytes. Writes are atomic via temp-file +
// rename so a crash mid-write cannot corrupt an existing entry.
//
// Capacity is bounded by maxBytes (0 = unlimited). When the budget
// would be exceeded by a Put, the least-recently-accessed entries are
// evicted until there's room. This keeps long-running nodes from
// filling their disk while still preserving the values that are
// actively used by the network.
type localStore struct {
	mu       sync.RWMutex
	data     map[string][]byte    // key.Hex() -> value
	access   map[string]time.Time // key.Hex() -> last accessed
	total    int64                // current total bytes
	maxBytes int64                // 0 = unlimited
	dataDir  string               // empty = in-memory only

	// Per-peer attribution: which remote peer originally STORE'd each
	// key, and how many bytes that peer has currently stored at us.
	// Used to enforce perPeerMax so a single malicious peer can't fill
	// our store with garbage. attribution[k] == "" means the value was
	// stored by us (cache, republish, our own publish), not enforced.
	attribution map[string]string // key.Hex() -> peer-id who STORE'd it
	perPeer     map[string]int64  // peer-id -> bytes currently attributed
	perPeerMax  int64             // 0 = unlimited
}

// newLocalStore creates an in-memory-only, unbounded store. Used by
// tests and as the default when no data directory is configured.
func newLocalStore() *localStore {
	return &localStore{
		data:        make(map[string][]byte),
		access:      make(map[string]time.Time),
		attribution: make(map[string]string),
		perPeer:     make(map[string]int64),
	}
}

// newLocalStoreWithDir creates a store backed by disk at dir with no
// size cap.
func newLocalStoreWithDir(dir string) (*localStore, error) {
	return newLocalStoreWithLimit(dir, 0)
}

// newLocalStoreWithLimit creates a store backed by disk at dir with a
// total-bytes budget. maxBytes=0 means unlimited.
//
// If dir already contains store files from a previous run they are
// loaded into the in-memory cache, with each file's mtime used as the
// initial last-accessed time. If the loaded set already exceeds
// maxBytes, the oldest entries are evicted on startup.
func newLocalStoreWithLimit(dir string, maxBytes int64) (*localStore, error) {
	s := &localStore{
		data:        make(map[string][]byte),
		access:      make(map[string]time.Time),
		attribution: make(map[string]string),
		perPeer:     make(map[string]int64),
		maxBytes:    maxBytes,
	}
	if dir == "" {
		return s, nil
	}
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}
	s.dataDir = storeDir
	if err := s.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("load store from disk: %w", err)
	}
	// Trim down to budget if the on-disk set was already over.
	s.evictUntilUnder(s.maxBytes)
	return s, nil
}

// loadFromDisk walks the store directory and populates the cache. Files
// whose names aren't valid hex IDs are skipped (they aren't ours).
func (s *localStore) loadFromDisk() error {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		hexName := entry.Name()
		if filepath.Ext(hexName) == ".tmp" {
			continue
		}
		if _, err := IDFromHex(hexName); err != nil {
			continue
		}
		path := filepath.Join(s.dataDir, hexName)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) > MaxValueSize {
			continue
		}
		s.data[hexName] = data
		s.total += int64(len(data))
		// Use file mtime as the initial last-accessed time so old files
		// get evicted first when we're over budget.
		info, err := entry.Info()
		if err == nil {
			s.access[hexName] = info.ModTime()
		} else {
			s.access[hexName] = time.Now()
		}
	}
	return nil
}

// Put records value under key as a self-store (no peer attribution,
// no per-peer quota check). Used for our own publishes, cached fetches,
// and anything else originating locally.
func (s *localStore) Put(key NodeID, value []byte) {
	_ = s.put(key, value, "")
}

// PutAttributed records value under key, attributing the bytes to
// peerID for per-peer quota accounting. Returns true if accepted,
// false if the peer has hit its perPeerMax. peerID="" is equivalent
// to Put (no attribution, always accepted modulo total budget).
func (s *localStore) PutAttributed(key NodeID, value []byte, peerID string) bool {
	return s.put(key, value, peerID)
}

func (s *localStore) put(key NodeID, value []byte, peerID string) bool {
	cp := make([]byte, len(value))
	copy(cp, value)
	hex := key.Hex()
	now := time.Now()
	size := int64(len(cp))

	s.mu.Lock()
	// Per-peer admission check: a remote peer can only have perPeerMax
	// bytes attributed to them at any time. We compute usage AFTER
	// accounting for refunding any prior entry attributed to the same
	// peer at this key (overwrite is fine; they're not adding bytes).
	if peerID != "" && s.perPeerMax > 0 {
		current := s.perPeer[peerID]
		if oldAttr, ok := s.attribution[hex]; ok && oldAttr == peerID {
			if old, ok := s.data[hex]; ok {
				current -= int64(len(old))
			}
		}
		if current+size > s.perPeerMax {
			s.mu.Unlock()
			return false
		}
	}

	// If overwriting an existing entry, refund its size and prior
	// attribution accounting.
	if old, ok := s.data[hex]; ok {
		s.total -= int64(len(old))
		if oldAttr, ok := s.attribution[hex]; ok && oldAttr != "" {
			s.perPeer[oldAttr] -= int64(len(old))
			if s.perPeer[oldAttr] <= 0 {
				delete(s.perPeer, oldAttr)
			}
		}
	}

	// Make room.
	s.evictToFit(size)
	s.data[hex] = cp
	s.access[hex] = now
	s.total += size
	if peerID != "" {
		s.attribution[hex] = peerID
		s.perPeer[peerID] += size
	} else {
		// Local stores override any prior remote attribution -- this
		// happens e.g. when we cache a fetched value that some peer
		// originally STORE'd into us.
		delete(s.attribution, hex)
	}
	dir := s.dataDir
	s.mu.Unlock()

	if dir != "" {
		if err := writeAtomic(filepath.Join(dir, hex), cp); err != nil {
			slog.Warn("dht: failed to persist value to disk",
				"subsystem", "dht.store",
				"key_prefix", hex[:16],
				"err", err)
		}
	}
	return true
}

// SetPerPeerMax configures the per-peer storage cap (0 = unlimited).
// Each remote peer is allowed up to maxBytes attributed to them in our
// store. Above the cap, further STOREs from that peer are rejected.
//
// This is the per-peer half of the disk-defense story; the other half
// is the total maxBytes budget that applies regardless of source.
func (s *localStore) SetPerPeerMax(max int64) {
	s.mu.Lock()
	s.perPeerMax = max
	s.mu.Unlock()
}

// PerPeerUsage returns the bytes currently attributed to peerID.
// Useful for tests and metrics.
func (s *localStore) PerPeerUsage(peerID string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.perPeer[peerID]
}

// Delete removes a key from the store unconditionally. Used by the
// revoke handler to purge revoked chunks from local cache + disk. No-
// op if the key isn't present. Releases per-peer attribution if the
// chunk had been STORE'd by a remote.
func (s *localStore) Delete(key NodeID) {
	hex := key.Hex()
	s.mu.Lock()
	v, ok := s.data[hex]
	if !ok {
		s.mu.Unlock()
		return
	}
	size := int64(len(v))
	s.total -= size
	delete(s.data, hex)
	delete(s.access, hex)
	if attr, ok := s.attribution[hex]; ok && attr != "" {
		s.perPeer[attr] -= size
		if s.perPeer[attr] <= 0 {
			delete(s.perPeer, attr)
		}
	}
	delete(s.attribution, hex)
	dir := s.dataDir
	s.mu.Unlock()
	if dir != "" {
		_ = os.Remove(filepath.Join(dir, hex))
	}
}

// Get returns a copy of the stored value, or (nil, false) if absent.
// Refreshes the entry's last-accessed time, so frequently-used values
// aren't evicted under disk pressure.
func (s *localStore) Get(key NodeID) ([]byte, bool) {
	hex := key.Hex()
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[hex]
	if !ok {
		return nil, false
	}
	s.access[hex] = time.Now()
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true
}

// Size returns the number of (key,value) pairs currently held.
func (s *localStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// TotalBytes returns the in-cache byte total. Useful for tests/metrics.
func (s *localStore) TotalBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}

// evictToFit removes the LRU entries until total + needed <= maxBytes.
// Caller must hold s.mu (write lock).
//
// If the new value alone exceeds maxBytes there's nothing we can do —
// the Put will succeed but the store will exceed budget by that one
// entry. (The alternative — refusing the Put — would silently break
// callers that don't check the error path. We accept temporary
// overshoot.)
func (s *localStore) evictToFit(needed int64) {
	if s.maxBytes <= 0 {
		return // unlimited
	}
	target := s.maxBytes - needed
	if target < 0 {
		// Single value bigger than budget: clear out everything else but
		// don't reject the new entry.
		target = 0
	}
	s.evictUntilUnder(target)
}

// evictUntilUnder removes LRU entries until s.total <= cap. Caller
// must hold s.mu (write lock).
func (s *localStore) evictUntilUnder(cap int64) {
	if cap <= 0 && s.maxBytes <= 0 {
		return // unlimited
	}
	if s.total <= cap {
		return
	}
	// Build a list of (key, lastAccessed), sort by access ascending,
	// remove from the front until we're under.
	type entry struct {
		hex  string
		when time.Time
	}
	entries := make([]entry, 0, len(s.data))
	for k := range s.data {
		entries = append(entries, entry{k, s.access[k]})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].when.Before(entries[j].when)
	})
	for _, e := range entries {
		if s.total <= cap {
			break
		}
		if v, ok := s.data[e.hex]; ok {
			size := int64(len(v))
			s.total -= size
			delete(s.data, e.hex)
			delete(s.access, e.hex)
			if attr, ok := s.attribution[e.hex]; ok && attr != "" {
				s.perPeer[attr] -= size
				if s.perPeer[attr] <= 0 {
					delete(s.perPeer, attr)
				}
			}
			delete(s.attribution, e.hex)
			if s.dataDir != "" {
				_ = os.Remove(filepath.Join(s.dataDir, e.hex))
			}
		}
	}
}

// writeAtomic writes data to path atomically: write to <path>.tmp, fsync,
// then rename. If the rename succeeds, readers see either the old data
// or the new data — never a half-written file.
func writeAtomic(path string, data []byte) error {
	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
