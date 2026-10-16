package dht

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// Blocklist is a set of chunk hashes (SHA-256, as 64-char hex) that the
// local store will refuse to accept (via PutAttributed) and refuse to
// return (via Get / GetUnverified). Used to keep known-bad content
// (notably CSAM) off the network at each node's storage layer.
//
// The exact-hash design is intentionally simple. It catches identical
// bytes. It does NOT catch perceptual variants (re-encoded JPEGs, etc.)
// — that needs PhotoDNA or similar perceptual-hash matching, which is
// a future addition. Even so, an exact-hash blocklist is the floor of
// what a content-hosting operator needs to claim good-faith moderation.
//
// Concurrency: safe for concurrent reads after construction. Use
// LoadBlocklistFromFile or NewBlocklist to build; the resulting *Blocklist
// is read-only for the lifetime of the daemon process.
type Blocklist struct {
	mu     sync.RWMutex
	hashes map[string]struct{} // key.Hex() -> present
}

// NewBlocklist returns an empty Blocklist. The zero value is also usable
// (every Contains returns false) — this constructor exists so callers
// can be explicit about creating one.
func NewBlocklist() *Blocklist {
	return &Blocklist{hashes: make(map[string]struct{})}
}

// LoadBlocklistFromFile parses one SHA-256 hex hash per line from path.
// Blank lines and lines starting with "#" are ignored. Invalid hashes
// are silently dropped (operator typo shouldn't crash the daemon).
//
// If the file doesn't exist, returns an empty blocklist and nil error —
// "no blocklist configured" is a normal operating state.
func LoadBlocklistFromFile(path string) (*Blocklist, error) {
	bl := NewBlocklist()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return bl, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comments e.g. "abc123...  # a known-bad image"
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Validate: must parse as a NodeID (64 lowercase hex chars).
		if _, err := IDFromHex(strings.ToLower(line)); err != nil {
			continue
		}
		bl.hashes[strings.ToLower(line)] = struct{}{}
	}
	return bl, sc.Err()
}

// Contains reports whether key is on the blocklist. Cheap; safe for
// hot-path use (every Store and Get checks this).
func (b *Blocklist) Contains(key NodeID) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.hashes[key.Hex()]
	return ok
}

// Size returns the number of blocked hashes. Useful for metrics.
func (b *Blocklist) Size() int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hashes)
}

// Add inserts a hex hash into the blocklist at runtime. Used by the
// revocation handler (when a signed revoke record arrives, the listed
// hashes get blocked from future re-acceptance). Returns true if the
// hash was newly added.
func (b *Blocklist) Add(key NodeID) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	hex := key.Hex()
	if _, ok := b.hashes[hex]; ok {
		return false
	}
	if b.hashes == nil {
		b.hashes = make(map[string]struct{})
	}
	b.hashes[hex] = struct{}{}
	return true
}
