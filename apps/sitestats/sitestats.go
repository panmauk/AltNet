// Package sitestats keeps per-site request counters for the gateway.
//
// Two consumers: the gateway (writer) records each request with the
// resolved name + remote IP + bytes served; the registrar (reader)
// exposes the running totals over its HTTP API so the desktop app can
// render a dashboard.
//
// We deliberately avoid a time-series store for v0 — running totals
// since boot, plus "last seen", plus the count of distinct IPs seen
// is enough for a useful site card. If we want last-24h-only or
// charts later, swap the inner storage for a ring of buckets.
package sitestats

import (
	"sync"
	"time"
)

// Snapshot is the JSON-friendly view of a single site's stats. Returned
// by Get/All.
type Snapshot struct {
	Name         string `json:"name"`
	Requests     int64  `json:"requests"`
	Bytes        int64  `json:"bytes"`
	UniqueIPs    int    `json:"unique_ips"`
	LastSeenUnix int64  `json:"last_seen_unix,omitempty"`
}

// SiteCounter accumulates the running totals for one .alt name. Methods
// on Stats are the only safe mutator path.
type SiteCounter struct {
	requests int64
	bytes    int64
	lastSeen int64
	ips      map[string]struct{}
}

// Stats is the shared registry. Safe for concurrent use; the gateway
// hits Record from many goroutines, the registrar hits Get / All.
//
// Implements both Recorder (gateway-facing) and Reader (registrar-facing)
// so we can pass narrow interfaces to each consumer instead of the
// concrete type.
type Stats struct {
	mu sync.Mutex

	// We bound the unique-IP set per site so a viral page can't blow
	// memory. Exact count up to maxIPs; an "approximate" flag would
	// be a future enhancement once we hit it.
	maxIPsPerSite int

	sites map[string]*SiteCounter
}

// New returns a Stats with sensible bounds.
func New() *Stats {
	return &Stats{
		maxIPsPerSite: 10_000,
		sites:         make(map[string]*SiteCounter),
	}
}

// --- Recorder interface (gateway-facing) ---

// Recorder is what the gateway needs: just record events.
type Recorder interface {
	Record(name, remoteIP string, bytesServed int64)
}

// Record bumps the counters for name. Safe to call with empty name
// (it's a no-op) so the gateway can call unconditionally.
func (s *Stats) Record(name, remoteIP string, bytesServed int64) {
	if name == "" {
		return
	}
	now := time.Now().Unix()
	s.mu.Lock()
	c, ok := s.sites[name]
	if !ok {
		c = &SiteCounter{ips: make(map[string]struct{})}
		s.sites[name] = c
	}
	c.requests++
	c.bytes += bytesServed
	c.lastSeen = now
	if remoteIP != "" && len(c.ips) < s.maxIPsPerSite {
		c.ips[remoteIP] = struct{}{}
	}
	s.mu.Unlock()
}

// --- Reader interface (registrar-facing) ---

// Reader is what the registrar needs: read snapshots out.
type Reader interface {
	Get(name string) Snapshot
	All() []Snapshot
}

// Get returns the snapshot for name. If we've never seen the name, the
// returned Snapshot is zero-valued (Requests==0). This intentionally
// doesn't distinguish "registered but unvisited" from "unknown" — the
// caller already knows the name is registered, that's why it's asking.
func (s *Stats) Get(name string) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.sites[name]
	if c == nil {
		return Snapshot{Name: name}
	}
	return Snapshot{
		Name:         name,
		Requests:     c.requests,
		Bytes:        c.bytes,
		UniqueIPs:    len(c.ips),
		LastSeenUnix: c.lastSeen,
	}
}

// All returns snapshots for every site that's been recorded against.
func (s *Stats) All() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Snapshot, 0, len(s.sites))
	for name, c := range s.sites {
		out = append(out, Snapshot{
			Name:         name,
			Requests:     c.requests,
			Bytes:        c.bytes,
			UniqueIPs:    len(c.ips),
			LastSeenUnix: c.lastSeen,
		})
	}
	return out
}

// Forget removes a site's counters. Used when the user takes a site
// down so its old numbers don't keep showing in the UI.
func (s *Stats) Forget(name string) {
	s.mu.Lock()
	delete(s.sites, name)
	s.mu.Unlock()
}
