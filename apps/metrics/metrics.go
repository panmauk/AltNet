// Package metrics serves runtime counters over HTTP so the AltNet
// desktop app (or any operator tool) can display node health.
//
// Endpoints:
//
//	GET /metrics      JSON snapshot of every counter
//	GET /healthz      simple liveness probe ("ok\n")
//
// Pull-based (the caller polls), not push-based, because the AltNet
// app sits next to the daemon on localhost and can poll cheaply. We
// don't try to be Prometheus-compatible -- the JSON shape is meant to
// be ergonomic to render in a UI, not to feed time-series databases.
package metrics

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"altnet/core/dht"
	"altnet/core/peer"
)

// Snapshot is the JSON payload returned by GET /metrics.
type Snapshot struct {
	// Identity
	PeerID  string `json:"peer_id"`
	ShortID string `json:"short_id"`

	// Reachability
	ListenAddress      string   `json:"listen_address"`
	AdvertisedAddrs    []string `json:"advertised_addresses"`
	IsPublic           bool     `json:"is_public"`
	RelayRegistrations []string `json:"relay_registrations"`

	// Connectivity
	ConnectedPeers int `json:"connected_peers"`
	UniqueConns    int `json:"unique_conns"`

	// DHT
	RoutingTableSize int   `json:"routing_table_size"`
	StoreEntries     int   `json:"store_entries"`
	StoreBytes       int64 `json:"store_bytes"`
	StoreBudget      int64 `json:"store_budget"`

	// Process
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	UptimeSec    int64  `json:"uptime_sec"`
}

// Server exposes a Snapshot over HTTP.
type Server struct {
	p     *peer.Peer
	d     *dht.DHT
	start time.Time
}

// New creates a metrics Server.
func New(p *peer.Peer, d *dht.DHT) *Server {
	return &Server{p: p, d: d, start: time.Now()}
}

// Start begins listening on addr. Returns the http.Server so the
// caller can shut it down.
func (s *Server) Start(addr string) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv, nil
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

// Snapshot collects the current counters. Exposed (not just used by
// the HTTP handler) so tests and an in-process AltNet app can grab
// the same view without going through localhost.
func (s *Server) Snapshot() Snapshot { return s.snapshot() }

func (s *Server) snapshot() Snapshot {
	var rtSize int
	var storeEntries int
	var storeBytes int64
	if s.d != nil {
		rtSize = s.d.RoutingTable().Size()
		storeEntries = s.d.LocalStoreSize()
		storeBytes = s.d.LocalStoreBytes()
	}
	return Snapshot{
		PeerID:             s.p.Identity.ID(),
		ShortID:            s.p.Identity.ShortID(),
		ListenAddress:      s.p.LocalAddr(),
		AdvertisedAddrs:    s.p.AdvertisedAddresses(),
		IsPublic:           s.p.IsPublic(),
		RelayRegistrations: s.p.RelayAddresses,
		ConnectedPeers:     s.p.PeerCount(),
		UniqueConns:        s.p.UniqueConnCount(),
		RoutingTableSize:   rtSize,
		StoreEntries:       storeEntries,
		StoreBytes:         storeBytes,
		StoreBudget:        s.d.LocalStoreBudget(),
		GoVersion:          runtime.Version(),
		NumGoroutine:       runtime.NumGoroutine(),
		UptimeSec:          int64(time.Since(s.start).Seconds()),
	}
}
