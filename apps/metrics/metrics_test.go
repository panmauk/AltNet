package metrics

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/peer"
)

func newNode(t *testing.T) (*peer.Peer, *dht.DHT) {
	t.Helper()
	id, err := crypto.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p := peer.New(id, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := dht.New(p)
	if err != nil {
		p.Stop()
		t.Fatal(err)
	}
	return p, d
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestMetricsSnapshotReflectsState verifies the snapshot reports
// the actual peer/DHT state, not stale or zero values.
func TestMetricsSnapshotReflectsState(t *testing.T) {
	p, d := newNode(t)
	defer p.Stop()

	// Add a synthetic value to the local store so we have non-zero
	// store metrics.
	value := []byte("hello metrics")
	_, err := d.Store(dht.ContentAddress(value), value)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(p, d)
	snap := srv.Snapshot()

	if snap.PeerID != p.Identity.ID() {
		t.Errorf("PeerID = %q, want %q", snap.PeerID, p.Identity.ID())
	}
	if snap.ShortID == "" {
		t.Error("ShortID should be populated")
	}
	if snap.ListenAddress == "" {
		t.Error("ListenAddress should be populated")
	}
	if snap.StoreEntries < 1 {
		t.Errorf("StoreEntries = %d, want >= 1 after a Store", snap.StoreEntries)
	}
	if snap.StoreBytes < int64(len(value)) {
		t.Errorf("StoreBytes = %d, want >= %d", snap.StoreBytes, len(value))
	}
	if snap.NumGoroutine == 0 {
		t.Error("NumGoroutine should be non-zero")
	}
	if snap.GoVersion == "" {
		t.Error("GoVersion should be populated")
	}
}

// TestMetricsHTTPRoundTrip exercises the actual HTTP endpoint and
// confirms the JSON parses into a Snapshot.
func TestMetricsHTTPRoundTrip(t *testing.T) {
	p, d := newNode(t)
	defer p.Stop()

	srv := New(p, d)
	addr := freePort(t)
	httpSrv, err := srv.Start(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx)
	}()

	// Wait briefly for the listener.
	time.Sleep(50 * time.Millisecond)

	// /metrics returns valid JSON.
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got Snapshot
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, body)
	}
	if got.PeerID != p.Identity.ID() {
		t.Errorf("PeerID = %q, want %q", got.PeerID, p.Identity.ID())
	}

	// /healthz returns "ok\n".
	resp2, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "ok\n" {
		t.Errorf("/healthz body = %q, want \"ok\\n\"", string(body2))
	}
}

// TestMetricsAdvertisedAddressesReflectPublicFlag: a peer marked
// public should report its direct address as the first advertised
// path in the snapshot.
func TestMetricsAdvertisedAddressesReflectPublicFlag(t *testing.T) {
	p, d := newNode(t)
	defer p.Stop()
	p.SetPublic(true)

	snap := New(p, d).Snapshot()
	if !snap.IsPublic {
		t.Error("IsPublic should be true")
	}
	if len(snap.AdvertisedAddrs) == 0 {
		t.Fatal("AdvertisedAddrs should not be empty")
	}
	if snap.AdvertisedAddrs[0] != p.LocalAddr() {
		t.Errorf("first advertised = %q, want listen %q",
			snap.AdvertisedAddrs[0], p.LocalAddr())
	}
}
