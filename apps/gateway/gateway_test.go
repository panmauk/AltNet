package gateway

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"altnet/apps/files"
	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/name"
	"altnet/core/peer"
	"altnet/core/relay"
)

func newNode(t *testing.T) (*peer.Peer, *dht.DHT, *crypto.Identity) {
	t.Helper()
	id, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	p := peer.New(id, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	d, err := dht.New(p)
	if err != nil {
		p.Stop()
		t.Fatalf("dht: %v", err)
	}
	return p, d, id
}

// freePort returns a port that is currently free on localhost.
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

// TestEndToEndPublishAndHTTPFetch is the milestone for the gateway. It
// proves the entire pipeline:
//
//  1. Peer A publishes a small site.
//  2. Peer A registers @site -> root.
//  3. Peer B is bootstrapped through A and runs the HTTP gateway.
//  4. We curl http://gateway/@site/index.html and get the bytes back.
//
// If this passes, the user flow "type a name in your browser, see content"
// works on real plumbing.
func TestEndToEndPublishAndHTTPFetch(t *testing.T) {
	pa, da, ida := newNode(t)
	defer pa.Stop()
	pb, db, _ := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// 1. Publish a tiny site on peer A.
	src := t.TempDir()
	indexHTML := []byte(`<!DOCTYPE html><h1>hello from altnet</h1>`)
	stylesCSS := []byte(`h1 { color: orange; }`)
	if err := os.WriteFile(filepath.Join(src, "index.html"), indexHTML, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "styles.css"), stylesCSS, 0o644); err != nil {
		t.Fatal(err)
	}

	rootKey, _, err := files.PublishDir(da, src)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	// 2. Register the name on A.
	if _, err := name.Publish(da, ida, "testsite.alt", rootKey, 1); err != nil {
		t.Fatalf("name publish: %v", err)
	}

	// 3. Start the gateway on B.
	gw := New(db)
	addr := freePort(t)
	srv, err := gw.Start(addr)
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Give the listener a moment to come up.
	time.Sleep(50 * time.Millisecond)

	// 4. Fetch via HTTP through B. We send the Host header that an end-user's
	// browser would send when typing "testsite.alt" into the URL bar
	// (assuming a DNS resolver pointed that domain at our gateway IP).
	client := &http.Client{Timeout: 5 * time.Second}

	doGet := func(path, hostHeader string) (*http.Response, []byte) {
		req, err := http.NewRequest("GET", "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if hostHeader != "" {
			req.Host = hostHeader
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s (Host=%s): %v", path, hostHeader, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, body
	}

	// (a) The primary path: domain in Host header, plain URL path for the file.
	resp, body := doGet("/index.html", "testsite.alt")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, indexHTML) {
		t.Errorf("index.html mismatch: got %q, want %q", body, indexHTML)
	}
	if ct := resp.Header.Get("Content-Type"); !startsWith(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}

	// (b) Default path resolves to index.html.
	resp2, body2 := doGet("/", "testsite.alt")
	if resp2.StatusCode != 200 {
		t.Fatalf("status = %d for /", resp2.StatusCode)
	}
	if !bytes.Equal(body2, indexHTML) {
		t.Errorf("default path did not return index.html")
	}

	// (c) Other files with correct content-type.
	resp3, body3 := doGet("/styles.css", "testsite.alt")
	if !bytes.Equal(body3, stylesCSS) {
		t.Errorf("styles.css mismatch")
	}
	if ct := resp3.Header.Get("Content-Type"); !startsWith(ct, "text/css") {
		t.Errorf("expected text/css, got %q", ct)
	}

	// (d) Unknown name: 404.
	resp4, _ := doGet("/", "nonexistent.alt")
	if resp4.StatusCode != 404 {
		t.Errorf("unknown name should be 404, got %d", resp4.StatusCode)
	}

	// (e) Fallback: localhost path-based routing for dev.
	resp5, body5 := doGet("/cid/"+rootKey.Hex()+"/index.html", "")
	if !bytes.Equal(body5, indexHTML) {
		t.Errorf("cid fetch did not return index.html (status=%d)", resp5.StatusCode)
	}

	// (f) Fallback: explicit /n/<name>/ path for dev.
	resp6, body6 := doGet("/n/testsite.alt/index.html", "")
	if !bytes.Equal(body6, indexHTML) {
		t.Errorf("/n/<name>/ fetch did not return index.html (status=%d)", resp6.StatusCode)
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// TestGatewayServesByteRange is the video-seek milestone: a client
// asking for bytes=5-9 of a file gets exactly those 5 bytes, status
// 206 Partial Content, plus a Content-Range header. Without Range
// support, browsers can't seek video / scrub audio / resume large
// downloads.
func TestGatewayServesByteRange(t *testing.T) {
	pa, da, ida := newNode(t)
	defer pa.Stop()
	pb, db, _ := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Publish a small file so we have a known byte sequence.
	src := t.TempDir()
	full := []byte("0123456789abcdef") // 16 bytes, easy to range-check
	if err := os.WriteFile(filepath.Join(src, "data.bin"), full, 0o644); err != nil {
		t.Fatal(err)
	}
	rootKey, _, err := files.PublishDir(da, src)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := name.Publish(da, ida, "rangesite.alt", rootKey, 1); err != nil {
		t.Fatal(err)
	}

	// Start gateway on B.
	gw := New(db)
	addr := freePort(t)
	srv, err := gw.Start(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	// Range: bytes=5-9 -- expect "56789".
	req, err := http.NewRequest("GET", "http://"+addr+"/data.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "rangesite.alt"
	req.Header.Set("Range", "bytes=5-9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("ranged GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status = %d, want 206 Partial Content", resp.StatusCode)
	}
	if cr := resp.Header.Get("Content-Range"); cr == "" {
		t.Error("Content-Range header missing")
	} else if !strings.HasPrefix(cr, "bytes 5-9/16") {
		t.Errorf("Content-Range = %q, want 'bytes 5-9/16...'", cr)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "56789" {
		t.Errorf("body = %q, want %q", body, "56789")
	}

	// Tail range: bytes=-3 means "the last 3 bytes" -> "def".
	req2, _ := http.NewRequest("GET", "http://"+addr+"/data.bin", nil)
	req2.Host = "rangesite.alt"
	req2.Header.Set("Range", "bytes=-3")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusPartialContent {
		t.Errorf("tail-range status = %d", resp2.StatusCode)
	}
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "def" {
		t.Errorf("tail body = %q, want %q", body2, "def")
	}

	// ETag-based caching: a If-None-Match with the published ETag
	// returns 304 Not Modified.
	req3, _ := http.NewRequest("GET", "http://"+addr+"/data.bin", nil)
	req3.Host = "rangesite.alt"
	// First request to grab the ETag.
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp3.Header.Get("ETag")
	resp3.Body.Close()
	if etag == "" {
		t.Fatal("expected ETag on full response")
	}

	req4, _ := http.NewRequest("GET", "http://"+addr+"/data.bin", nil)
	req4.Host = "rangesite.alt"
	req4.Header.Set("If-None-Match", etag)
	resp4, err := client.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: status = %d, want 304", resp4.StatusCode)
	}
}

// TestEndToEndOverRelay is the full NAT-traversal milestone. It proves
// that the entire stack -- relay + DHT + name + content fetch + HTTP
// gateway + secure transport -- works end-to-end when the publisher is
// behind NAT.
//
// Topology:
//
//   R: public node, runs peer + relay (the bootstrap-and-rendezvous box)
//   A: "publisher" peer, registers via R, publishes a site, owns the name
//   B: "browser" peer, bootstraps via R, runs the HTTP gateway
//
// Critically, the only address A ever advertises to the network is
// "relay://R/A_id". B never directly dials A's listen socket -- all
// traffic between A and B flows through the relay R, end-to-end
// encrypted (R cannot read it).
//
// This is the user flow we promised: someone puts a site on AltNet from
// a home network behind NAT, and another person on a different network
// can browse it.
func TestEndToEndOverRelay(t *testing.T) {
	// --- R: public node with peer + relay ---
	pr, dr, _ := newNode(t)
	defer pr.Stop()

	relaySrv := relay.NewServer()
	if err := relaySrv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer relaySrv.Stop()
	relayAddr := relaySrv.LocalAddr().String()

	// --- A: NAT-ed publisher, registered via R ---
	pa, da, ida := newNode(t)
	defer pa.Stop()
	pa.UseRelay(relayAddr)

	// Wait for A's relay registration to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relaySrv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if relaySrv.RegistrationCount() != 1 {
		t.Fatal("A never registered with relay")
	}

	// A bootstraps through R (outbound TCP, NAT-friendly).
	if err := da.Bootstrap(pr.LocalAddr()); err != nil {
		t.Fatalf("A bootstrap to R: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// A publishes a site and registers the name.
	src := t.TempDir()
	indexHTML := []byte(`<!DOCTYPE html><h1>hello from behind NAT</h1>`)
	if err := os.WriteFile(filepath.Join(src, "index.html"), indexHTML, 0o644); err != nil {
		t.Fatal(err)
	}
	rootKey, _, err := files.PublishDir(da, src)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := name.Publish(da, ida, "panmox.alt", rootKey, 1); err != nil {
		t.Fatalf("name publish: %v", err)
	}

	// Sanity: R's routing table should now have A, listed under its
	// relay URL (because that's what A advertised in hello).
	contacts := dr.RoutingTable().All()
	foundRelayedA := false
	for _, c := range contacts {
		if c.ID.Hex() == ida.ID() {
			if !startsWith(c.Address, "relay://") {
				t.Errorf("R has A but at non-relay address %q", c.Address)
			}
			foundRelayedA = true
		}
	}
	if !foundRelayedA {
		t.Fatal("R's routing table doesn't have A; A never propagated through bootstrap")
	}

	// --- B: browser with gateway, bootstraps through R ---
	pb, db, _ := newNode(t)
	defer pb.Stop()
	if err := db.Bootstrap(pr.LocalAddr()); err != nil {
		t.Fatalf("B bootstrap to R: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Start the gateway on B.
	gw := New(db)
	gwAddr := freePort(t)
	srv, err := gw.Start(gwAddr)
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	// --- The actual user flow: GET panmox.alt/ via the gateway ---
	// This forces:
	//   B's gateway -> resolves panmox.alt via DHT (asks R)
	//   B's gateway -> fetches root manifest from DHT
	//                  (R has it because A republished or B finds A as holder)
	//   B's gateway -> fetches chunks from A
	//                  -> peer.Connect("relay://R/A_id")
	//                  -> relay.DialVia opens a tunnel through R to A
	//                  -> secure handshake B<->A end-to-end
	//                  -> chunks travel back through R, encrypted
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "http://"+gwAddr+"/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "panmox.alt"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET panmox.alt/index.html via gateway: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, indexHTML) {
		t.Errorf("body mismatch: got %q, want %q", body, indexHTML)
	}

	// And confirm B actually established a relayed connection to A
	// (rather than somehow skipping the relay path).
	bPeers := pb.PeerCountByAddr()
	relayedConn := false
	for addr := range bPeers {
		if startsWith(addr, "relay://") {
			relayedConn = true
		}
	}
	if !relayedConn {
		t.Errorf("expected B to have a relayed connection, got peers: %v", bPeers)
	}
}
