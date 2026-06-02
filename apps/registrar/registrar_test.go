package registrar

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"altnet/apps/sitestats"
	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/name"
	"altnet/core/peer"
)

const testToken = "secret-test-token-1234"

// newTestNode spins up a peer + DHT for testing.
func newTestNode(t *testing.T) (*peer.Peer, *dht.DHT, *crypto.Identity) {
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

func startRegistrar(t *testing.T) (*Registrar, string, func()) {
	t.Helper()
	p, d, id := newTestNode(t)
	reg := New(d, id, testToken)
	srv, err := reg.Start("127.0.0.1:0")
	if err != nil {
		p.Stop()
		t.Fatalf("start registrar: %v", err)
	}
	// Wait a moment for the server to bind.
	time.Sleep(50 * time.Millisecond)

	addr := srv.Addr
	// srv.Addr might be ":0"; we need the real bound address.
	// Since we use ListenAndServe in a goroutine, we need a workaround.
	// Let's use a known port approach or wrap it differently.
	// Actually, we'll just test at the handler level instead.

	cleanup := func() {
		srv.Close()
		p.Stop()
	}
	return reg, addr, cleanup
}

// --- Handler-level tests (no network needed) ---

func TestCheckAvailableDomain(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()

	reg := New(d, id, testToken)

	resp := doCheck(t, reg, "alice.alt")
	if !resp.Available {
		t.Errorf("alice.alt should be available, got available=%v", resp.Available)
	}
	if resp.Name != "alice.alt" {
		t.Errorf("expected name=alice.alt, got %q", resp.Name)
	}
}

func TestCheckInvalidDomain(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()

	reg := New(d, id, testToken)

	resp := doCheck(t, reg, "alice.com")
	if resp.Error == "" {
		t.Error("alice.com should be rejected (not .alt TLD)")
	}
}

func TestRegisterAndCheck(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	reg := New(db, idb, testToken)

	// Register a domain.
	rootKey := dht.ContentAddress([]byte("my-site-content"))
	regResp := doRegister(t, reg, testToken, RegisterRequest{
		Name:  "alice.alt",
		Root:  rootKey.Hex(),
		Owner: "alice@example.com",
	})
	if regResp.Error != "" {
		t.Fatalf("register failed: %s", regResp.Error)
	}
	if regResp.Name != "alice.alt" {
		t.Errorf("expected name=alice.alt, got %q", regResp.Name)
	}
	if regResp.Root != rootKey.Hex() {
		t.Errorf("expected root=%s, got %s", rootKey.Hex(), regResp.Root)
	}

	// Now check it -- should no longer be available.
	checkResp := doCheck(t, reg, "alice.alt")
	if checkResp.Available {
		t.Error("alice.alt should be taken after registration")
	}
	if checkResp.Owner != "alice@example.com" {
		t.Errorf("expected owner=alice@example.com, got %q", checkResp.Owner)
	}
}

func TestRegisterDuplicateRejected(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	reg := New(db, idb, testToken)
	rootKey := dht.ContentAddress([]byte("content"))

	// First registration should succeed.
	resp1 := doRegister(t, reg, testToken, RegisterRequest{
		Name:  "alice.alt",
		Root:  rootKey.Hex(),
		Owner: "alice@example.com",
	})
	if resp1.Error != "" {
		t.Fatalf("first register failed: %s", resp1.Error)
	}

	// Second registration of same domain should fail.
	resp2 := doRegister(t, reg, testToken, RegisterRequest{
		Name:  "alice.alt",
		Root:  rootKey.Hex(),
		Owner: "bob@example.com",
	})
	if resp2.Error == "" {
		t.Error("second registration should have been rejected")
	}
}

func TestRegisterRequiresAuth(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()

	reg := New(d, id, testToken)
	rootKey := dht.ContentAddress([]byte("content"))

	// No token.
	resp := doRegister(t, reg, "", RegisterRequest{
		Name: "alice.alt", Root: rootKey.Hex(), Owner: "alice",
	})
	if resp.Error == "" {
		t.Error("registration without token should fail")
	}

	// Wrong token.
	resp = doRegister(t, reg, "wrong-token", RegisterRequest{
		Name: "alice.alt", Root: rootKey.Hex(), Owner: "alice",
	})
	if resp.Error == "" {
		t.Error("registration with wrong token should fail")
	}
}

func TestUpdateDomain(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	reg := New(db, idb, testToken)
	rootKey1 := dht.ContentAddress([]byte("content-v1"))
	rootKey2 := dht.ContentAddress([]byte("content-v2"))

	// Register.
	doRegister(t, reg, testToken, RegisterRequest{
		Name: "alice.alt", Root: rootKey1.Hex(), Owner: "alice",
	})

	// Update to new root.
	updateResp := doUpdate(t, reg, testToken, UpdateRequest{
		Name: "alice.alt",
		Root: rootKey2.Hex(),
	})
	if updateResp.Error != "" {
		t.Fatalf("update failed: %s", updateResp.Error)
	}
	if updateResp.Root != rootKey2.Hex() {
		t.Errorf("expected updated root=%s, got %s", rootKey2.Hex(), updateResp.Root)
	}

	// Verify DHT has the new record.
	rec, err := name.Resolve(db, "alice.alt")
	if err != nil {
		t.Fatalf("resolve after update: %v", err)
	}
	if rec.Root != rootKey2.Hex() {
		t.Errorf("DHT root should be updated, got %s", rec.Root)
	}
}

func TestUpdateNonexistentDomain(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()

	reg := New(d, id, testToken)
	rootKey := dht.ContentAddress([]byte("content"))

	resp := doUpdate(t, reg, testToken, UpdateRequest{
		Name: "ghost.alt",
		Root: rootKey.Hex(),
	})
	if resp.Error == "" {
		t.Error("updating a nonexistent domain should fail")
	}
}

func TestListDomains(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	reg := New(db, idb, testToken)
	rootKey := dht.ContentAddress([]byte("content"))

	doRegister(t, reg, testToken, RegisterRequest{
		Name: "alice.alt", Root: rootKey.Hex(), Owner: "alice",
	})
	doRegister(t, reg, testToken, RegisterRequest{
		Name: "bob.alt", Root: rootKey.Hex(), Owner: "bob",
	})

	domains := doListDomains(t, reg, testToken)
	if domains.Count != 2 {
		t.Errorf("expected 2 domains, got %d", domains.Count)
	}
}

func TestListDomainsRequiresAuth(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()

	reg := New(d, id, testToken)

	// Build a request without auth.
	body := doRequest(t, reg, "GET", "/api/domains", "", nil)
	var resp map[string]string
	json.Unmarshal(body, &resp)
	if resp["error"] == "" {
		t.Error("listing domains without auth should fail")
	}
}

// TestRegistrarPersistence verifies that registrations survive a restart.
// We register a domain, throw away the registrar, open a new one at the
// same data dir, and confirm the registration is still there.
func TestRegistrarPersistence(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	dataDir := t.TempDir()

	// First instance: register a domain.
	reg1, err := NewWithDataDir(db, idb, testToken, dataDir)
	if err != nil {
		t.Fatalf("create reg1: %v", err)
	}
	rootKey := dht.ContentAddress([]byte("alice site"))
	resp := doRegister(t, reg1, testToken, RegisterRequest{
		Name:  "alice.alt",
		Root:  rootKey.Hex(),
		Owner: "alice@example.com",
	})
	if resp.Error != "" {
		t.Fatalf("register: %s", resp.Error)
	}

	// Second instance at the same data dir: should see the prior registration.
	reg2, err := NewWithDataDir(db, idb, testToken, dataDir)
	if err != nil {
		t.Fatalf("create reg2: %v", err)
	}

	check := doCheck(t, reg2, "alice.alt")
	if check.Available {
		t.Error("alice.alt should be remembered as taken across restart")
	}
	if check.Owner != "alice@example.com" {
		t.Errorf("expected owner=alice@example.com after restart, got %q", check.Owner)
	}

	// And it should appear in the domain list.
	domains := doListDomains(t, reg2, testToken)
	if domains.Count != 1 {
		t.Errorf("expected 1 domain after restart, got %d", domains.Count)
	}
}

func TestPublishDirectory(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)

	// Make a temp directory with two small files.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"),
		[]byte("<h1>hello altnet</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "style.css"),
		[]byte("body{background:#000}"), 0o644); err != nil {
		t.Fatal(err)
	}

	body := doRequest(t, reg, "POST", "/api/publish", testToken, PublishRequest{Path: dir})
	var resp PublishResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, body)
	}
	if resp.Error != "" {
		t.Fatalf("publish failed: %s", resp.Error)
	}
	if resp.EntryCount != 2 {
		t.Errorf("expected 2 entries, got %d", resp.EntryCount)
	}
	if len(resp.Root) != 64 {
		t.Errorf("expected 64-char hex root, got %q (len=%d)", resp.Root, len(resp.Root))
	}
}

func TestPublishRequiresAuth(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)

	body := doRequest(t, reg, "POST", "/api/publish", "", PublishRequest{Path: "/whatever"})
	var er map[string]string
	_ = json.Unmarshal(body, &er)
	if er["error"] == "" {
		t.Fatal("expected auth error")
	}
}

func TestPublishRejectsMissingPath(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)

	body := doRequest(t, reg, "POST", "/api/publish", testToken, PublishRequest{Path: ""})
	var resp PublishResponse
	_ = json.Unmarshal(body, &resp)
	if resp.Error == "" {
		t.Fatal("expected error for empty path")
	}
}

func TestStatsEndpoint(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)
	st := sitestats.New()
	reg.SetStats(st)

	// Pretend the gateway has served some traffic.
	st.Record("alice.alt", "192.0.2.1", 256)
	st.Record("alice.alt", "192.0.2.2", 512)

	body := doRequest(t, reg, "GET", "/api/stats/alice.alt", testToken, nil)
	var resp StatsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if resp.Requests != 2 || resp.Bytes != 768 || resp.UniqueIPs != 2 {
		t.Fatalf("unexpected snapshot: %+v", resp)
	}
}

func TestStatsRequiresAuth(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)
	reg.SetStats(sitestats.New())
	body := doRequest(t, reg, "GET", "/api/stats/alice.alt", "", nil)
	var er map[string]string
	_ = json.Unmarshal(body, &er)
	if er["error"] == "" {
		t.Fatal("expected auth error")
	}
}

func TestUnregisterFlow(t *testing.T) {
	pa, _, _ := newTestNode(t)
	defer pa.Stop()
	pb, db, idb := newTestNode(t)
	defer pb.Stop()
	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	reg := New(db, idb, testToken)
	rootKey := dht.ContentAddress([]byte("v0-content"))
	resp := doRegister(t, reg, testToken, RegisterRequest{
		Name: "alice.alt", Root: rootKey.Hex(), Owner: "alice@example.com",
	})
	if resp.Error != "" {
		t.Fatalf("register: %s", resp.Error)
	}

	body := doRequest(t, reg, "POST", "/api/unregister", testToken, UnregisterRequest{Name: "alice.alt"})
	var unr UnregisterResponse
	if err := json.Unmarshal(body, &unr); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, body)
	}
	if !unr.OK {
		t.Fatalf("expected ok=true, got %+v", unr)
	}

	// Take-down removes the local registration. The DHT record can't
	// actually be deleted — it'll keep replying until its TTL — so
	// /api/check still reports unavailable. What we can verify is the
	// LOCAL state: GET /api/domains should no longer list it.
	domBody := doRequest(t, reg, "GET", "/api/domains", testToken, nil)
	var dr DomainsResponse
	if err := json.Unmarshal(domBody, &dr); err != nil {
		t.Fatalf("unmarshal domains: %v body=%s", err, domBody)
	}
	if dr.Count != 0 {
		t.Fatalf("expected local registry empty after unregister, got %+v", dr)
	}
}

func TestUnregisterMissingReturns404(t *testing.T) {
	p, d, id := newTestNode(t)
	defer p.Stop()
	reg := New(d, id, testToken)
	body := doRequest(t, reg, "POST", "/api/unregister", testToken,
		UnregisterRequest{Name: "ghost.alt"})
	var unr UnregisterResponse
	_ = json.Unmarshal(body, &unr)
	if unr.OK || unr.Error == "" {
		t.Fatalf("expected error on unknown name, got %+v", unr)
	}
}

func TestValidateDomainRules(t *testing.T) {
	good := []string{
		"alice.alt",
		"my-site.alt",
		"sub.domain.alt",
		"a.alt",
	}
	for _, s := range good {
		if err := ValidateDomain(s); err != nil {
			t.Errorf("ValidateDomain(%q) unexpectedly failed: %v", s, err)
		}
	}

	bad := []string{
		"",
		"alice.com",        // wrong TLD
		"alice.org",        // wrong TLD
		".alt",          // empty prefix
		"alt",           // bare TLD, no dot prefix
		"a",                // no .alt suffix
	}
	for _, s := range bad {
		if err := ValidateDomain(s); err == nil {
			t.Errorf("ValidateDomain(%q) should have failed", s)
		}
	}
}

// --- Test helpers: invoke handlers directly via http.ResponseWriter ---

func doRequest(t *testing.T, reg *Registrar, method, path, token string, body interface{}) []byte {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, path, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rr := &testResponseWriter{headers: http.Header{}}
	// Route to the correct handler based on path.
	switch {
	case method == "GET" && len(path) > len("/api/check/") && path[:len("/api/check/")] == "/api/check/":
		req.URL.Path = path
		reg.handleCheck(rr, req)
	case path == "/api/register":
		reg.handleRegister(rr, req)
	case path == "/api/update":
		reg.handleUpdate(rr, req)
	case path == "/api/domains":
		reg.handleDomains(rr, req)
	case path == "/api/publish":
		reg.handlePublish(rr, req)
	case method == "GET" && len(path) > len("/api/stats/") && path[:len("/api/stats/")] == "/api/stats/":
		req.URL.Path = path
		reg.handleStats(rr, req)
	case path == "/api/unregister":
		reg.handleUnregister(rr, req)
	default:
		t.Fatalf("unknown path: %s", path)
	}
	return rr.body
}

func doCheck(t *testing.T, reg *Registrar, domain string) CheckResponse {
	t.Helper()
	body := doRequest(t, reg, "GET", "/api/check/"+domain, "", nil)
	var resp CheckResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal check response: %v (body: %s)", err, body)
	}
	return resp
}

func doRegister(t *testing.T, reg *Registrar, token string, req RegisterRequest) RegisterResponse {
	t.Helper()
	body := doRequest(t, reg, "POST", "/api/register", token, req)
	var resp RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try parsing as error response.
		var errResp map[string]string
		if err2 := json.Unmarshal(body, &errResp); err2 == nil {
			return RegisterResponse{Error: errResp["error"]}
		}
		t.Fatalf("unmarshal register response: %v (body: %s)", err, body)
	}
	return resp
}

func doUpdate(t *testing.T, reg *Registrar, token string, req UpdateRequest) RegisterResponse {
	t.Helper()
	body := doRequest(t, reg, "POST", "/api/update", token, req)
	var resp RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		var errResp map[string]string
		if err2 := json.Unmarshal(body, &errResp); err2 == nil {
			return RegisterResponse{Error: errResp["error"]}
		}
		t.Fatalf("unmarshal update response: %v (body: %s)", err, body)
	}
	return resp
}

func doListDomains(t *testing.T, reg *Registrar, token string) DomainsResponse {
	t.Helper()
	body := doRequest(t, reg, "GET", "/api/domains", token, nil)
	var resp DomainsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal domains response: %v (body: %s)", err, body)
	}
	return resp
}

// testResponseWriter is a minimal http.ResponseWriter for handler-level testing.
type testResponseWriter struct {
	status  int
	headers http.Header
	body    []byte
}

func (w *testResponseWriter) Header() http.Header       { return w.headers }
func (w *testResponseWriter) WriteHeader(status int)     { w.status = status }
func (w *testResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
