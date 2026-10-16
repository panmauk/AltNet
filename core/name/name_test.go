package name

import (
	"encoding/json"
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/peer"
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

// --- Pure logic ---

func TestCanonicalName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"panmox.alt", "panmox.alt"},
		{"Panmox.alt", "panmox.alt"},
		{"  PANMOX.alt  ", "panmox.alt"},
		{"panmox.alt.", "panmox.alt"}, // trailing-dot from DNS clients
	}
	for _, tc := range cases {
		if got := CanonicalName(tc.in); got != tc.want {
			t.Errorf("CanonicalName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidName(t *testing.T) {
	good := []string{
		"a",
		"alice",
		"alice.alt",
		"my-site.alt",
		"sub.domain.example.alt",
		"abc123",
	}
	for _, s := range good {
		if err := validName(s); err != nil {
			t.Errorf("validName(%q) unexpectedly failed: %v", s, err)
		}
	}
	bad := []string{
		"",
		"  ",
		"-leading.alt",
		"trailing-.alt",
		".leading-dot",
		"with space",
		"bang!.alt",
		"double..dot",
		"UPPERCASE_LETTERS.alt", // canonicalized lowercases -- but underscore still illegal
	}
	for _, s := range bad {
		if err := validName(s); err == nil {
			t.Errorf("validName(%q) should have failed", s)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	id, _ := crypto.NewIdentity()
	rec := &NameRecord{
		Name:      "alice.alt",
		Root:      "00" + repeat("0", 62),
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := rec.Sign(id); err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("legitimate record should verify: %v", err)
	}
}

func TestVerifyRejectsTamperedRoot(t *testing.T) {
	id, _ := crypto.NewIdentity()
	rec := &NameRecord{
		Name:      "alice.alt",
		Root:      "11" + repeat("0", 62),
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := rec.Sign(id); err != nil {
		t.Fatal(err)
	}
	rec.Root = "22" + repeat("0", 62) // tamper after signing
	if err := rec.Verify(); err == nil {
		t.Fatal("tampered record should fail verification")
	}
}

// --- DHT round-trip ---

func TestPublishAndResolve(t *testing.T) {
	pa, _, _ := newNode(t)
	defer pa.Stop()
	pb, db, idb := newNode(t)
	defer pb.Stop()
	pc, dc, _ := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	root := dht.ContentAddress([]byte("pretend-this-is-a-site-root"))
	rec, err := Publish(db, idb, "bob.alt", root, 1)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rec.Name != "bob.alt" {
		t.Errorf("expected canonical name bob.alt, got %q", rec.Name)
	}

	got, err := Resolve(dc, "bob.alt")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	gotRoot, err := got.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	if !gotRoot.Equal(root) {
		t.Errorf("root mismatch: got %s, want %s", gotRoot, root)
	}
}

func TestResolveRejectsRecordWithMismatchedName(t *testing.T) {
	pa, da, ida := newNode(t)
	defer pa.Stop()
	pb, db, _ := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// Build a properly-signed record claiming to be "bob.alt" but plant
	// it under the DHT key for "alice.alt".
	rec := &NameRecord{
		Name:      "bob.alt",
		Root:      dht.ContentAddress([]byte("x")).Hex(),
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if err := rec.Sign(ida); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(rec)
	if _, err := da.Store(RecordKey("alice.alt"), blob); err != nil {
		t.Fatal(err)
	}

	if _, err := Resolve(db, "alice.alt"); err == nil {
		t.Fatal("Resolve should reject a record whose embedded name doesn't match")
	}
}

// TestResolvePicksHighestVersion is the version-voting milestone: when
// two peers hold records for the same name with different Versions,
// Resolve picks the higher one even if the lower-version peer is
// hit first by the iterative lookup.
//
// Setup: A holds version 1, B holds version 5 (both signed by the same
// owner). C resolves; must get version 5.
func TestResolvePicksHighestVersion(t *testing.T) {
	pa, da, owner := newNode(t)
	defer pa.Stop()
	pb, db, _ := newNode(t)
	defer pb.Stop()
	pc, dc, _ := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// Build a stale (v1) and a fresh (v5) record for "evolving.alt",
	// both signed by the same owner.
	oldRoot := dht.ContentAddress([]byte("v1-content"))
	newRoot := dht.ContentAddress([]byte("v5-content"))

	stale := &NameRecord{
		Name:      "evolving.alt",
		Root:      oldRoot.Hex(),
		Version:   1,
		Timestamp: time.Now().Unix() - 3600,
	}
	if err := stale.Sign(owner); err != nil {
		t.Fatal(err)
	}
	staleBlob, _ := json.Marshal(stale)

	fresh := &NameRecord{
		Name:      "evolving.alt",
		Root:      newRoot.Hex(),
		Version:   5,
		Timestamp: time.Now().Unix(),
	}
	if err := fresh.Sign(owner); err != nil {
		t.Fatal(err)
	}
	freshBlob, _ := json.Marshal(fresh)

	// Plant directly: A gets the STALE one, B gets the FRESH one.
	// This simulates a partial-update scenario where one replica got
	// the new version and another didn't.
	if _, err := da.Store(RecordKey("evolving.alt"), staleBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Store(RecordKey("evolving.alt"), freshBlob); err != nil {
		t.Fatal(err)
	}

	got, err := Resolve(dc, "evolving.alt")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Version != 5 {
		t.Errorf("Resolve returned Version=%d, want 5 (highest)", got.Version)
	}
	if got.Root != newRoot.Hex() {
		t.Errorf("Resolve returned Root=%q, want %q (the v5 root)", got.Root, newRoot.Hex())
	}
}

// TestPickBestRecordSkipsBogusReplicas exercises the voting logic on a
// hand-built candidate list: a tampered record, a wrong-name record,
// junk JSON, AND a valid record. The valid one must win regardless of
// the order it appears in the list.
//
// We use the unit-level helper rather than a full DHT topology because
// at the integration level Store() replicates to closest peers, which
// would clobber any divergent state we tried to plant on individual
// peers.
func TestPickBestRecordSkipsBogusReplicas(t *testing.T) {
	owner, _ := crypto.NewIdentity()

	root := dht.ContentAddress([]byte("real content"))
	good := &NameRecord{
		Name:      "site.alt",
		Root:      root.Hex(),
		Version:   2,
		Timestamp: time.Now().Unix(),
	}
	if err := good.Sign(owner); err != nil {
		t.Fatal(err)
	}
	goodBlob, _ := json.Marshal(good)

	// Tampered: same name+version but Root swapped after signing.
	tampered := &NameRecord{
		Name:      "site.alt",
		Root:      root.Hex(),
		Version:   3, // higher version, but invalid sig should disqualify
		Timestamp: time.Now().Unix(),
	}
	_ = tampered.Sign(owner)
	tampered.Root = dht.ContentAddress([]byte("attacker root")).Hex()
	tamperedBlob, _ := json.Marshal(tampered)

	// Wrong name: signed but for the wrong DHT key.
	wrong := &NameRecord{
		Name:      "evil.alt",
		Root:      root.Hex(),
		Version:   100,
		Timestamp: time.Now().Unix(),
	}
	_ = wrong.Sign(owner)
	wrongBlob, _ := json.Marshal(wrong)

	junk := []byte(`{not even valid json`)

	// Try in several orders to confirm voting doesn't depend on input
	// ordering.
	orders := [][][]byte{
		{goodBlob, tamperedBlob, wrongBlob, junk},
		{tamperedBlob, junk, wrongBlob, goodBlob},
		{junk, tamperedBlob, goodBlob, wrongBlob},
	}
	for i, candidates := range orders {
		best, _ := pickBestRecord("site.alt", candidates)
		if best == nil {
			t.Errorf("order %d: pickBestRecord returned nil despite valid candidate", i)
			continue
		}
		if best.Version != 2 {
			t.Errorf("order %d: picked Version=%d, want 2 (the valid one)", i, best.Version)
		}
		if best.Root != root.Hex() {
			t.Errorf("order %d: picked Root=%q, want %q", i, best.Root, root.Hex())
		}
	}

	// All-bogus list yields nil + last error.
	best, lastErr := pickBestRecord("site.alt", [][]byte{tamperedBlob, junk})
	if best != nil {
		t.Errorf("expected nil for all-bogus, got %+v", best)
	}
	if lastErr == nil {
		t.Error("expected an error explaining why nothing matched")
	}
}

// TestExpiredRecordIsRejected: a signed record that's past its TTL
// must be skipped by pickBestRecord, even if it's the only candidate.
// This is the replay-protection guarantee.
func TestExpiredRecordIsRejected(t *testing.T) {
	owner, _ := crypto.NewIdentity()

	expired := &NameRecord{
		Name:      "old.alt",
		Root:      dht.ContentAddress([]byte("x")).Hex(),
		Version:   1,
		Timestamp: time.Now().Unix() - 30*24*3600, // 30 days old
		TTL:       7 * 24 * 3600,                  // 7-day TTL -> expired by 23 days
	}
	if err := expired.Sign(owner); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(expired)

	best, lastErr := pickBestRecord("old.alt", [][]byte{blob})
	if best != nil {
		t.Errorf("expected nil for expired-only candidate, got Version=%d", best.Version)
	}
	if lastErr == nil {
		t.Error("expected an error explaining expiry")
	}
}

// TestFreshRecordSupersedesExpired: when both a stale-but-valid
// signature record AND a fresh record are present, the fresh one wins.
// This is the "you can't replay an old version after I publish a
// newer one" property.
func TestFreshRecordSupersedesExpired(t *testing.T) {
	owner, _ := crypto.NewIdentity()
	now := time.Now().Unix()

	// Old record: high version, but expired.
	old := &NameRecord{
		Name:      "evolving.alt",
		Root:      dht.ContentAddress([]byte("old root")).Hex(),
		Version:   100, // high version
		Timestamp: now - 30*24*3600,
		TTL:       7 * 24 * 3600,
	}
	_ = old.Sign(owner)
	oldBlob, _ := json.Marshal(old)

	// Fresh record: lower version (e.g. publisher reset their counter
	// after a wipe), but unexpired.
	fresh := &NameRecord{
		Name:      "evolving.alt",
		Root:      dht.ContentAddress([]byte("new root")).Hex(),
		Version:   2,
		Timestamp: now,
		TTL:       DefaultNameTTL,
	}
	_ = fresh.Sign(owner)
	freshBlob, _ := json.Marshal(fresh)

	got, _ := pickBestRecord("evolving.alt", [][]byte{oldBlob, freshBlob})
	if got == nil {
		t.Fatal("expected the fresh record to win")
	}
	if got.Version != 2 {
		t.Errorf("got Version=%d, want 2 (the fresh one; expired v100 should be ignored)", got.Version)
	}
}

// TestFutureDatedRecordRejected: an attacker can't bypass TTL by
// stamping a far-future timestamp.
func TestFutureDatedRecordRejected(t *testing.T) {
	owner, _ := crypto.NewIdentity()
	rec := &NameRecord{
		Name:      "evil.alt",
		Root:      dht.ContentAddress([]byte("x")).Hex(),
		Version:   1,
		Timestamp: time.Now().Unix() + 365*24*3600, // 1 year in the future
		TTL:       DefaultNameTTL,
	}
	_ = rec.Sign(owner)
	blob, _ := json.Marshal(rec)

	best, _ := pickBestRecord("evil.alt", [][]byte{blob})
	if best != nil {
		t.Error("future-dated record should have been rejected")
	}
}

// TestPublishStampsTTL: the public Publish API should set DefaultNameTTL
// so callers don't accidentally publish never-expiring records.
func TestPublishStampsTTL(t *testing.T) {
	pa, _, _ := newNode(t)
	defer pa.Stop()
	pb, db, idb := newNode(t)
	defer pb.Stop()
	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	rec, err := Publish(db, idb, "ttltest.alt", dht.ContentAddress([]byte("x")), 1)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TTL != DefaultNameTTL {
		t.Errorf("Publish set TTL=%d, want %d", rec.TTL, DefaultNameTTL)
	}
}

// helper: build a string by repeating r n times
func repeat(r string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += r
	}
	return out
}
