package files

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/peer"
)

// newNode is a small helper to spin up a peer + DHT bound to a free port.
func newNode(t *testing.T) (*peer.Peer, *dht.DHT) {
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
	return p, d
}

// TestRoundTripBytes verifies that a single-peer publish/fetch cycle
// preserves the data exactly. Tests several sizes including: empty,
// smaller than one chunk, exactly one chunk, several chunks, and
// non-aligned (chunk + remainder).
func TestRoundTripBytes(t *testing.T) {
	_, d := newNode(t)

	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 100},
		{"one_chunk", ChunkSize},
		{"two_chunks", 2 * ChunkSize},
		{"unaligned", 3*ChunkSize + 12345},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.size)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			_, key, err := PublishBytes(d, data)
			if err != nil {
				t.Fatalf("publish: %v", err)
			}
			got, err := FetchBytes(d, key)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("data mismatch: got %d bytes, want %d", len(got), len(data))
			}
		})
	}
}

// TestPublishFetchDirAcrossNetwork is the milestone test for the file-system
// layer: peer B publishes a directory of files, peer C (which never directly
// stored anything) reconstructs the entire directory byte-for-byte from the
// DHT through peer A.
func TestPublishFetchDirAcrossNetwork(t *testing.T) {
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

	// Build a small "site" directory on disk.
	src := t.TempDir()
	files := map[string][]byte{
		"index.html":            []byte("<html><body><h1>hi from altnet</h1></body></html>"),
		"styles.css":            []byte("body { font-family: sans-serif; }"),
		"img/logo.bin":          randBytes(t, 3*ChunkSize+777), // multi-chunk binary
		"posts/2026/hello.md":   []byte("# hello\n\njust a test post"),
		"empty.txt":             []byte(""),
	}
	for path, data := range files {
		full := filepath.Join(src, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	rootKey, manifest, err := PublishDir(db, src)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(manifest.Entries) != len(files) {
		t.Errorf("manifest has %d entries, want %d", len(manifest.Entries), len(files))
	}

	// Now fetch on peer C.
	dest := t.TempDir()
	if _, err := FetchDir(dc, rootKey, dest); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	// Compare every file byte-for-byte.
	for path, want := range files {
		full := filepath.Join(dest, filepath.FromSlash(path))
		got, err := os.ReadFile(full)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("file %s mismatch: got %d bytes, want %d", path, len(got), len(want))
		}
	}
}

// TestFetchRejectsPathTraversal verifies that a malicious directory record
// with "../" in a path is refused, so we can never overwrite files outside
// the requested destination.
func TestFetchRejectsPathTraversal(t *testing.T) {
	_, d := newNode(t)

	// Build a directory entry by hand.
	bad := &Directory{Entries: []DirEntry{{Path: "../escaped.txt", Size: 0, ManifestKey: ""}}}
	blob, _ := bad.Marshal()
	rootKey := dht.ContentAddress(blob)
	if _, err := d.Store(rootKey, blob); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if _, err := FetchDir(d, rootKey, dest); err == nil {
		t.Fatal("FetchDir should reject path-traversal entries")
	} else if !strings.Contains(err.Error(), "unsafe path") {
		t.Errorf("expected 'unsafe path' error, got %v", err)
	}
}

// randBytes returns n cryptographically random bytes for tests.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
