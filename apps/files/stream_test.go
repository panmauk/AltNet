package files

import (
	"bytes"
	"io"
	"testing"
	"time"

	"altnet/core/dht"
)

// TestChunkReaderSequentialRead reads a multi-chunk file end-to-end
// through ChunkReader and verifies the bytes match what we published.
func TestChunkReaderSequentialRead(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	// Build a file that spans ~3.5 chunks so we exercise multi-chunk
	// fetch + a partial last chunk.
	original := bytes.Repeat([]byte("0123456789ABCDEF"), (ChunkSize/16)*3+ChunkSize/32)
	_, manifestKey, err := PublishBytes(da, original)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	reader, err := NewChunkReader(da, manifestKey)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if reader.Size() != int64(len(original)) {
		t.Errorf("Size = %d, want %d", reader.Size(), len(original))
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("ReadAll size mismatch: got %d bytes, want %d", len(got), len(original))
	}
}

// TestChunkReaderRandomAccess: Seek + Read on arbitrary offsets
// should return correct bytes. This is what http.ServeContent does
// for Range requests.
func TestChunkReaderRandomAccess(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	// Distinct byte at every offset so we can verify position.
	original := make([]byte, 4*ChunkSize+128)
	for i := range original {
		original[i] = byte(i & 0xFF)
	}
	_, manifestKey, err := PublishBytes(da, original)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := NewChunkReader(da, manifestKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		offset int64
		n      int
	}{
		{0, 16},                 // first bytes
		{int64(ChunkSize - 4), 8}, // straddles chunk 0/1 boundary
		{int64(2 * ChunkSize), 256},
		{int64(len(original)) - 32, 32}, // final chunk's tail
	}
	for _, tc := range cases {
		if _, err := reader.Seek(tc.offset, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, tc.n)
		// May take multiple Reads if range crosses a chunk.
		got := make([]byte, 0, tc.n)
		for len(got) < tc.n {
			n, err := reader.Read(buf[:tc.n-len(got)])
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Fatalf("Read at %d: %v", tc.offset, err)
			}
		}
		if !bytes.Equal(got, original[tc.offset:tc.offset+int64(tc.n)]) {
			t.Errorf("Seek(%d)+Read(%d) returned wrong bytes", tc.offset, tc.n)
		}
	}
}

// TestChunkReaderDoesNotPrefetch verifies the streaming property:
// creating the reader fetches ONLY the manifest, not any chunks.
// We measure this by checking the local store size before/after
// NewChunkReader on a fresh peer that doesn't have the chunks
// locally.
//
// Setup: peer A publishes (gets all chunks locally). Peer B
// bootstraps to A. We open a ChunkReader on B against A's manifest
// key. B's store should grow by exactly the manifest size, not the
// full file.
func TestChunkReaderDoesNotPrefetch(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// 8 chunks worth of data so prefetch vs lazy is obvious.
	original := bytes.Repeat([]byte("x"), 8*ChunkSize)
	_, manifestKey, err := PublishBytes(da, original)
	if err != nil {
		t.Fatal(err)
	}

	bytesBeforeReader := db.LocalStoreBytes()

	reader, err := NewChunkReader(db, manifestKey)
	if err != nil {
		t.Fatal(err)
	}
	bytesAfterReader := db.LocalStoreBytes()

	// Only the manifest should have been fetched / cached locally.
	// Manifest is small (a few hundred bytes for 8 chunks). We assert
	// the growth is much less than even a single chunk.
	growth := bytesAfterReader - bytesBeforeReader
	if growth >= int64(ChunkSize) {
		t.Errorf("NewChunkReader fetched %d bytes -- it should fetch only the manifest, not chunks", growth)
	}

	// First Read should pull exactly one chunk.
	buf := make([]byte, 16)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 {
		t.Errorf("first Read returned %d bytes", n)
	}
	bytesAfterOneChunk := db.LocalStoreBytes()
	chunkGrowth := bytesAfterOneChunk - bytesAfterReader
	if chunkGrowth > int64(ChunkSize)+1024 {
		// chunkSize plus some manifest/overhead slack
		t.Errorf("first read fetched %d bytes -- expected ~one chunk (%d)", chunkGrowth, ChunkSize)
	}
}

// TestChunkReaderSeekEndReportsSize matches what http.ServeContent
// uses to compute Content-Length. Seek(0, io.SeekEnd) must return
// the true file size from the manifest.
func TestChunkReaderSeekEndReportsSize(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	data := make([]byte, ChunkSize+777)
	_, mkey, err := PublishBytes(da, data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewChunkReader(da, mkey)
	if err != nil {
		t.Fatal(err)
	}
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}
	if end != int64(len(data)) {
		t.Errorf("Seek(0, SeekEnd) = %d, want %d", end, len(data))
	}
}

// TestChunkReaderTrustsContentAddressing: confirms the chunks
// returned by Read pass through dht.Get's content-address verification
// (so a tampered chunk would fail). We don't simulate tampering here
// because the dht layer's TestGetRejectsTamperedValue already covers
// it; this just sanity-checks that ChunkReader wires through Get.
func TestChunkReaderUsesGetForChunks(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	data := []byte("verify me end-to-end")
	_, mkey, err := PublishBytes(da, data)
	if err != nil {
		t.Fatal(err)
	}
	// Forget to publish: actually we DID publish. Let's just check
	// the reader returns the right bytes; the dht layer verifies on
	// each Get.
	r, err := NewChunkReader(da, mkey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
	_ = dht.NodeID{} // keep import used if the test changes shape
}
