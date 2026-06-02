package files

import (
	"errors"
	"fmt"
	"io"

	"altnet/core/dht"
)

// ChunkReader is an io.ReadSeeker over a chunked file stored in the
// DHT. Chunks are fetched LAZILY -- only the chunks that overlap the
// current read position are pulled, and a one-chunk cache holds the
// most recently fetched chunk so sequential reads don't refetch.
//
// This is the streaming alternative to FetchBytes: serving a 4 GB
// video through the gateway used to require 4 GB of RAM via
// FetchBytes (whole file into one slice). With ChunkReader, peak
// memory is one chunk (64 KiB) plus the manifest. Range requests
// (Range: bytes=N-M) only fetch the chunks that overlap [N..M].
//
// ChunkReader implements net/http's expectation for http.ServeContent:
// io.ReadSeeker. Seek(0, io.SeekEnd) returns the file size so the
// HTTP layer can do partial-content arithmetic.
type ChunkReader struct {
	d           *dht.DHT
	manifest    *FileManifest
	manifestKey dht.NodeID

	pos int64 // current read position in the logical file

	// One-chunk cache: many readers go sequentially through a file,
	// so a single-slot cache is plenty. Random-access (Range) callers
	// pay the refetch cost when they jump.
	cachedIdx   int    // -1 means no chunk cached
	cachedChunk []byte
}

// NewChunkReader fetches the manifest at manifestKey and returns a
// reader positioned at offset 0. The chunk data itself is NOT fetched
// up front -- it's pulled on demand as the caller Reads/Seeks.
func NewChunkReader(d *dht.DHT, manifestKey dht.NodeID) (*ChunkReader, error) {
	blob, err := d.Get(manifestKey)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	manifest, err := UnmarshalFileManifest(blob)
	if err != nil {
		return nil, err
	}
	return &ChunkReader{
		d:           d,
		manifest:    manifest,
		manifestKey: manifestKey,
		cachedIdx:   -1,
	}, nil
}

// Size returns the total file size in bytes from the manifest.
func (cr *ChunkReader) Size() int64 { return cr.manifest.Size }

// Read fills p with file bytes starting at the current position.
// Returns io.EOF once we've passed the end of the file. A single
// Read may return fewer bytes than requested if the requested range
// crosses a chunk boundary -- caller is expected to loop or use
// io.ReadFull / io.Copy if they need exact byte counts.
func (cr *ChunkReader) Read(p []byte) (int, error) {
	if cr.pos >= cr.manifest.Size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	chunkIdx := int(cr.pos / int64(ChunkSize))
	chunkOffset := int(cr.pos % int64(ChunkSize))

	chunk, err := cr.fetchChunk(chunkIdx)
	if err != nil {
		return 0, err
	}
	if chunkOffset >= len(chunk) {
		// Should not happen with a well-formed manifest, but guard
		// against an out-of-range chunk.
		return 0, fmt.Errorf("file: chunk %d shorter than expected (offset %d, len %d)",
			chunkIdx, chunkOffset, len(chunk))
	}

	n := copy(p, chunk[chunkOffset:])
	cr.pos += int64(n)
	return n, nil
}

// Seek implements io.Seeker for http.ServeContent's range/length
// arithmetic. Position past the end of the file is allowed (next Read
// returns io.EOF) but a negative position is not.
func (cr *ChunkReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = cr.pos + offset
	case io.SeekEnd:
		newPos = cr.manifest.Size + offset
	default:
		return 0, errors.New("file: bad whence")
	}
	if newPos < 0 {
		return 0, errors.New("file: negative position")
	}
	cr.pos = newPos
	return newPos, nil
}

// fetchChunk returns the chunk at index idx, using the one-slot cache
// to avoid refetching if we just read this chunk.
func (cr *ChunkReader) fetchChunk(idx int) ([]byte, error) {
	if idx == cr.cachedIdx && cr.cachedChunk != nil {
		return cr.cachedChunk, nil
	}
	if idx < 0 || idx >= len(cr.manifest.Chunks) {
		return nil, fmt.Errorf("file: chunk index %d out of range (have %d)",
			idx, len(cr.manifest.Chunks))
	}
	key, err := dht.IDFromHex(cr.manifest.Chunks[idx])
	if err != nil {
		return nil, fmt.Errorf("file: bad chunk key at %d: %w", idx, err)
	}
	data, err := cr.d.Get(key)
	if err != nil {
		return nil, fmt.Errorf("fetch chunk %d (%s): %w", idx, cr.manifest.Chunks[idx][:8], err)
	}
	cr.cachedIdx = idx
	cr.cachedChunk = data
	return data, nil
}
