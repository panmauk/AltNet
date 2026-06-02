// Package files implements a thin file-system layer on top of the DHT.
//
// Files are split into fixed-size chunks. Each chunk is stored under its
// own SHA-256 (content-addressed) so identical chunks are deduplicated
// across the network. A FileManifest lists the chunk hashes and is itself
// stored in the DHT. A Directory lists path -> file-manifest-hash and is
// also stored in the DHT -- its own hash is the "root" for an entire
// folder tree.
//
// Three layers of hashing, each verified on retrieval:
//
//	root hash -> Directory{ entries: [{path, manifest_hash}, ...] }
//	manifest hash -> FileManifest{ size, chunks: [chunk_hash, ...] }
//	chunk hash -> raw bytes
package files

import (
	"encoding/json"
	"errors"
	"fmt"

	"altnet/core/dht"
)

// ChunkSize is the maximum bytes in one chunk. We pick a value comfortably
// below dht.MaxValueSize to leave room for JSON+base64 overhead of the
// store payload. 64 KiB raw bytes -> ~85 KiB base64 -> ~86 KiB on the wire,
// well under the 1 MiB message cap.
const ChunkSize = 64 * 1024

// FileManifest describes the chunks that make up a single file.
//
// It is stored in the DHT as a JSON value; its own SHA-256 (when serialized
// canonically) is the "manifest hash" that you reference from a Directory.
type FileManifest struct {
	Size   int64    `json:"size"`   // total file size in bytes
	Chunks []string `json:"chunks"` // hex SHA-256 of each chunk, in order
}

// Marshal produces the canonical JSON representation of the manifest.
// Use ContentAddress(Marshal(...)) to compute the manifest's DHT key.
func (m *FileManifest) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalFileManifest parses a manifest blob retrieved from the DHT.
func UnmarshalFileManifest(data []byte) (*FileManifest, error) {
	var m FileManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("file manifest: %w", err)
	}
	return &m, nil
}

// PublishBytes splits data into ChunkSize-sized pieces, stores each chunk
// in the DHT under its own content hash, and returns a manifest describing
// the file. The manifest itself is NOT stored here -- the caller stores it
// (typically as part of building a Directory).
//
// Returns the manifest and the manifest's content key (so callers can
// either store-and-forget or build it into a higher-level manifest).
func PublishBytes(d *dht.DHT, data []byte) (*FileManifest, dht.NodeID, error) {
	manifest := &FileManifest{
		Size:   int64(len(data)),
		Chunks: make([]string, 0, (len(data)+ChunkSize-1)/ChunkSize),
	}

	for offset := 0; offset < len(data); offset += ChunkSize {
		end := offset + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		key := dht.ContentAddress(chunk)
		if _, err := d.Store(key, chunk); err != nil {
			return nil, dht.NodeID{}, fmt.Errorf("store chunk %d: %w", offset/ChunkSize, err)
		}
		manifest.Chunks = append(manifest.Chunks, key.Hex())
	}

	manifestBlob, err := manifest.Marshal()
	if err != nil {
		return nil, dht.NodeID{}, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestKey := dht.ContentAddress(manifestBlob)
	if _, err := d.Store(manifestKey, manifestBlob); err != nil {
		return nil, dht.NodeID{}, fmt.Errorf("store manifest: %w", err)
	}
	return manifest, manifestKey, nil
}

// FetchBytes retrieves the manifest at manifestKey, then fetches every
// chunk it points to, reassembles them in order, and returns the full
// file bytes. Every chunk and the manifest are content-verified by the
// DHT layer (hash(value) must equal requested key) so the result cannot
// have been tampered with.
func FetchBytes(d *dht.DHT, manifestKey dht.NodeID) ([]byte, error) {
	manifestBlob, err := d.Get(manifestKey)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := UnmarshalFileManifest(manifestBlob)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, m.Size)
	for i, hexKey := range m.Chunks {
		key, err := dht.IDFromHex(hexKey)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: bad key %q: %w", i, hexKey, err)
		}
		chunk, err := d.Get(key)
		if err != nil {
			return nil, fmt.Errorf("fetch chunk %d (%s): %w", i, hexKey[:8], err)
		}
		out = append(out, chunk...)
	}

	if int64(len(out)) != m.Size {
		return nil, errors.New("file: reassembled size does not match manifest")
	}
	return out, nil
}
