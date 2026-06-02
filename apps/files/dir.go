package files

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"altnet/core/dht"
)

// DirEntry describes one file inside a published directory.
type DirEntry struct {
	Path        string `json:"path"`         // forward-slash separated, relative to the directory root
	Size        int64  `json:"size"`         // file size in bytes (also in the manifest, kept here for listing)
	ManifestKey string `json:"manifest_key"` // hex key of the file's FileManifest in the DHT
}

// Directory is the top-level record for a published folder.
//
// It is stored in the DHT as a JSON value. Its own SHA-256 is the "root
// hash" -- the single piece of information you share to make a directory
// retrievable, e.g. "fetch <root>".
type Directory struct {
	Entries []DirEntry `json:"entries"`
}

// Marshal returns the canonical JSON. Use ContentAddress(Marshal(...))
// to compute the root key for the directory.
func (d *Directory) Marshal() ([]byte, error) {
	return json.Marshal(d)
}

// UnmarshalDirectory parses a directory blob retrieved from the DHT.
func UnmarshalDirectory(data []byte) (*Directory, error) {
	var dir Directory
	if err := json.Unmarshal(data, &dir); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	return &dir, nil
}

// PublishDir walks rootPath, publishes every regular file as chunks +
// manifest, builds a Directory record, stores it, and returns the
// directory's content key (the "root hash").
//
// Symlinks, devices, sockets etc. are skipped silently. Hidden files (those
// whose name starts with ".") are included -- the caller can pre-filter if
// they want a different policy.
func PublishDir(d *dht.DHT, rootPath string) (dht.NodeID, *Directory, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return dht.NodeID{}, nil, fmt.Errorf("stat %s: %w", rootPath, err)
	}
	if !info.IsDir() {
		return dht.NodeID{}, nil, fmt.Errorf("%s is not a directory", rootPath)
	}

	dir := &Directory{}

	walkErr := filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}
		// Always use forward slashes in the manifest so the format is
		// platform-independent.
		rel = filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		manifest, key, err := PublishBytes(d, data)
		if err != nil {
			return fmt.Errorf("publish %s: %w", rel, err)
		}
		dir.Entries = append(dir.Entries, DirEntry{
			Path:        rel,
			Size:        manifest.Size,
			ManifestKey: key.Hex(),
		})
		return nil
	})
	if walkErr != nil {
		return dht.NodeID{}, nil, walkErr
	}

	// Sort entries by path so the JSON is deterministic -- same set of
	// files produces the same root hash regardless of walk order.
	sort.Slice(dir.Entries, func(i, j int) bool {
		return dir.Entries[i].Path < dir.Entries[j].Path
	})

	blob, err := dir.Marshal()
	if err != nil {
		return dht.NodeID{}, nil, fmt.Errorf("marshal directory: %w", err)
	}
	rootKey := dht.ContentAddress(blob)
	if _, err := d.Store(rootKey, blob); err != nil {
		return dht.NodeID{}, nil, fmt.Errorf("store directory: %w", err)
	}
	return rootKey, dir, nil
}

// FetchDir given a root hash and a destination directory, retrieves the
// directory record, then fetches every file's manifest and chunks, and
// writes the files out to dest. Subdirectories implied by file paths are
// created as needed. Existing files in dest are overwritten.
//
// dest will be created if it does not exist; it must not be a regular file.
func FetchDir(d *dht.DHT, rootKey dht.NodeID, dest string) (*Directory, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir dest: %w", err)
	}

	blob, err := d.Get(rootKey)
	if err != nil {
		return nil, fmt.Errorf("fetch directory: %w", err)
	}
	dir, err := UnmarshalDirectory(blob)
	if err != nil {
		return nil, err
	}

	for _, entry := range dir.Entries {
		// Refuse path traversal: an attacker could publish a directory
		// with "../../etc/passwd" as a path. Reject anything that escapes.
		if strings.Contains(entry.Path, "..") || strings.HasPrefix(entry.Path, "/") {
			return nil, fmt.Errorf("unsafe path in directory: %q", entry.Path)
		}
		manifestKey, err := dht.IDFromHex(entry.ManifestKey)
		if err != nil {
			return nil, fmt.Errorf("bad manifest key for %s: %w", entry.Path, err)
		}
		data, err := FetchBytes(d, manifestKey)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", entry.Path, err)
		}
		if int64(len(data)) != entry.Size {
			return nil, fmt.Errorf("size mismatch on %s: got %d want %d",
				entry.Path, len(data), entry.Size)
		}

		full := filepath.Join(dest, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", full, err)
		}
	}
	return dir, nil
}

// Sentinel error: nothing currently triggers it directly but we expose it
// so callers can match on "directory not found in DHT".
var ErrEmptyDirectory = errors.New("files: directory has no entries")
