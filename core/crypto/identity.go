// Package crypto provides cryptographic identity for peers.
//
// Each peer is identified by an Ed25519 keypair. The peer's ID is the
// SHA-256 hash of its public key. This means:
//
//   - You cannot fake an identity: only the holder of the private key can
//     produce signatures that verify against the public key.
//   - The ID is deterministic: same key, same ID, forever.
//   - The public key is sufficient to verify someone's identity, but you
//     never need to share the private key.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyExportPrefix tags a key string so users can recognise one. A
// version suffix (-1) lets us evolve the export format without
// confusing old strings for new ones.
const KeyExportPrefix = "altnet-key-1:"

// Identity is a peer's cryptographic identity: the keypair plus the derived ID.
type Identity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// NewIdentity creates a fresh random identity.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// ID returns the peer ID, which is the SHA-256 hash of the public key
// encoded as a lowercase hex string.
func (id *Identity) ID() string {
	return PublicKeyToID(id.PublicKey)
}

// ShortID returns the first 8 characters of the ID for readable logs.
func (id *Identity) ShortID() string {
	full := id.ID()
	if len(full) <= 8 {
		return full
	}
	return full[:8]
}

// PublicKeyToID derives the peer ID from a public key.
// This is the canonical mapping: anyone with the public key can compute
// the same ID, but no one can compute a public key from an ID.
func PublicKeyToID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// Save writes the private key to a file. The file is created with mode 0600
// (owner read/write only) on platforms that honor unix permissions.
//
// IMPORTANT: this is a private key. If someone gets this file they can
// impersonate this peer. Keep it secret. Real production code would
// encrypt this at rest with a passphrase.
func (id *Identity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	// We persist the private key; the public key is the second half of it.
	data := []byte(hex.EncodeToString(id.PrivateKey))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// Load reads a private key from disk and reconstructs the identity.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	raw, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: %d, want %d", len(raw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(raw)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive public key: unexpected type")
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// Export returns a portable, human-pasteable string encoding of this
// identity's private key. The format is:
//
//	altnet-key-1:<base64(seed || sha256(seed)[0:4])>
//
// Where `seed` is the 32-byte Ed25519 seed (the canonical secret),
// and the 4-byte checksum lets a human catch typos when transcribing.
//
// Anyone holding this string can impersonate this peer. It's the
// "your domain rides on this" piece -- treat it like a password
// manager entry. The AltNet app's UX should display it once with a
// copy-button and a "save this" warning.
//
// Mirrors what crypto wallets do (BIP39 mnemonic / xprv) but stays
// stdlib-only.
func (id *Identity) Export() string {
	seed := id.PrivateKey.Seed()
	sum := sha256.Sum256(seed)
	body := make([]byte, 0, 32+4)
	body = append(body, seed...)
	body = append(body, sum[:4]...)
	return KeyExportPrefix + base64.RawStdEncoding.EncodeToString(body)
}

// ImportKey parses the string returned by Export and reconstructs the
// identity. Returns an error if the prefix is wrong, the base64 is
// malformed, the length is wrong, or the checksum doesn't match
// (which catches typos / paste corruption).
func ImportKey(s string) (*Identity, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, KeyExportPrefix) {
		return nil, fmt.Errorf("not an altnet key export (expected prefix %q)", KeyExportPrefix)
	}
	body, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, KeyExportPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode key string: %w", err)
	}
	if len(body) != 32+4 {
		return nil, fmt.Errorf("key body wrong length: %d (want 36)", len(body))
	}
	seed := body[:32]
	gotSum := body[32:36]
	wantSum := sha256.Sum256(seed)
	if !bytes.Equal(gotSum, wantSum[:4]) {
		return nil, errors.New("key checksum mismatch -- key string is corrupted or mistyped")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derive public key: unexpected type")
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// LoadOrCreate loads an identity from disk if it exists, otherwise creates
// a fresh one and saves it. This is the typical entry point for a node.
func LoadOrCreate(path string) (*Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	}
	id, err := NewIdentity()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, err
	}
	return id, nil
}
