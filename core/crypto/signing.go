package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// ErrBadSignature means a signature did not verify against the claimed public key.
var ErrBadSignature = errors.New("crypto: bad signature")

// Sign produces an Ed25519 signature over data using id's private key.
// Returns the signature as a hex string for easy embedding in JSON messages.
func (id *Identity) Sign(data []byte) string {
	sig := ed25519.Sign(id.PrivateKey, data)
	return hex.EncodeToString(sig)
}

// Verify checks that sigHex is a valid Ed25519 signature over data
// produced by the holder of pub. Returns nil on success, ErrBadSignature on failure.
func Verify(pub ed25519.PublicKey, data []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}

// PublicKeyFromHex parses a hex-encoded Ed25519 public key.
func PublicKeyFromHex(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("crypto: invalid public key size")
	}
	return ed25519.PublicKey(raw), nil
}

// PublicKeyToHex encodes an Ed25519 public key as hex for transmission.
func PublicKeyToHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}
