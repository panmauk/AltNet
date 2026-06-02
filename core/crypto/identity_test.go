package crypto

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestIDIsDeterministic(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.ID() != id.ID() {
		t.Fatal("ID() should be deterministic")
	}
	if id.ID() != PublicKeyToID(id.PublicKey) {
		t.Fatal("ID() should equal PublicKeyToID(PublicKey)")
	}
}

func TestSignAndVerify(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello peer")
	sig := id.Sign(msg)
	if err := Verify(id.PublicKey, msg, sig); err != nil {
		t.Fatalf("legitimate signature should verify: %v", err)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	id, _ := NewIdentity()
	sig := id.Sign([]byte("original"))
	if err := Verify(id.PublicKey, []byte("tampered"), sig); err == nil {
		t.Fatal("tampered message should fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	sig := idA.Sign([]byte("hi"))
	if err := Verify(idB.PublicKey, []byte("hi"), sig); err == nil {
		t.Fatal("signature should not verify under a different public key")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	original, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original.PublicKey, loaded.PublicKey) {
		t.Error("public key mismatch after load")
	}
	if !bytes.Equal(original.PrivateKey, loaded.PrivateKey) {
		t.Error("private key mismatch after load")
	}
	if original.ID() != loaded.ID() {
		t.Error("ID mismatch after load")
	}
}

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Error("LoadOrCreate should return the same identity on second call")
	}
}

// TestExportImportRoundTrip is the headline test for key portability:
// export a fresh identity, import the resulting string, and confirm
// the new Identity has the same ID and signing behavior as the original.
func TestExportImportRoundTrip(t *testing.T) {
	original, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	exported := original.Export()
	imported, err := ImportKey(exported)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	if original.ID() != imported.ID() {
		t.Errorf("imported ID = %s, want %s", imported.ID(), original.ID())
	}
	if !bytes.Equal(original.PrivateKey, imported.PrivateKey) {
		t.Error("imported private key bytes differ from original")
	}

	// Sign with the imported key, verify with the original's public
	// key. If the keys are truly the same, the signature must verify.
	sig := imported.Sign([]byte("hello"))
	if err := Verify(original.PublicKey, []byte("hello"), sig); err != nil {
		t.Errorf("signature from imported key did not verify against original: %v", err)
	}
}

// TestImportRejectsWrongPrefix: a string lacking the altnet-key-1
// prefix is not an AltNet key and must be rejected.
func TestImportRejectsWrongPrefix(t *testing.T) {
	_, err := ImportKey("ssh-ed25519 AAAA...")
	if err == nil {
		t.Error("expected error for wrong prefix")
	}
}

// TestImportRejectsCorruptedChecksum: flipping a single byte in the
// body should be caught by the checksum, so users notice paste typos
// before they end up with a wrong identity.
func TestImportRejectsCorruptedChecksum(t *testing.T) {
	id, _ := NewIdentity()
	good := id.Export()
	// Flip one character somewhere in the middle of the body.
	mid := len(good) / 2
	bad := good[:mid] + flipChar(good[mid:mid+1]) + good[mid+1:]
	if bad == good {
		t.Skip("flipChar produced same char; rerun")
	}
	_, err := ImportKey(bad)
	if err == nil {
		t.Error("expected checksum mismatch error after byte flip")
	}
}

// flipChar maps an alphanumeric char to a different one of the same
// kind so the resulting string still parses as base64 but encodes
// different bytes.
func flipChar(s string) string {
	if len(s) != 1 {
		return s
	}
	c := s[0]
	switch {
	case c >= 'a' && c < 'z':
		return string(c + 1)
	case c == 'z':
		return "a"
	case c >= 'A' && c < 'Z':
		return string(c + 1)
	case c == 'Z':
		return "A"
	case c >= '0' && c < '9':
		return string(c + 1)
	case c == '9':
		return "0"
	}
	return s
}
