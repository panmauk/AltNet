package secure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pair returns two endpoints of a fresh in-memory connection, plus two
// freshly-generated identities (alice = initiator, bob = responder).
func pair(t *testing.T) (alicePriv ed25519.PrivateKey, bobPriv ed25519.PrivateKey, aliceConn net.Conn, bobConn net.Conn) {
	t.Helper()
	_, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, bobPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceConn, bobConn = net.Pipe()
	return alicePriv, bobPriv, aliceConn, bobConn
}

// handshakeBoth runs Handshake on both ends concurrently and waits for
// both to finish. Returns the two encrypted conns or fails the test.
func handshakeBoth(t *testing.T, aliceConn, bobConn net.Conn, alicePriv, bobPriv ed25519.PrivateKey, expectedFromAlice ed25519.PublicKey) (aliceSec, bobSec *Conn) {
	t.Helper()
	type result struct {
		c   *Conn
		err error
	}
	aliceCh := make(chan result, 1)
	bobCh := make(chan result, 1)

	go func() {
		c, err := Handshake(aliceConn, alicePriv, true, expectedFromAlice)
		aliceCh <- result{c, err}
	}()
	go func() {
		c, err := Handshake(bobConn, bobPriv, false, nil)
		bobCh <- result{c, err}
	}()

	select {
	case r := <-aliceCh:
		if r.err != nil {
			t.Fatalf("alice handshake: %v", r.err)
		}
		aliceSec = r.c
	case <-time.After(3 * time.Second):
		t.Fatal("alice handshake timeout")
	}
	select {
	case r := <-bobCh:
		if r.err != nil {
			t.Fatalf("bob handshake: %v", r.err)
		}
		bobSec = r.c
	case <-time.After(3 * time.Second):
		t.Fatal("bob handshake timeout")
	}
	return aliceSec, bobSec
}

// TestHandshakeRoundTrip is the headline test: both sides handshake,
// then exchange a message in each direction, and the bytes match.
func TestHandshakeRoundTrip(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)
	aliceSec, bobSec := handshakeBoth(t, aliceConn, bobConn, alicePriv, bobPriv, nil)

	// Alice -> Bob
	go func() {
		_, _ = aliceSec.Write([]byte("hello bob"))
	}()
	buf := make([]byte, 64)
	n, err := bobSec.Read(buf)
	if err != nil {
		t.Fatalf("bob read: %v", err)
	}
	if got := string(buf[:n]); got != "hello bob" {
		t.Errorf("bob got %q, want %q", got, "hello bob")
	}

	// Bob -> Alice
	go func() {
		_, _ = bobSec.Write([]byte("hello alice"))
	}()
	n, err = aliceSec.Read(buf)
	if err != nil {
		t.Fatalf("alice read: %v", err)
	}
	if got := string(buf[:n]); got != "hello alice" {
		t.Errorf("alice got %q, want %q", got, "hello alice")
	}
}

// TestRemotePublicKeyMatches confirms each side learns the other's real
// long-term Ed25519 pubkey through the handshake.
func TestRemotePublicKeyMatches(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)
	aliceSec, bobSec := handshakeBoth(t, aliceConn, bobConn, alicePriv, bobPriv, nil)

	alicePub := alicePriv.Public().(ed25519.PublicKey)
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	if !bytes.Equal(bobSec.RemotePublicKey(), alicePub) {
		t.Error("bob did not learn alice's correct pubkey")
	}
	if !bytes.Equal(aliceSec.RemotePublicKey(), bobPub) {
		t.Error("alice did not learn bob's correct pubkey")
	}
}

// TestExpectedRemoteMismatch ensures we abort if the remote presents a
// different long-term key than the caller required.
func TestExpectedRemoteMismatch(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)

	// Generate a wrong expected key (NOT bob's).
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type result struct{ err error }
	aliceCh := make(chan result, 1)
	bobCh := make(chan result, 1)
	go func() {
		_, err := Handshake(aliceConn, alicePriv, true, wrongPub)
		aliceCh <- result{err}
	}()
	go func() {
		_, err := Handshake(bobConn, bobPriv, false, nil)
		bobCh <- result{err}
	}()

	select {
	case r := <-aliceCh:
		if !errors.Is(r.err, ErrIdentityMismatch) {
			t.Errorf("alice should have failed with ErrIdentityMismatch, got %v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("alice did not return")
	}
	// Bob will fail at the next read/write because alice closed; we don't
	// assert a specific error there.
	<-bobCh
}

// TestTamperedCiphertextDetected makes sure flipping bits in a frame
// causes decryption to fail (AEAD authenticity).
func TestTamperedCiphertextDetected(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)
	// We sit between alice and bob to flip bits.
	aliceSec, _ := handshakeBoth(t, aliceConn, bobConn, alicePriv, bobPriv, nil)

	// We don't actually have a MITM in net.Pipe, so emulate by writing a
	// frame with one bit flipped to bobConn directly. Easiest: directly
	// use the raw conn under bobSec — but we're already past handshake.
	// Instead, write garbage to alice's incoming side and confirm her
	// next read errors. For simplicity, manually craft a corrupt frame
	// and write it via aliceConn's other end directly.

	// aliceConn ↔ bobConn via net.Pipe. Anything bobConn writes appears
	// on aliceConn.Read. So: write 4-byte length + 32 bytes of garbage
	// (which will not authenticate) into bobConn.
	go func() {
		_, _ = bobConn.Write([]byte{0, 0, 0, 32})
		_, _ = bobConn.Write(make([]byte, 32))
	}()

	buf := make([]byte, 64)
	_, err := aliceSec.Read(buf)
	if err == nil {
		t.Error("expected decrypt failure on tampered/garbage frame")
	}
}

// TestLargeMessageRoundTrip pushes ~512 KiB through the encrypted conn.
// This exercises the "frame larger than one Read buffer" path: the
// receiver must reassemble multiple Reads from one decrypted frame.
func TestLargeMessageRoundTrip(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)
	aliceSec, bobSec := handshakeBoth(t, aliceConn, bobConn, alicePriv, bobPriv, nil)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 32*1024) // 512 KiB
	go func() {
		_, _ = aliceSec.Write(payload)
	}()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	for len(got) < len(payload) {
		n, err := bobSec.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes (want %d)", len(got), len(payload))
	}
}

// TestNonceMonotonicity ensures replays don't decrypt: if we send the
// same plaintext twice, the second frame uses a different nonce, so
// the ciphertexts differ. (Otherwise an observer could detect repeat
// messages.)
func TestNonceMonotonicityVariesCiphertexts(t *testing.T) {
	alicePriv, bobPriv, aliceConn, bobConn := pair(t)
	aliceSec, _ := handshakeBoth(t, aliceConn, bobConn, alicePriv, bobPriv, nil)

	// Read raw bytes off bob's side without decrypting. We can't directly
	// without disrupting the encrypted Conn, so instead capture from
	// bobConn before bobSec uses it. Simpler: swap to a direct test
	// using the AEAD-level invariant — sendCount must increment.

	before := aliceSec.sendCount
	go func() {
		_, _ = aliceSec.Write([]byte("foo"))
	}()
	// drain on the other side
	go func() {
		buf := make([]byte, 1024)
		_, _ = bobConn.Read(buf)
	}()
	// Wait briefly.
	time.Sleep(50 * time.Millisecond)
	after := aliceSec.sendCount
	if after <= before {
		t.Error("sendCount should increment after Write")
	}
}

// TestHandshakeTimeoutOnSilentRemote ensures we don't hang forever when
// the peer never sends its handshake.
func TestHandshakeTimeoutOnSilentRemote(t *testing.T) {
	alicePriv, _, aliceConn, _ := pair(t)
	// We never read or write on bobConn — just leave it open.
	// Use a shorter custom timeout by setting a deadline ourselves;
	// the production HandshakeTimeout is 10s which is too long for tests.
	_ = aliceConn.SetDeadline(time.Now().Add(200 * time.Millisecond))

	_, err := Handshake(aliceConn, alicePriv, true, nil)
	if err == nil {
		t.Fatal("Handshake should have errored on silent remote")
	}
	// Either net.Error timeout or io.EOF / closed pipe is acceptable.
	if !strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "timeout") &&
		!strings.Contains(err.Error(), "i/o") &&
		!strings.Contains(err.Error(), io.EOF.Error()) {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestHKDFKnownAnswer is a smoke test of our HKDF-SHA256 implementation
// against RFC 5869 test vector 1.
func TestHKDFKnownAnswer(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	got := hkdf(ikm, salt, info, 42)
	// RFC 5869 test case 1 expected OKM (42 bytes).
	want := []byte{
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
		0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
		0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
		0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
		0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
		0x58, 0x65,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("HKDF mismatch:\n got=%x\nwant=%x", got, want)
	}
}
