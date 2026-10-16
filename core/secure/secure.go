// Package secure provides an authenticated, encrypted transport on top of
// a raw net.Conn, used by the peer layer for all peer-to-peer traffic.
//
// What it gives you:
//
//   - Confidentiality: traffic is encrypted with AES-256-GCM, so a network
//     observer can see only the framing, not the message contents.
//   - Authenticity: each frame is AEAD-tagged, so a man-in-the-middle who
//     flips even one bit will cause decryption to fail and the connection
//     to drop.
//   - Identity: a single Ed25519 handshake at the start proves to each
//     side that the peer at the other end actually owns the long-term
//     public key it claims. After that the verified key is exposed via
//     RemotePublicKey().
//   - Forward secrecy: keys are derived from a fresh X25519 ECDH every
//     connection, so capturing today's traffic and stealing a peer's
//     long-term private key tomorrow does not let you decrypt today's
//     traffic.
//
// Wire format:
//
//	HANDSHAKE (sent by each side once, in plaintext):
//	  32 bytes: long-term Ed25519 public key
//	  32 bytes: ephemeral X25519 public key
//	  64 bytes: Ed25519 signature; initiator signs eph_pub, responder
//	            signs (eph_pub || initiator_eph_pub) so its handshake is
//	            bound to the specific session it is replying to.
//
//	DATA (after handshake, every Write becomes one frame):
//	  4  bytes: big-endian uint32 ciphertext length
//	  N  bytes: AES-256-GCM ciphertext (includes 16-byte auth tag)
//
// Each direction has its own AES-256 key derived from the shared X25519
// secret. Nonces are 12-byte big-endian counters starting at 0 and
// incrementing per message -- so a replay or out-of-order frame fails
// AEAD verification.
//
// This is roughly the same shape as the Noise XK pattern, hand-rolled
// with stdlib only (no third-party crypto dependencies).
package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// HandshakeMessageSize is the fixed size of one handshake message.
	// 32 (lt pub) + 32 (eph pub) + 64 (sig) = 128 bytes.
	HandshakeMessageSize = 32 + 32 + ed25519.SignatureSize

	// MaxFrameSize caps a single encrypted frame's ciphertext length.
	// 1 MiB plaintext + 16-byte tag fits comfortably below this. Sized
	// to align with peer.MaxMessageSize.
	MaxFrameSize = (1 << 20) + 64

	// HandshakeTimeout is how long either side will wait for the peer
	// to send its handshake message before giving up.
	HandshakeTimeout = 10 * time.Second
)

// ErrIdentityMismatch is returned if the remote presents a long-term
// public key that differs from what the caller required via Handshake's
// expectedRemote argument.
var ErrIdentityMismatch = errors.New("secure: remote public key did not match expected identity")

// Conn wraps a net.Conn with authenticated encryption. It implements
// net.Conn so callers can substitute it for the underlying connection.
type Conn struct {
	raw net.Conn

	// Per-direction AEAD ciphers and counters. AEAD is created once per
	// connection because gcm Seal/Open are stateless.
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	sendCount uint64
	recvCount uint64

	remotePub ed25519.PublicKey

	writeMu sync.Mutex
	readMu  sync.Mutex

	// readBuf holds plaintext bytes that have been decrypted but not yet
	// consumed by Read. One Read may not drain a whole frame, so we
	// buffer the rest for subsequent Reads.
	readBuf bytes.Buffer
}

// RemotePublicKey returns the verified Ed25519 public key the remote
// proved ownership of during the handshake.
func (c *Conn) RemotePublicKey() ed25519.PublicKey { return c.remotePub }

// Read decrypts and returns plaintext from the next frame. If the last
// frame yielded more bytes than the caller asked for, the remainder is
// returned on subsequent Reads.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() == 0 {
		if err := c.readNextFrame(); err != nil {
			return 0, err
		}
	}
	return c.readBuf.Read(p)
}

func (c *Conn) readNextFrame() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(c.raw, lenBuf[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > MaxFrameSize {
		return fmt.Errorf("secure: invalid frame size %d", size)
	}
	ct := make([]byte, size)
	if _, err := io.ReadFull(c.raw, ct); err != nil {
		return err
	}

	nonce := nonceFor(c.recvCount)
	c.recvCount++

	pt, err := c.recvAEAD.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("secure: decrypt failed: %w", err)
	}
	c.readBuf.Write(pt)
	return nil
}

// Write encrypts p as a single frame and sends it.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	nonce := nonceFor(c.sendCount)
	c.sendCount++

	ct := c.sendAEAD.Seal(nil, nonce, p, nil)
	if len(ct) > MaxFrameSize {
		return 0, fmt.Errorf("secure: frame too large (%d bytes)", len(ct))
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))

	// Write length and ciphertext separately. We could combine, but the
	// underlying TCP socket will coalesce them into one packet anyway.
	if _, err := c.raw.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	if _, err := c.raw.Write(ct); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close shuts down the underlying connection.
func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// nonceFor returns a 12-byte big-endian nonce for the given counter.
// Both sides keep separate send/recv counters and use distinct keys
// per direction, so a counter value never produces the same (key, nonce)
// pair on both endpoints.
func nonceFor(counter uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

// --- Handshake ---

// Handshake performs the secure handshake on conn and returns an
// authenticated, encrypted Conn.
//
// myKey is the local long-term Ed25519 private key (used to sign our
// ephemeral key). isInitiator must be true for the dialer and false
// for the acceptor -- the two sides derive different send/recv keys
// based on this role.
//
// expectedRemote, if non-nil, is the long-term Ed25519 public key we
// expect the remote to own. If the remote presents a different key,
// the handshake aborts with ErrIdentityMismatch. Pass nil to accept
// any peer (typical for incoming connections and bootstrap dials
// where we don't yet know who we're talking to).
func Handshake(conn net.Conn, myKey ed25519.PrivateKey, isInitiator bool, expectedRemote ed25519.PublicKey) (*Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(HandshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{}) // clear after handshake

	// Generate our ephemeral X25519 keypair.
	curve := ecdh.X25519()
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secure: generate ephemeral: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()
	myLT := myKey.Public().(ed25519.PublicKey)

	// Build and send our handshake message. The initiator signs only its
	// own ephemeral pubkey (it doesn't know the responder's yet). The
	// responder signs (its eph || initiator's eph) which binds its
	// signature to this specific session.
	if isInitiator {
		sig := ed25519.Sign(myKey, ephPub)
		if err := writeHandshake(conn, myLT, ephPub, sig); err != nil {
			return nil, err
		}
		// Now read the responder's handshake.
		theirLT, theirEph, theirSig, err := readHandshake(conn)
		if err != nil {
			return nil, err
		}
		if expectedRemote != nil && !bytes.Equal(theirLT, expectedRemote) {
			return nil, ErrIdentityMismatch
		}
		// Verify responder's signature: signed (their_eph || our_eph).
		signedPayload := append(append([]byte{}, theirEph...), ephPub...)
		if !ed25519.Verify(theirLT, signedPayload, theirSig) {
			return nil, errors.New("secure: bad signature from responder")
		}
		return finishHandshake(conn, ephPriv, theirEph, theirLT, true)
	}

	// Responder path: read first, then reply.
	theirLT, theirEph, theirSig, err := readHandshake(conn)
	if err != nil {
		return nil, err
	}
	if expectedRemote != nil && !bytes.Equal(theirLT, expectedRemote) {
		return nil, ErrIdentityMismatch
	}
	// Verify initiator's signature: signed just their_eph.
	if !ed25519.Verify(theirLT, theirEph, theirSig) {
		return nil, errors.New("secure: bad signature from initiator")
	}
	// Sign (our eph || their eph) and reply.
	signedPayload := append(append([]byte{}, ephPub...), theirEph...)
	sig := ed25519.Sign(myKey, signedPayload)
	if err := writeHandshake(conn, myLT, ephPub, sig); err != nil {
		return nil, err
	}
	return finishHandshake(conn, ephPriv, theirEph, theirLT, false)
}

// finishHandshake performs the X25519 ECDH and key derivation, returning
// a usable encrypted Conn.
func finishHandshake(conn net.Conn, ephPriv *ecdh.PrivateKey, theirEphBytes []byte, remotePub ed25519.PublicKey, isInitiator bool) (*Conn, error) {
	curve := ecdh.X25519()
	theirEph, err := curve.NewPublicKey(theirEphBytes)
	if err != nil {
		return nil, fmt.Errorf("secure: bad remote ephemeral: %w", err)
	}
	shared, err := ephPriv.ECDH(theirEph)
	if err != nil {
		return nil, fmt.Errorf("secure: ecdh: %w", err)
	}

	// Mix the transcript (both ephemeral pubkeys, in initiator-first
	// order) into the KDF so a passive observer can't replay session
	// material across handshakes.
	myEph := ephPriv.PublicKey().Bytes()
	var transcript []byte
	if isInitiator {
		transcript = append(append([]byte{}, myEph...), theirEphBytes...)
	} else {
		transcript = append(append([]byte{}, theirEphBytes...), myEph...)
	}

	// Derive 64 bytes: first 32 = initiator->responder key,
	// second 32 = responder->initiator key.
	keys := hkdf(shared, transcript, []byte("altnet-aead-v1"), 64)
	keyI2R, keyR2I := keys[:32], keys[32:64]

	var sendKey, recvKey []byte
	if isInitiator {
		sendKey, recvKey = keyI2R, keyR2I
	} else {
		sendKey, recvKey = keyR2I, keyI2R
	}

	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	sendAEAD, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, err
	}

	return &Conn{
		raw:       conn,
		sendAEAD:  sendAEAD,
		recvAEAD:  recvAEAD,
		remotePub: remotePub,
	}, nil
}

func writeHandshake(conn net.Conn, ltPub ed25519.PublicKey, ephPub []byte, sig []byte) error {
	if len(ltPub) != ed25519.PublicKeySize {
		return errors.New("secure: bad long-term pub size")
	}
	if len(ephPub) != 32 {
		return errors.New("secure: bad ephemeral size")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("secure: bad signature size")
	}
	buf := make([]byte, 0, HandshakeMessageSize)
	buf = append(buf, ltPub...)
	buf = append(buf, ephPub...)
	buf = append(buf, sig...)
	_, err := conn.Write(buf)
	return err
}

func readHandshake(conn net.Conn) (ltPub ed25519.PublicKey, ephPub []byte, sig []byte, err error) {
	buf := make([]byte, HandshakeMessageSize)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, nil, nil, err
	}
	ltPub = ed25519.PublicKey(buf[0:32])
	ephPub = buf[32:64]
	sig = buf[64:128]
	return ltPub, ephPub, sig, nil
}

// --- HKDF (RFC 5869) over SHA-256 ---

// hkdf derives outLen bytes of pseudo-random key material from ikm,
// salted by salt and tagged with info. We implement it from stdlib's
// crypto/hmac to avoid pulling in golang.org/x/crypto/hkdf.
func hkdf(ikm, salt, info []byte, outLen int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	// Extract: PRK = HMAC-SHA256(salt, IKM)
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i)
	var out []byte
	var prev []byte
	for i := byte(1); len(out) < outLen; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:outLen]
}
