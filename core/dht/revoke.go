package dht

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"altnet/core/crypto"
	"altnet/core/peer"
)

// randRead fills b with cryptographic random bytes. Wrapped so we can
// stub it in tests.
var randRead = func(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}

// RevokePayload is the on-wire JSON of a dht_revoke message. It is
// signed by a key listed in the local trusted-revokers config; any
// node receiving a revoke verifies the signature before honouring it.
//
// Wire format:
//
//	{
//	  "name":       "panmox.alt",
//	  "chunks":     ["aabbcc...", "..."],   // SHA-256 hashes (hex), one per chunk
//	  "timestamp":  1779392691,             // unix seconds, replay protection
//	  "nonce":      "1f3c5d9a...",          // 16 random hex bytes, replay protection
//	  "pubkey":     "...",                  // signer's Ed25519 public key (hex)
//	  "signature":  "..."                   // signature over canonical encoding of the above
//	}
//
// Canonical signed bytes (what we feed to Ed25519 verify):
//
//	"revoke\n" + name + "\n" + sorted-chunks-joined-by-newline + "\n"
//	+ ts-as-decimal-string + "\n" + nonce
//
// Sorting the chunk list makes the signed bytes independent of slice
// ordering, so a re-broadcast where chunks happen to be in a different
// order still verifies.
type RevokePayload struct {
	Name      string   `json:"name"`
	Chunks    []string `json:"chunks"`
	Timestamp int64    `json:"timestamp"`
	Nonce     string   `json:"nonce"`
	PublicKey string   `json:"pubkey"`
	Signature string   `json:"signature"`
}

// MaxRevokeAge bounds how old a revoke timestamp can be when received.
// Anything older is dropped — combined with the nonce dedup this kills
// most replay attacks. A legitimate admin re-broadcast within this
// window stays valid (so an admin can re-issue if propagation stalls).
const MaxRevokeAge = 24 * time.Hour

// MaxRevokeFutureSkew tolerates clocks slightly ahead. Records dated
// more than this in the future are dropped.
const MaxRevokeFutureSkew = 5 * time.Minute

// RevokeCanonical returns the byte string that gets signed/verified.
// Public so test code and the admin signing path use the same bytes.
func RevokeCanonical(name string, chunks []string, timestamp int64, nonce string) []byte {
	// Sort chunks so signed bytes don't depend on slice order.
	sorted := append([]string(nil), chunks...)
	for i := range sorted {
		sorted[i] = strings.ToLower(strings.TrimSpace(sorted[i]))
	}
	sort.Strings(sorted)
	var b strings.Builder
	b.WriteString("revoke\n")
	b.WriteString(strings.ToLower(strings.TrimSpace(name)))
	b.WriteByte('\n')
	b.WriteString(strings.Join(sorted, "\n"))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%d", timestamp)
	b.WriteByte('\n')
	b.WriteString(nonce)
	return []byte(b.String())
}

// revokeID is the deduplication key for "have we already applied this
// revoke?" — independent of slice order, since the signed bytes are.
func revokeID(p *RevokePayload) string {
	h := sha256.Sum256(RevokeCanonical(p.Name, p.Chunks, p.Timestamp, p.Nonce))
	return hex.EncodeToString(h[:])
}

// SignRevoke builds a signed RevokePayload. Used by the registrar's
// admin endpoint when an abuse report is decided "revoke". Generates
// a fresh nonce and stamps the current time.
func SignRevoke(id *crypto.Identity, name string, chunks []string) (*RevokePayload, error) {
	if id == nil {
		return nil, errors.New("revoke: nil identity")
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("revoke: name required")
	}
	nonceBytes := make([]byte, 16)
	if _, err := randRead(nonceBytes); err != nil {
		return nil, fmt.Errorf("revoke: nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	ts := time.Now().Unix()
	sig := id.Sign(RevokeCanonical(name, chunks, ts, nonce))
	// Normalise stored chunks the same way RevokeCanonical normalises
	// the signed bytes, so the persisted record matches what we signed.
	normChunks := make([]string, 0, len(chunks))
	for _, c := range chunks {
		normChunks = append(normChunks, strings.ToLower(strings.TrimSpace(c)))
	}
	sort.Strings(normChunks)
	return &RevokePayload{
		Name:      strings.ToLower(strings.TrimSpace(name)),
		Chunks:    normChunks,
		Timestamp: ts,
		Nonce:     nonce,
		PublicKey: crypto.PublicKeyToHex(id.PublicKey),
		Signature: sig,
	}, nil
}

// TrustedRevokers is a set of Ed25519 public keys whose revokes the
// local node honours. Anything else is silently dropped before the
// signature is even checked.
//
// Operators populate this from a config file (data/trusted-revokers.txt,
// one hex pubkey per line) and/or from a baked-in default list.
type TrustedRevokers struct {
	mu   sync.RWMutex
	keys map[string]struct{} // hex pubkey
}

// NewTrustedRevokers returns an empty set. The zero value is safe to
// use; every Contains returns false.
func NewTrustedRevokers() *TrustedRevokers {
	return &TrustedRevokers{keys: make(map[string]struct{})}
}

// Add inserts a hex pubkey into the trusted set. Returns true if it
// was new.
func (t *TrustedRevokers) Add(hexKey string) bool {
	if t == nil {
		return false
	}
	hexKey = strings.ToLower(strings.TrimSpace(hexKey))
	if _, err := crypto.PublicKeyFromHex(hexKey); err != nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.keys == nil {
		t.keys = make(map[string]struct{})
	}
	if _, ok := t.keys[hexKey]; ok {
		return false
	}
	t.keys[hexKey] = struct{}{}
	return true
}

// Contains reports whether hexKey is in the trusted set.
func (t *TrustedRevokers) Contains(hexKey string) bool {
	if t == nil {
		return false
	}
	hexKey = strings.ToLower(strings.TrimSpace(hexKey))
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.keys[hexKey]
	return ok
}

// Size returns the number of trusted keys.
func (t *TrustedRevokers) Size() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.keys)
}

// SetTrustedRevokers installs the set of trusted revoker pubkeys on
// the DHT. Idempotent. Set to nil to disable revoke processing.
func (d *DHT) SetTrustedRevokers(t *TrustedRevokers) {
	d.trustedRevokers = t
}

// applyRevoke applies a verified revoke locally: deletes the listed
// chunks from the local store and adds them to the in-memory
// blocklist so they can't be re-accepted.
func (d *DHT) applyRevoke(p *RevokePayload) {
	// Ensure we have a blocklist to add to. If the operator never
	// configured one, install an empty one now so revoke-driven
	// blocking still works for the life of this process.
	if d.blocklist == nil {
		d.blocklist = NewBlocklist()
	}
	for _, hexHash := range p.Chunks {
		id, err := IDFromHex(hexHash)
		if err != nil {
			continue
		}
		d.blocklist.Add(id)
		d.store.Delete(id)
	}
}

// handleRevoke validates an incoming dht_revoke and, on success,
// applies it locally and forwards it to our K closest peers (per
// chunk hash) to propagate across the network.
func (d *DHT) handleRevoke(p *peer.Peer, addr string, msg peer.Message) {
	if d.trustedRevokers == nil || d.trustedRevokers.Size() == 0 {
		return // node didn't opt into trusting any revoker — drop silently
	}
	var rp RevokePayload
	if err := json.Unmarshal([]byte(msg.Payload), &rp); err != nil {
		return
	}
	fmt.Printf("[revoke] RX dht_revoke name=%s pk=%s from=%s trusted=%v\n",
		rp.Name, rp.PublicKey, addr, d.trustedRevokers.Contains(rp.PublicKey))
	if !d.trustedRevokers.Contains(rp.PublicKey) {
		return
	}
	now := time.Now().Unix()
	if rp.Timestamp < now-int64(MaxRevokeAge.Seconds()) {
		return // too old
	}
	if rp.Timestamp > now+int64(MaxRevokeFutureSkew.Seconds()) {
		return // too far in the future
	}
	pub, err := crypto.PublicKeyFromHex(rp.PublicKey)
	if err != nil {
		return
	}
	if err := crypto.Verify(pub, RevokeCanonical(rp.Name, rp.Chunks, rp.Timestamp, rp.Nonce), rp.Signature); err != nil {
		return
	}
	// Replay dedup: have we already seen this exact revoke? If so,
	// stop here so we don't loop forever in the propagation gossip.
	rid := revokeID(&rp)
	d.revokeSeenMu.Lock()
	if d.revokeSeen == nil {
		d.revokeSeen = make(map[string]time.Time)
	}
	if _, dup := d.revokeSeen[rid]; dup {
		d.revokeSeenMu.Unlock()
		return
	}
	d.revokeSeen[rid] = time.Now()
	// Lazily evict revoke IDs older than 2 * MaxRevokeAge so the map
	// can't grow unbounded.
	if len(d.revokeSeen) > 1024 {
		cutoff := time.Now().Add(-2 * MaxRevokeAge)
		for k, t := range d.revokeSeen {
			if t.Before(cutoff) {
				delete(d.revokeSeen, k)
			}
		}
	}
	d.revokeSeenMu.Unlock()

	d.applyRevoke(&rp)
	fmt.Printf("[revoke] applied %s, purged %d chunk(s) locally\n", rp.Name, len(rp.Chunks))
	// Forward to our K closest peers for each chunk. Cheap because
	// the peer layer dedups outgoing connections and the receivers
	// will dedup on the same revokeID we just minted.
	d.gossipRevoke(addr, msg)
}

// gossipRevoke forwards a revoke message to every peer we have a LIVE
// connection to, pushing over the existing socket rather than dialing
// addresses from the routing table.
//
// Why not dial: most nodes are NAT'd home PCs that connect outbound to
// the seed and advertise unreachable addresses (127.0.0.1, RFC-1918,
// relay). Dialing those back fails, so a routing-table gossip never
// reaches the very nodes that hold the content. Pushing over the live
// connection works in both directions. The peer we received it from
// gets an echo too, but it (and everyone) drops duplicates via the
// revokeSeen dedup, so the flood terminates. fromAddr is unused now but
// kept for call-site compatibility.
func (d *DHT) gossipRevoke(fromAddr string, msg peer.Message) {
	_ = fromAddr
	if d.p != nil {
		d.p.Broadcast(msg)
	}
}

// BroadcastRevoke is the local-side entry point: takes a freshly
// signed payload, applies it locally, and gossips it out. Used by
// the registrar admin path after signing.
func (d *DHT) BroadcastRevoke(p *RevokePayload) {
	if p == nil {
		return
	}
	d.applyRevoke(p)
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	n := 0
	if d.p != nil {
		n = d.p.PeerCount()
	}
	fmt.Printf("[revoke] broadcasting %s (%d chunks) over %d live peer(s)\n", p.Name, len(p.Chunks), n)
	d.gossipRevoke("", peer.Message{Type: "dht_revoke", Payload: string(body)})
}
