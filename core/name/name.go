// Package name implements a signed naming layer on top of the DHT.
//
// Names are domain-style, e.g. "panmox.alt". A NameRecord maps a name
// to a content root hash, signed by the registrant's private key. Anyone
// resolving the name can verify the signature against the embedded
// public key and trust that whoever published it owns the corresponding
// identity.
//
// The DHT key for a name record is sha256(canonicalize(name)) -- the value
// is a JSON NameRecord. Because the record is mutable (the owner can
// publish a new version pointing at a new root), Get is used in
// "unverified" mode (the key is not the hash of the value). Authenticity
// instead comes from verifying the embedded signature.
//
// Limitations of this first version:
//   - First-writer-wins squatting: nothing prevents two people from picking
//     the same name. The first one to STORE a record under that key takes
//     the slot until the DHT's last-writer-wins overwrites it. A real
//     system would need either a blockchain or a registration ceremony.
//   - No expiry / refresh: records persist as long as some peer still
//     holds them.
//   - Single-record only: we don't currently fetch from multiple peers
//     and pick the highest version. With fetch caching, the most recently
//     published record will spread, but there's no rollback protection.
package name

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"altnet/core/crypto"
	"altnet/core/dht"
)

// Permissioned naming.
//
// trustedRegistrars, when non-empty, restricts name resolution to records
// signed by one of these Ed25519 public keys (hex). This turns the open
// "anyone can claim a name" layer into a PERMISSIONED one: only names the
// registrar authority signed will resolve on this network — the protocol-
// level enforcement of admin approval. Empty (the default) = open mode:
// every validly-signed record is accepted. So this is backward-compatible
// and the test suite is unaffected unless it opts in.
//
// A fork that strips this list just builds a different, separate network.
var (
	trustedRegistrarsMu sync.RWMutex
	trustedRegistrars   map[string]bool
)

// SetTrustedRegistrars configures the permissioned-naming allowlist. Pass
// the raw Ed25519 public-key hex values (the same string a NameRecord's
// "pk" field carries — NOT the node ID). An empty or nil list disables
// enforcement (open mode). Call once at startup before serving.
func SetTrustedRegistrars(keys []string) {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			m[k] = true
		}
	}
	trustedRegistrarsMu.Lock()
	if len(m) == 0 {
		trustedRegistrars = nil
	} else {
		trustedRegistrars = m
	}
	trustedRegistrarsMu.Unlock()
}

// TrustedRegistrarCount reports how many authority keys are configured
// (0 = open mode). Handy for startup logging.
func TrustedRegistrarCount() int {
	trustedRegistrarsMu.RLock()
	defer trustedRegistrarsMu.RUnlock()
	return len(trustedRegistrars)
}

// registrarAllowed reports whether a record signed by pk may resolve. In
// open mode (no allowlist configured) everything is allowed.
func registrarAllowed(pk string) bool {
	trustedRegistrarsMu.RLock()
	defer trustedRegistrarsMu.RUnlock()
	if len(trustedRegistrars) == 0 {
		return true
	}
	return trustedRegistrars[strings.ToLower(strings.TrimSpace(pk))]
}

// MaxNameLen caps the human name length to keep the JSON record small
// and bound the storage cost of squatting.
const MaxNameLen = 253 // matches DNS hostname length limit

// DefaultNameTTL is how long a published NameRecord stays valid
// without the publisher re-signing it. Seven days is short enough
// that an attacker can't replay an old (now-superseded) record
// indefinitely, and long enough that a publisher who's offline for
// a few days doesn't lose their domain.
//
// Publishers (the AltNet app's registration flow) should refresh
// records ahead of expiry; the daemon's republish loop only re-stores
// records, it does not re-sign them, so a record that hits TTL
// without a fresh sign-and-publish from the owner expires.
const DefaultNameTTL int64 = 7 * 24 * 3600

// MaxClockSkew is how far in the future a record's Timestamp may be
// relative to our local clock before we reject it. Without this, an
// attacker could set Timestamp = year 3000 and the record would
// effectively never expire, defeating the whole TTL mechanism.
const MaxClockSkew = 5 * 60 // five minutes

// NameRecord is the JSON value stored in the DHT for one name registration.
type NameRecord struct {
	Name      string `json:"name"`             // e.g. "panmox.alt"
	PublicKey string `json:"pk"`               // hex Ed25519 pubkey of the registrant
	Root      string `json:"root"`             // hex content key the name points to (typically a directory)
	Version   int64  `json:"version"`          // monotonically increasing sequence number
	Timestamp int64  `json:"ts"`               // unix seconds at the time of signing
	TTL       int64  `json:"ttl,omitempty"`    // seconds after Timestamp during which this record is valid; 0 = no expiry (legacy)
	Sig       string `json:"sig,omitempty"`    // hex Ed25519 signature; computed over the JSON with Sig=""
}

// Expired reports whether this record's TTL has elapsed relative to
// the given "now" time. A record with TTL=0 is treated as
// non-expiring (used by older code paths and the test fixtures).
//
// Future-dated records (Timestamp more than MaxClockSkew seconds
// ahead of now) are also rejected: an attacker could otherwise set
// Timestamp far in the future to make the record effectively never
// expire under the TTL window.
func (r *NameRecord) Expired(now int64) bool {
	if r.Timestamp > now+MaxClockSkew {
		return true // future-dated
	}
	if r.TTL <= 0 {
		return false // permanent / legacy
	}
	return now > r.Timestamp+r.TTL
}

// CanonicalName lowercases and trims the name so cosmetic differences
// don't produce different DHT keys. Trailing dots (sometimes added by
// DNS clients) are stripped. "Panmox.alt." and "panmox.alt" resolve
// to the same record.
func CanonicalName(name string) string {
	c := strings.ToLower(strings.TrimSpace(name))
	c = strings.TrimSuffix(c, ".")
	return c
}

// RecordKey returns the DHT key under which a name's record is stored.
func RecordKey(name string) dht.NodeID {
	h := sha256.Sum256([]byte(CanonicalName(name)))
	var id dht.NodeID
	copy(id[:], h[:])
	return id
}

// validName enforces basic domain-name rules so we don't accept anything
// a DNS client would refuse to route. Lowercase letters, digits, hyphens,
// and dots only; non-empty labels; max length 253; cannot start or end
// with a hyphen or dot.
func validName(name string) error {
	c := CanonicalName(name)
	if c == "" {
		return errors.New("name is empty")
	}
	if len(c) > MaxNameLen {
		return fmt.Errorf("name too long (max %d)", MaxNameLen)
	}
	if c[0] == '.' || c[len(c)-1] == '.' {
		return errors.New("name cannot start or end with '.'")
	}
	for _, label := range strings.Split(c, ".") {
		if label == "" {
			return errors.New("empty label in name (e.g. consecutive dots)")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q too long (max 63)", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q cannot start or end with '-'", label)
		}
		for _, r := range label {
			if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return fmt.Errorf("invalid character %q in name", r)
			}
		}
	}
	return nil
}

// Sign fills in PublicKey and Sig from id. Should be called as the last
// step before storing the record.
func (r *NameRecord) Sign(id *crypto.Identity) error {
	r.PublicKey = crypto.PublicKeyToHex(id.PublicKey)
	r.Sig = ""
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	r.Sig = id.Sign(data)
	return nil
}

// Verify checks the embedded signature against the embedded public key.
// Does not check that the public key is "the rightful owner of the name"
// (we have no notion of that yet).
func (r *NameRecord) Verify() error {
	pub, err := crypto.PublicKeyFromHex(r.PublicKey)
	if err != nil {
		return fmt.Errorf("name: parse pubkey: %w", err)
	}
	sig := r.Sig
	r.Sig = ""
	data, err := json.Marshal(r)
	r.Sig = sig
	if err != nil {
		return err
	}
	return crypto.Verify(pub, data, sig)
}

// Publish signs a new NameRecord pointing name at root with the
// default TTL and stores it in the DHT. version should be
// monotonically increasing relative to any previous record the caller
// has published. Returns the stored record.
//
// Caller is responsible for tracking version numbers. A simple strategy
// is to Resolve first, take existing.Version + 1, then Publish.
//
// Use PublishWithTTL if you need a custom TTL. After TTL elapses,
// resolvers will reject this record -- the publisher must re-sign and
// re-publish before then to keep the domain alive.
func Publish(d *dht.DHT, id *crypto.Identity, name string, root dht.NodeID, version int64) (*NameRecord, error) {
	return PublishWithTTL(d, id, name, root, version, DefaultNameTTL)
}

// PublishWithTTL is Publish with an explicit TTL in seconds. ttl=0
// signs a never-expiring record (NOT recommended in production
// because it removes any replay-protection window).
func PublishWithTTL(d *dht.DHT, id *crypto.Identity, name string, root dht.NodeID, version, ttl int64) (*NameRecord, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	rec := &NameRecord{
		Name:      CanonicalName(name),
		Root:      root.Hex(),
		Version:   version,
		Timestamp: time.Now().Unix(),
		TTL:       ttl,
	}
	if err := rec.Sign(id); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if len(blob) > dht.MaxValueSize {
		return nil, errors.New("name record exceeds DHT MaxValueSize")
	}
	if _, err := d.Store(RecordKey(name), blob); err != nil {
		return nil, fmt.Errorf("store record: %w", err)
	}
	return rec, nil
}

// Resolve looks up name in the DHT, parses the record, verifies the
// signature, and confirms the embedded name matches what the caller
// asked for. Returns the verified record on success.
//
// Resolve queries every replica that holds a candidate record and
// returns the one with the highest Version that passes signature
// verification and matches the requested name. This matters because
// records are mutable: after a Publish bumps Version, replicas don't
// update instantly. A naive "first responder wins" lookup could return
// stale data; the version vote here converges to the freshest signed
// record.
//
// An attacker cannot point name at content they don't own without
// matching the original signer's private key -- but they CAN race the
// original signer to first registration. See package doc for the
// squatting limitation.
func Resolve(d *dht.DHT, name string) (*NameRecord, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	canonical := CanonicalName(name)

	candidates, err := d.GetAllUnverified(RecordKey(canonical))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", canonical, err)
	}

	best, lastErr := pickBestRecord(canonical, candidates)
	if best == nil {
		if lastErr != nil {
			return nil, fmt.Errorf("resolve %s: no valid record (%w)", canonical, lastErr)
		}
		return nil, fmt.Errorf("resolve %s: no valid record found", canonical)
	}
	return best, nil
}

// pickBestRecord parses each candidate blob, drops the ones that
// don't match the requested name, fail signature verification, OR
// have expired (TTL elapsed) / are future-dated. Returns the
// survivor with the highest Version. Exposed (lowercase) so tests
// can exercise the voting logic in isolation without standing up a
// full DHT topology.
//
// The expiry filter is the replay-protection layer: an attacker
// holding an OLD signed record can serve it back, but resolvers
// drop it once now > Timestamp+TTL. Combined with version voting,
// this means a fresh Publish definitively supersedes prior records
// across the network within at most one TTL window.
func pickBestRecord(canonical string, candidates [][]byte) (*NameRecord, error) {
	now := time.Now().Unix()
	var best *NameRecord
	var lastErr error
	for _, blob := range candidates {
		var rec NameRecord
		if err := json.Unmarshal(blob, &rec); err != nil {
			lastErr = fmt.Errorf("parse: %w", err)
			continue
		}
		if rec.Name != canonical {
			// Someone planted a record claiming to be "alice.alt" under
			// the key for "bob.alt". Skip; keep looking.
			lastErr = fmt.Errorf("record name %q does not match", rec.Name)
			continue
		}
		if err := rec.Verify(); err != nil {
			lastErr = fmt.Errorf("bad signature: %w", err)
			continue
		}
		if !registrarAllowed(rec.PublicKey) {
			// Permissioned naming: the record is validly signed, but not
			// by an approved registrar authority. On the canonical AltNet
			// this means the name was never approved by the admin, so we
			// refuse to resolve it. (Open mode skips this check.)
			lastErr = fmt.Errorf("registrar %.8s not an approved authority", rec.PublicKey)
			continue
		}
		if rec.Expired(now) {
			lastErr = fmt.Errorf("record expired or future-dated (ts=%d ttl=%d now=%d)",
				rec.Timestamp, rec.TTL, now)
			continue
		}
		if best == nil || rec.Version > best.Version {
			r := rec
			best = &r
		}
	}
	return best, lastErr
}

// RootKey returns the resolved record's root as a NodeID, ready to feed
// into files.FetchDir or any other content-addressed lookup.
func (r *NameRecord) RootKey() (dht.NodeID, error) {
	return dht.IDFromHex(r.Root)
}
