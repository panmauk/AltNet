// Package altca generates a per-install certificate authority for the
// AltNet daemon's HTTPS gateway, and mints per-site leaf certificates
// on demand.
//
// # Why a private CA at all
//
// `.alt` is not in public DNS, so no public CA (Let's Encrypt, etc.)
// will ever sign certificates for it — their domain-validation step
// requires real DNS, which we don't have. The only path to a green
// padlock for `https://panmox.alt/` is for the user's browser to
// already trust the CA that signed the cert. Easiest: ship a CA, have
// the user install its root cert into their own trust store.
//
// # Why this is still safe
//
// A naive private root CA is dangerous: whoever holds its private key
// can mint a valid cert for *any* domain — bank.com, google.com,
// anything — and impersonate it on the user's machine. We close that
// hole with **X.509 Name Constraints** (RFC 5280 §4.2.1.10). The root
// declares `permittedDNSDomains = [".alt"]` and marks the extension
// critical, so browsers refuse to honor any leaf signed by us whose
// SAN isn't a `.alt` name. Even if the on-disk private key leaks, the
// blast radius is "an attacker can MITM your `.alt` sites" — not the
// whole web.
//
// Each install generates its OWN CA, so there's no shared trust to
// burn. The private key never leaves the daemon's data dir and is
// stored with 0600 permissions (Windows ACL inherits the dir's).
//
// # Lifecycle
//
//   LoadOrCreate(dir)   - read existing CA or generate on first call
//   ca.CertPEM()        - bytes the app installs in the trust store
//   ca.Issue(name)      - returns a tls.Certificate for a `.alt` name,
//                         cached so SNI replies are instant
package altca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File names inside the CA dir. Public cert is fine for everyone to
// read; the private key is the secret. We write the cert in BOTH PEM
// (human-readable, used for in-process roundtrip) AND DER (.cer, the
// only format Windows' Import-Certificate cmdlet accepts).
const (
	caCertFile    = "altnet-ca.crt" // PEM
	caCertDERFile = "altnet-ca.cer" // DER — Windows trust-store importable
	caKeyFile     = "altnet-ca.key"
)

// CA is the loaded (or freshly generated) AltNet CA. Safe for
// concurrent use; Issue() is internally locked because it mutates the
// cert cache.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey

	dir string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate returns the CA stored under dir. If the on-disk files
// are missing, a fresh CA is generated and saved. dir is created with
// mode 0700 if it doesn't exist.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		if err == nil {
			ca.dir = dir
			ca.cache = make(map[string]*tls.Certificate)
			// Make sure the DER companion file exists. Older installs
			// of altca wrote only .crt (PEM); without .cer the
			// Windows trust importer can't read it.
			derPath := filepath.Join(dir, caCertDERFile)
			if _, err := os.Stat(derPath); err != nil {
				_ = os.WriteFile(derPath, ca.Cert.Raw, 0o644)
			}
			return ca, nil
		}
		// Fall through to regenerate if the existing pair is unparseable.
	}

	return generate(dir)
}

// generate creates a fresh CA, writes it to disk, and returns it.
func generate(dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().Add(-1 * time.Hour) // backdate slightly for clock skew
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AltNet Local CA",
			Organization: []string{"AltNet"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0, // can sign leaves but not other CAs
		MaxPathLenZero:        true,

		// THE critical safety feature: this CA cannot mint certs for
		// anything outside .alt. Browsers honor PermittedDNSDomains
		// when set, so an exfiltrated key can't be used to MITM
		// bank.com or google.com.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{".alt"},
		ExcludedDNSDomains:          nil,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign ca: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse ca: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, caCertDERFile), der, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}

	return &CA{
		Cert:    parsed,
		CertPEM: certPEM,
		Key:     key,
		dir:     dir,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("ca cert: missing CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca key: empty pem")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	return &CA{Cert: cert, CertPEM: certPEM, Key: key}, nil
}

// Issue returns a TLS certificate valid for hostname, signed by this
// CA. Results are cached forever in memory (1 cert per name per
// daemon lifetime is plenty).
//
// hostname must end in `.alt` — anything else returns an error so we
// don't accidentally violate our own Name Constraint and produce a
// cert browsers will reject anyway.
func (c *CA) Issue(hostname string) (*tls.Certificate, error) {
	if !validAltHostname(hostname) {
		return nil, fmt.Errorf("altca: hostname %q is not under .alt", hostname)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.cache[hostname]; ok {
		return cert, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-1 * time.Hour)
	leafTpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now,
		// Long-ish so browsers don't nag, short enough that
		// a stolen key doesn't haunt the user forever.
		NotAfter:    now.Add(395 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, c.Cert, &leafKey.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafDER, c.Cert.Raw}, // leaf + CA so clients can build the chain
		PrivateKey:  leafKey,
		Leaf:        nil, // tls package will parse on demand
	}
	c.cache[hostname] = tlsCert
	return tlsCert, nil
}

// CertPath is the PEM-encoded public CA cert. Human-readable, fine for
// inspection but not what Windows' Import-Certificate expects.
func (c *CA) CertPath() string { return filepath.Join(c.dir, caCertFile) }

// CertDERPath is the DER-encoded public CA cert. This is the path the
// desktop app feeds to Windows' trust-store importer.
func (c *CA) CertDERPath() string { return filepath.Join(c.dir, caCertDERFile) }

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serial, well above the 64-bit RFC minimum
	return rand.Int(rand.Reader, max)
}

// validAltHostname enforces the canonical form of a `.alt` name
// (lowercase ASCII, digits, hyphen, dot). Callers must canonicalize
// before calling Issue — we *don't* fold case here on purpose. Issuing
// a cert for an upper-cased name would put a non-canonical SAN in
// the leaf, which is the wrong cert to return on SNI for `panmox.alt`.
// Defense-in-depth for the Name Constraint.
func validAltHostname(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	if !strings.HasSuffix(s, ".alt") {
		return false
	}
	prefix := strings.TrimSuffix(s, ".alt")
	if prefix == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}
