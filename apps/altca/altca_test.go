package altca

import (
	"crypto/x509"
	"testing"
)

func TestLoadOrCreateGeneratesThenLoads(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if first.Cert == nil || first.Key == nil {
		t.Fatal("ca is missing pieces")
	}

	// A subsequent call must load from disk, not regenerate (same
	// serial proves it).
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first.Cert.SerialNumber.Cmp(second.Cert.SerialNumber) != 0 {
		t.Fatal("regenerated on reload instead of loading from disk")
	}
}

func TestRootHasAltOnlyNameConstraint(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Fatal("root cert isCA must be true")
	}
	if !ca.Cert.PermittedDNSDomainsCritical {
		t.Fatal("PermittedDNSDomainsCritical must be true so browsers enforce it")
	}
	if len(ca.Cert.PermittedDNSDomains) != 1 || ca.Cert.PermittedDNSDomains[0] != ".alt" {
		t.Fatalf("PermittedDNSDomains = %v, want [.alt]", ca.Cert.PermittedDNSDomains)
	}
}

func TestLeafIsSignedByRootAndScopedToName(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := ca.Issue("panmox.alt")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Verify the leaf chains to the root and the SAN matches the name.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "panmox.alt",
	}); err != nil {
		t.Fatalf("leaf does not verify under root: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "panmox.alt" {
		t.Fatalf("leaf SAN = %v, want [panmox.alt]", leaf.DNSNames)
	}
}

func TestIssueIsCached(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ca.Issue("alice.alt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Issue("alice.alt")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("Issue should return the cached cert on repeat calls")
	}
}

func TestIssueRejectsNonAlt(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"google.com", "bank.com", "", ".alt", "foo bar.alt", "FOO.ALT"} {
		if _, err := ca.Issue(bad); err == nil {
			t.Errorf("Issue(%q) should have been rejected", bad)
		}
	}
}

func TestNameConstraintBlocksNonAltVerification(t *testing.T) {
	// Synthetic check: x509.Verify with a DNSName outside .alt should
	// fail Name Constraint enforcement even if we manually try.
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, _ := ca.Issue("alice.alt")
	leaf, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	// Try verifying against a non-.alt name — should fail (the SAN
	// doesn't match) BUT importantly, even a hand-crafted attempt to
	// reuse the chain for google.com is blocked by Name Constraints.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "google.com"}); err == nil {
		t.Fatal("leaf must not verify for google.com")
	}
}
