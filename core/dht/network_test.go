package dht

import (
	"testing"
	"time"

	"altnet/core/crypto"
	"altnet/core/peer"
)

// newNode spins up a peer + DHT bound to a free port. Returns both so the
// test can call Bootstrap, inspect the routing table, etc.
func newNode(t *testing.T) (*peer.Peer, *DHT) {
	t.Helper()
	id, err := crypto.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	p := peer.New(id, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	d, err := New(p)
	if err != nil {
		p.Stop()
		t.Fatalf("dht: %v", err)
	}
	return p, d
}

// TestPingOverNetwork verifies that two real peers can DHT-ping each other.
func TestPingOverNetwork(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := da.Bootstrap(pb.LocalAddr()); err != nil {
		t.Fatalf("A bootstrap to B: %v", err)
	}
	// After bootstrap, A knows B. Pick the contact and ping it.
	contacts := da.RoutingTable().All()
	if len(contacts) == 0 {
		t.Fatal("A's routing table empty after bootstrap")
	}
	if err := da.Ping(contacts[0]); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	_ = db // keep db referenced to keep the linter quiet
}

// TestBootstrapPopulatesRoutingTable verifies that a peer joining via
// Bootstrap learns about its bootstrap target.
func TestBootstrapPopulatesRoutingTable(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := db.RoutingTable().Size(); got != 1 {
		t.Errorf("after bootstrap, B should know about A only, got size=%d", got)
	}
}

// TestThreeNodeDiscovery is the milestone test: a peer joining a network
// learns about peers it never directly contacted, just by talking to one.
//
//	A starts.
//	B bootstraps to A   -> A and B know each other.
//	C bootstraps to A   -> C learns about A directly, AND about B
//	                       through A's reply to FIND_NODE.
//
// If this test passes, peer discovery without prior knowledge works.
func TestThreeNodeDiscovery(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("B bootstrap: %v", err)
	}
	// Give the lookup-of-self traffic a moment to settle.
	time.Sleep(150 * time.Millisecond)

	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatalf("C bootstrap: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// C should now know both A and B.
	contacts := dc.RoutingTable().All()
	knowsA := false
	knowsB := false
	for _, c := range contacts {
		if c.ID.Hex() == da.Self().Hex() {
			knowsA = true
		}
		if c.ID.Hex() == db.Self().Hex() {
			knowsB = true
		}
	}
	if !knowsA {
		t.Errorf("C should know A after bootstrap, table=%v", contacts)
	}
	if !knowsB {
		t.Errorf("C should have learned B via A, table=%v", contacts)
	}
}

// TestLookupFindsRemotePeer is the explicit lookup form of the previous
// test. C asks "find peers close to B's ID". Even though C never directly
// connected to B, the result should include B.
func TestLookupFindsRemotePeer(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	results := dc.Lookup(db.Self())

	found := false
	for _, c := range results {
		if c.ID.Hex() == db.Self().Hex() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Lookup(B) from C did not find B; got %d contacts: %v", len(results), results)
	}
	_ = pc
}
