package dht

import (
	"bytes"
	"testing"
	"time"
)

// TestRepublishKeepsValuesAlive verifies the core promise of the
// republish loop: even if the peer that originally stored a value goes
// away, copies live on at the K-closest peers because of periodic
// re-announcement.
//
// Setup: peers A, B, C are bootstrapped together. B stores a value.
// Then we run republish on B and verify A (or C) holds the value
// locally — i.e. it spread beyond just B's local store.
func TestRepublishSpreadsValues(t *testing.T) {
	pa, da := newNode(t)
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
	time.Sleep(200 * time.Millisecond)

	value := []byte("alive across churn")
	key := ContentAddress(value)
	if _, err := db.Store(key, value); err != nil {
		t.Fatal(err)
	}

	// Run a republish cycle manually instead of waiting an hour.
	m := &Maintenance{d: db}
	m.republishAll()

	// At least one of A or C should have the value cached now.
	_, hasA := da.store.Get(key)
	_, hasC := dc.store.Get(key)
	if !hasA && !hasC {
		t.Errorf("after republish, neither A nor C has the value")
	}
}

// TestPingAllPrunesDead verifies that pingAll removes contacts that
// don't respond. We add a contact pointing at a dead address and
// confirm the routing table evicts it after a check pass.
func TestPingAllPrunesDeadPeers(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	// Plant a dead contact.
	deadID := idFromString("ghost")
	da.rt.Update(Contact{ID: deadID, Address: "127.0.0.1:1"}) // unlikely to be listening

	if da.rt.Size() != 1 {
		t.Fatalf("expected RT size 1 after planting, got %d", da.rt.Size())
	}

	m := &Maintenance{d: da}
	m.pingAll()

	if da.rt.Size() != 0 {
		t.Errorf("dead contact should have been pruned, RT size = %d", da.rt.Size())
	}
}

// TestBootstrapAllFallsBackOnDeadPrimary verifies that BootstrapAll
// tries successive addresses when the first fails, and returns the
// address of whichever succeeded.
func TestBootstrapAllFallsBackOnDeadPrimary(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()

	addrs := []string{
		"127.0.0.1:1", // dead
		pa.LocalAddr(), // live
	}
	chosen, err := db.BootstrapAll(addrs)
	if err != nil {
		t.Fatalf("BootstrapAll: %v", err)
	}
	if chosen != pa.LocalAddr() {
		t.Errorf("chosen = %s, want %s", chosen, pa.LocalAddr())
	}
}

// TestBootstrapAllAllDeadReturnsError ensures we get a useful error when
// nothing works.
func TestBootstrapAllAllDeadReturnsError(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	addrs := []string{"127.0.0.1:1", "127.0.0.1:2"}
	_, err := da.BootstrapAll(addrs)
	if err == nil {
		t.Error("BootstrapAll with all-dead addresses should return error")
	}
}

// TestStartupRepublishSpreadsPersistedValues verifies that a peer that
// just started up with values loaded from disk republishes them to its
// new peers shortly after StartMaintenance, rather than waiting an
// hour for the regular republish cycle.
//
// Setup: A peer "P" has a value pre-loaded into its store (simulating
// disk-loaded data). P starts maintenance and bootstraps to other
// peers. We assert that the value reaches at least one other peer
// within seconds, not the hour-long republish interval.
func TestStartupRepublishSpreadsPersistedValues(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	defer pb.Stop()
	pc, dc := newNode(t)
	defer pc.Stop()

	// A and B bootstrap together first.
	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// C: simulates a peer that just came back from disk holding a value.
	value := []byte("persisted across a restart")
	key := ContentAddress(value)
	dc.store.Put(key, value)

	// Before bootstrap, only C has the value.
	if _, ok := da.store.Get(key); ok {
		t.Fatal("A shouldn't have value yet (test setup bug)")
	}

	// C bootstraps and starts maintenance with a tiny startup-republish
	// budget so the test isn't slow.
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	m := dc.StartMaintenance(MaintenanceConfig{
		RepublishInterval:      time.Hour,        // would normally wait this long
		PeerCheckInterval:      time.Hour,
		BootstrapRetryInterval: time.Hour,
	})
	defer m.Stop()

	// Within a few seconds, the startup republish should have pushed
	// the value to A or B. Poll for it.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, hasA := da.store.Get(key)
		_, hasB := db.store.Get(key)
		if hasA || hasB {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("startup republish did not spread persisted value within 5s")
}

// TestStartMaintenanceShutsDownCleanly verifies the goroutines exit
// when Stop is called, and that Stop is safe to call multiple times.
func TestStartMaintenanceShutsDownCleanly(t *testing.T) {
	pa, da := newNode(t)
	defer pa.Stop()

	m := da.StartMaintenance(MaintenanceConfig{
		RepublishInterval:      time.Hour,
		PeerCheckInterval:      time.Hour,
		BootstrapRetryInterval: time.Hour,
	})

	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s")
	}

	// Calling Stop again should be a no-op, not a panic.
	m.Stop()
}

// TestRepublishedValueRetrievableEndToEnd is the integration milestone:
// peer B stores something. B goes offline. C asks A for it; A got the
// value via the republish cycle and serves it.
func TestRepublishedValueSurvivesOriginalPeerLeaving(t *testing.T) {
	pa, _ := newNode(t)
	defer pa.Stop()
	pb, db := newNode(t)
	pc, dc := newNode(t)
	defer pc.Stop()

	if err := db.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := dc.Bootstrap(pa.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	value := []byte("the show must go on")
	key := ContentAddress(value)
	if _, err := db.Store(key, value); err != nil {
		t.Fatal(err)
	}

	// Force republish so A has a copy.
	(&Maintenance{d: db}).republishAll()

	// B leaves the network.
	pb.Stop()
	time.Sleep(100 * time.Millisecond)

	// Drop B from C's routing table so C only learns about A.
	bID := idFromString("dummy") // placeholder; we just need C to query A
	_ = bID

	got, err := dc.Get(key)
	if err != nil {
		t.Fatalf("Get after B left: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("got %q, want %q", got, value)
	}
}
