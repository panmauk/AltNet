package dht

import (
	"strings"
	"sync"
	"time"
)

// Default maintenance intervals. These are deliberately conservative for
// a small network; production-scale Kademlia tunes these based on churn.
const (
	// DefaultRepublishInterval is how often each peer re-announces its
	// stored values to the K closest known peers. Without republishing,
	// values would disappear when the peers holding them go offline.
	DefaultRepublishInterval = 1 * time.Hour

	// DefaultPeerCheckInterval is how often we ping every contact in the
	// routing table to evict dead ones.
	DefaultPeerCheckInterval = 10 * time.Minute

	// DefaultBootstrapRetryInterval is how often we try to reconnect to
	// our bootstrap peers if the routing table is empty.
	DefaultBootstrapRetryInterval = 30 * time.Second
)

// MaintenanceConfig controls the background maintenance loop.
// All zero values fall back to the Default* constants.
type MaintenanceConfig struct {
	BootstrapPeers         []string      // addresses to retry if RT empties
	RepublishInterval      time.Duration // how often to re-announce stored values
	PeerCheckInterval      time.Duration // how often to ping routing table
	BootstrapRetryInterval time.Duration // how often to retry bootstrap when alone
}

// StartMaintenance launches the background maintenance loop. It runs
// until ctx is cancelled (use Stop on the returned Maintenance).
//
// The maintenance loop does three things:
//
//   1. REPUBLISH every stored value to the K closest peers, periodically.
//      This is what keeps content alive on the network even as peers churn.
//
//   2. PING every routing table contact and evict dead ones. Keeps the
//      table fresh so lookups don't waste time on offline peers.
//
//   3. RECONNECT to bootstrap peers when the routing table empties (e.g.
//      after a network partition). Without this, a temporarily isolated
//      peer never rejoins the swarm.
func (d *DHT) StartMaintenance(cfg MaintenanceConfig) *Maintenance {
	if cfg.RepublishInterval == 0 {
		cfg.RepublishInterval = DefaultRepublishInterval
	}
	if cfg.PeerCheckInterval == 0 {
		cfg.PeerCheckInterval = DefaultPeerCheckInterval
	}
	if cfg.BootstrapRetryInterval == 0 {
		cfg.BootstrapRetryInterval = DefaultBootstrapRetryInterval
	}

	m := &Maintenance{
		d:    d,
		cfg:  cfg,
		stop: make(chan struct{}),
	}
	m.wg.Add(4)
	go m.republishLoop()
	go m.peerCheckLoop()
	go m.bootstrapLoop()
	go m.startupRepublish()
	return m
}

// startupRepublish does ONE republish pass shortly after startup, so a
// peer that just came back online with persisted values from disk
// re-announces them to the K-closest peers immediately rather than
// waiting up to RepublishInterval (an hour by default).
//
// Without this, restarting a peer creates a window where its content
// is held only locally; any peer in the network looking for that
// content has to find it through the closest-peer iteration and
// happen to land on us. With this, we proactively spread our values
// to the right neighbours as soon as we have any peers to talk to.
func (m *Maintenance) startupRepublish() {
	defer m.wg.Done()
	// Wait briefly for the routing table to populate (bootstraps
	// happen in parallel). If the RT is still empty after a short
	// budget, give up -- a peer with no peers can't republish anyway,
	// and the regular republish loop will retry once we make contact.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-m.stop:
			return
		default:
		}
		if m.d.rt.Size() > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if m.d.rt.Size() == 0 {
		return // nothing we can do until we find peers
	}
	m.republishAll()
}

// Maintenance is a handle to a running maintenance loop.
type Maintenance struct {
	d    *DHT
	cfg  MaintenanceConfig
	stop chan struct{}
	wg   sync.WaitGroup
}

// Stop halts the maintenance loop and waits for the goroutines to exit.
func (m *Maintenance) Stop() {
	select {
	case <-m.stop:
		// already stopped
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

// republishLoop periodically re-announces every stored (key, value) to
// the K closest peers we know about for that key. This is what keeps
// content alive across peer churn: even if every original holder leaves,
// the K closest peers (which change as the network grows) will receive
// fresh copies on each republish cycle.
func (m *Maintenance) republishLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.cfg.RepublishInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.republishAll()
		}
	}
}

// republishAll iterates the local store and re-stores every entry. We
// avoid republishing things that are already widely replicated by relying
// on Store's idempotence — duplicate STOREs are cheap.
func (m *Maintenance) republishAll() {
	keys := m.d.store.snapshotKeys()
	for _, hex := range keys {
		key, err := IDFromHex(hex)
		if err != nil {
			continue
		}
		value, ok := m.d.store.Get(key)
		if !ok {
			continue
		}
		// Best-effort. Errors here just mean some replicas couldn't be
		// reached; we'll try again next cycle.
		_, _ = m.d.Store(key, value)
	}
}

// peerCheckLoop pings every contact in the routing table at a steady
// cadence. Contacts that fail to respond are removed.
func (m *Maintenance) peerCheckLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.cfg.PeerCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.pingAll()
		}
	}
}

// pingAll pings every contact concurrently and prunes ones that fail.
func (m *Maintenance) pingAll() {
	contacts := m.d.rt.All()
	var wg sync.WaitGroup
	for _, c := range contacts {
		wg.Add(1)
		go func(c Contact) {
			defer wg.Done()
			if err := m.d.Ping(c); err != nil {
				m.d.rt.Remove(c.ID)
			}
		}(c)
	}
	wg.Wait()
}

// MaxBootstrapBackoff caps the exponential backoff between failed
// bootstrap attempts. Without a cap, a peer that's been offline for
// hours would wait hours before trying again on reconnect.
const MaxBootstrapBackoff = 5 * time.Minute

// bootstrapLoop reconnects to bootstrap peers when the routing table
// is empty (i.e. we've been partitioned off the network). Does nothing
// if no bootstrap peers were configured or if the table is healthy.
//
// Uses exponential backoff: each consecutive failure doubles the wait
// (capped at MaxBootstrapBackoff). On success or when the table is
// non-empty (somebody else got us connected), the backoff resets to
// the configured baseline. Without backoff, dead bootstrap addresses
// get pummeled at a fixed rate forever, which is wasteful and looks
// like a flooder to the operator of the (very-much-down) bootstrap.
func (m *Maintenance) bootstrapLoop() {
	defer m.wg.Done()
	if len(m.cfg.BootstrapPeers) == 0 {
		return
	}
	baseline := m.cfg.BootstrapRetryInterval
	wait := baseline
	for {
		select {
		case <-m.stop:
			return
		case <-time.After(wait):
		}

		if m.d.rt.Size() > 0 {
			wait = baseline // healthy: reset
			continue
		}

		// Routing table is empty -- try every bootstrap address.
		succeeded := false
		for _, addr := range m.cfg.BootstrapPeers {
			if err := m.d.Bootstrap(addr); err == nil {
				succeeded = true
				break
			}
		}
		if succeeded {
			wait = baseline
		} else {
			wait *= 2
			if wait > MaxBootstrapBackoff {
				wait = MaxBootstrapBackoff
			}
		}
	}
}

// snapshotKeys returns a copy of all currently-held keys. Used by the
// republish loop so we don't hold the store lock while making network
// calls.
func (s *localStore) snapshotKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys
}

// BootstrapAll attempts to bootstrap through any of the given addresses,
// stopping at the first success. Returns the address that succeeded,
// or an error listing what each one failed with.
//
// This replaces single-address bootstrap with redundancy: if your
// primary bootstrap node is offline, the secondaries take over. Real
// deployments hard-code 3-5 well-known bootstrap addresses.
func (d *DHT) BootstrapAll(addrs []string) (string, error) {
	if len(addrs) == 0 {
		return "", nil
	}
	var errs []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if err := d.Bootstrap(addr); err == nil {
			return addr, nil
		} else {
			errs = append(errs, addr+": "+err.Error())
		}
	}
	return "", &bootstrapError{tries: errs}
}

type bootstrapError struct{ tries []string }

func (e *bootstrapError) Error() string {
	return "all bootstrap attempts failed: " + strings.Join(e.tries, "; ")
}
