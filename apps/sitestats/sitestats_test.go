package sitestats

import "testing"

func TestRecordAndGet(t *testing.T) {
	s := New()
	s.Record("alice.alt", "192.0.2.1", 100)
	s.Record("alice.alt", "192.0.2.2", 250)
	s.Record("alice.alt", "192.0.2.1", 50)

	got := s.Get("alice.alt")
	if got.Requests != 3 {
		t.Fatalf("requests=%d, want 3", got.Requests)
	}
	if got.Bytes != 400 {
		t.Fatalf("bytes=%d, want 400", got.Bytes)
	}
	if got.UniqueIPs != 2 {
		t.Fatalf("unique_ips=%d, want 2", got.UniqueIPs)
	}
}

func TestGetUnknownReturnsZero(t *testing.T) {
	s := New()
	got := s.Get("never-seen.alt")
	if got.Requests != 0 || got.Bytes != 0 || got.UniqueIPs != 0 {
		t.Fatalf("expected zero snapshot, got %+v", got)
	}
}

func TestAll(t *testing.T) {
	s := New()
	s.Record("a.alt", "10.0.0.1", 1)
	s.Record("b.alt", "10.0.0.2", 1)
	all := s.All()
	if len(all) != 2 {
		t.Fatalf("want 2 sites, got %d", len(all))
	}
}

func TestForget(t *testing.T) {
	s := New()
	s.Record("a.alt", "10.0.0.1", 1)
	s.Forget("a.alt")
	got := s.Get("a.alt")
	if got.Requests != 0 {
		t.Fatalf("expected forgotten, got requests=%d", got.Requests)
	}
}

func TestEmptyNameIsNoop(t *testing.T) {
	s := New()
	s.Record("", "10.0.0.1", 100)
	if len(s.All()) != 0 {
		t.Fatalf("empty name should be ignored")
	}
}

func TestUniqueIPCap(t *testing.T) {
	s := New()
	s.maxIPsPerSite = 3
	for i, ip := range []string{"a", "b", "c", "d", "e"} {
		s.Record("a.alt", ip, 1)
		_ = i
	}
	got := s.Get("a.alt")
	if got.UniqueIPs != 3 {
		t.Fatalf("expected capped at 3, got %d", got.UniqueIPs)
	}
	if got.Requests != 5 {
		t.Fatalf("requests still all counted, got %d", got.Requests)
	}
}
