package dns

import (
	"testing"
	"time"
)

// TestUDPRateLimiterCaps: a fresh source gets `burst` allowed, then
// is denied until refill.
func TestUDPRateLimiterCaps(t *testing.T) {
	l := newUDPRateLimiter(10, 3)
	ip := "1.2.3.4"

	for i := 0; i < 3; i++ {
		if !l.allow(ip) {
			t.Fatalf("burst #%d should be allowed", i+1)
		}
	}
	if l.allow(ip) {
		t.Error("over-burst request should be denied")
	}

	time.Sleep(150 * time.Millisecond)
	if !l.allow(ip) {
		t.Error("after refill, request should be allowed")
	}
}

// TestUDPRateLimiterIsolatesSources: A burning their bucket doesn't
// affect B.
func TestUDPRateLimiterIsolatesSources(t *testing.T) {
	l := newUDPRateLimiter(1, 2)
	a, b := "1.1.1.1", "2.2.2.2"

	l.allow(a)
	l.allow(a)
	if l.allow(a) {
		t.Error("A over its budget")
	}
	if !l.allow(b) {
		t.Error("B unaffected")
	}
}
