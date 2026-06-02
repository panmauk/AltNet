package gateway

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimiterBurstAndRefill: a fresh IP gets a full bucket (burst
// capacity), then is denied until refill.
func TestRateLimiterBurstAndRefill(t *testing.T) {
	// 10 tokens/sec, burst 3.
	l := newIPRateLimiter(10, 3)
	ip := "1.2.3.4"

	// Burst: first 3 should succeed.
	for i := 0; i < 3; i++ {
		if !l.allow(ip) {
			t.Fatalf("burst request #%d should be allowed", i+1)
		}
	}
	// 4th should be denied (no tokens left, no time has elapsed).
	if l.allow(ip) {
		t.Error("4th request should have been rate-limited")
	}

	// After ~150ms, we should have earned ~1.5 tokens at 10/sec, so
	// one more request succeeds.
	time.Sleep(150 * time.Millisecond)
	if !l.allow(ip) {
		t.Error("after 150ms, refill should have produced ~1.5 tokens")
	}
}

// TestRateLimiterIsolatesIPs: one IP burning through its quota
// shouldn't affect a different IP.
func TestRateLimiterIsolatesIPs(t *testing.T) {
	l := newIPRateLimiter(1, 2) // very tight: 2 burst, 1/sec refill
	a := "1.1.1.1"
	b := "2.2.2.2"

	// A burns through.
	l.allow(a)
	l.allow(a)
	if l.allow(a) {
		t.Error("A should be over its limit")
	}
	// B should be unaffected.
	if !l.allow(b) {
		t.Error("B's first request should succeed")
	}
	if !l.allow(b) {
		t.Error("B's second request should succeed")
	}
	if l.allow(b) {
		t.Error("B's third request should be denied (own bucket exhausted)")
	}
}

// TestGatewayReturns429UnderLoad fires more requests than the
// configured rate allows and confirms 429 responses kick in.
func TestGatewayReturns429UnderLoad(t *testing.T) {
	_, d, _ := newNode(t)

	// Tiny limits so the test is fast and deterministic.
	gw := NewWithOptions(d, Options{
		PerIPRate:     1,
		PerIPBurst:    2,
		MaxConcurrent: 100,
	})
	addr := freePort(t)
	srv, err := gw.Start(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	// Hit the unknown-name path (returns 404, but rate limiting runs
	// first). Spam fast.
	client := &http.Client{Timeout: 2 * time.Second}
	var ok, limited int32
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
		req.Host = "nosuchsite.alt"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			atomic.AddInt32(&limited, 1)
		default:
			atomic.AddInt32(&ok, 1)
		}
	}

	// We expect at least a few 429s out of 10 quick requests under a
	// burst-of-2 limit.
	if limited == 0 {
		t.Errorf("expected some 429 responses, got %d ok / %d limited", ok, limited)
	}
}

// TestGatewayReturns503WhenSaturated: when MaxConcurrent is 1 and a
// request is in flight, the next request is rejected with 503.
func TestGatewayReturns503WhenSaturated(t *testing.T) {
	_, d, _ := newNode(t)

	gw := NewWithOptions(d, Options{
		PerIPRate:     1000, // not the test target
		PerIPBurst:    1000,
		MaxConcurrent: 1,
	})
	addr := freePort(t)
	srv, err := gw.Start(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	// We need an in-flight slow request. The simplest is to fill the
	// semaphore from outside the test by acquiring it directly.
	gw.sem <- struct{}{}
	defer func() { <-gw.sem }()

	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "anything.alt"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (saturated)", resp.StatusCode)
	}
}
