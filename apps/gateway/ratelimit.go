package gateway

import (
	"sync"
	"time"
)

// ipRateLimiter is a token-bucket rate limiter keyed by remote IP.
// Each IP gets its own bucket. Tokens accrue at `rate` per second up
// to `burst`. A request consumes one token; if no token is available,
// the request is denied.
//
// Buckets are GC'd when an IP has been idle long enough (no buckets
// stick around forever from a one-shot scanner).
//
// Pure stdlib; no golang.org/x/time/rate dependency.
type ipRateLimiter struct {
	rate    float64 // tokens per second
	burst   float64 // bucket capacity

	mu       sync.Mutex
	buckets  map[string]*ipBucket
	lastSweep time.Time
}

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newIPRateLimiter(rate, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		rate:      float64(rate),
		burst:     float64(burst),
		buckets:   make(map[string]*ipBucket),
		lastSweep: time.Now(),
	}
}

// allow reports whether the request from ip should be permitted. It
// also accounts the consumed token if it returns true.
func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Periodic GC of idle buckets. Run at most every 30 seconds; fast
	// in the common case (small map).
	if now.Sub(l.lastSweep) > 30*time.Second {
		l.gc(now)
		l.lastSweep = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		// New IP: full bucket of tokens.
		b = &ipBucket{tokens: l.burst, lastSeen: now}
		l.buckets[ip] = b
	}

	// Refill: tokens earned since last seen, capped at burst.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// gc drops buckets that haven't been touched in a while. Caller holds mu.
func (l *ipRateLimiter) gc(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.lastSeen) > 5*time.Minute {
			delete(l.buckets, ip)
		}
	}
}
