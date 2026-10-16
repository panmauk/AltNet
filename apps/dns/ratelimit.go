package dns

import (
	"sync"
	"time"
)

// udpRateLimiter is a token-bucket rate limiter keyed by source IP.
// Same shape as the gateway's HTTP limiter -- duplicated here because
// the dns package is a leaf module and we don't want it depending on
// apps/gateway.
type udpRateLimiter struct {
	rate  float64
	burst float64

	mu        sync.Mutex
	buckets   map[string]*udpBucket
	lastSweep time.Time
}

type udpBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newUDPRateLimiter(qps, burst int) *udpRateLimiter {
	return &udpRateLimiter{
		rate:      float64(qps),
		burst:     float64(burst),
		buckets:   make(map[string]*udpBucket),
		lastSweep: time.Now(),
	}
}

// allow reports whether a query from ip should be permitted, and
// consumes a token if so.
func (l *udpRateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) > 30*time.Second {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > 5*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &udpBucket{tokens: l.burst, lastSeen: now}
		l.buckets[ip] = b
	}

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
