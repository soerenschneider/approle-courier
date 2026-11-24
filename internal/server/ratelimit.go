package server

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterSweepInterval is how often idle limiters are dropped.
const limiterSweepInterval = time.Minute

// keyedLimiter is a token-bucket rate limit per key, e.g. per client network
// or per machine.
type keyedLimiter[K comparable] struct {
	rate  rate.Limit
	burst int

	mu        sync.Mutex
	limiters  map[K]*rate.Limiter
	lastSweep time.Time
}

func newKeyedLimiter[K comparable](r rate.Limit, burst int) *keyedLimiter[K] {
	return &keyedLimiter[K]{
		rate:     r,
		burst:    burst,
		limiters: make(map[K]*rate.Limiter),
	}
}

// allow reports whether key may make a request at now and, if not, how long
// until it may.
func (l *keyedLimiter[K]) allow(key K, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= limiterSweepInterval {
		l.sweep(now)
	}
	lim, ok := l.limiters[key]
	if !ok {
		lim = rate.NewLimiter(l.rate, l.burst)
		l.limiters[key] = lim
	}
	r := lim.ReserveN(now, 1)
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// sweep drops limiters whose bucket has refilled; a new one behaves the same.
func (l *keyedLimiter[K]) sweep(now time.Time) {
	for k, lim := range l.limiters {
		if lim.TokensAt(now) >= float64(l.burst) {
			delete(l.limiters, k)
		}
	}
	l.lastSweep = now
}

// retryAfterFor converts a wait into a Retry-After value of at least 1.
func retryAfterFor(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}
