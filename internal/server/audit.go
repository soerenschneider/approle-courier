package server

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// auditSampleInterval limits rejections of unauthenticated requests to one
// log line per reason and client network per interval, so they cannot be
// used to flood the logs. The next line reports how many were suppressed.
const auditSampleInterval = time.Minute

// maxAuditDetail caps logged details that may quote caller input.
const maxAuditDetail = 200

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// audit logs a rejected request as "request rejected" with the reason (the
// same value as the metrics label), the client address and attrs. Tokens
// and other secrets must never be passed in attrs. If sampled, the line is
// subject to auditSampleInterval.
func (s *Server) audit(ctx context.Context, sampled bool, reason string, attrs ...any) {
	client := clientIPFrom(ctx)
	if sampled {
		ok, suppressed := s.sampler.allow(sampleKey{reason: reason, client: clientNetwork(client)}, s.now())
		if !ok {
			return
		}
		if suppressed > 0 {
			attrs = append(attrs, "suppressed", suppressed)
		}
	}
	s.log.WarnContext(ctx, "request rejected", append([]any{"reason", reason, "client_ip", client.String()}, attrs...)...)
}

// rejectChallenge counts and logs a rejected challenge request. The request
// is unauthenticated, so the log is sampled and machineID is only logged if
// it is a valid name.
func (s *Server) rejectChallenge(ctx context.Context, reason, machineID string) {
	s.metrics.challengesRejected.WithLabelValues(reason).Inc()
	var attrs []any
	if validName(machineID) {
		attrs = append(attrs, "machine_id", machineID)
	}
	s.audit(ctx, true, reason, attrs...)
}

// rejectSecretID counts and logs a refused SecretID request from an
// authenticated machine. These are always logged. detail is a
// server-generated message, never caller input.
func (s *Server) rejectSecretID(ctx context.Context, reason, machineID string, p secretIDParams, detail string) {
	s.metrics.secretIDsDenied.WithLabelValues(reason).Inc()
	attrs := []any{"machine_id", machineID}
	if validName(p.mount) && validName(p.role) {
		attrs = append(attrs, "mount", p.mount, "role", p.role)
	}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	s.audit(ctx, false, reason, attrs...)
}

type sampleKey struct {
	reason string
	client netip.Prefix
}

type sampleState struct {
	last       time.Time
	suppressed int
}

// logSampler allows one event per key per interval.
type logSampler struct {
	interval time.Duration

	mu        sync.Mutex
	seen      map[sampleKey]*sampleState
	lastSweep time.Time
}

func newLogSampler(interval time.Duration) *logSampler {
	return &logSampler{interval: interval, seen: make(map[sampleKey]*sampleState)}
}

// allow reports whether to log an event for key at now and, if so, how many
// events for key were suppressed since the last one logged.
func (l *logSampler) allow(key sampleKey, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= l.interval {
		for k, st := range l.seen {
			if now.Sub(st.last) >= 2*l.interval {
				delete(l.seen, k)
			}
		}
		l.lastSweep = now
	}
	st, ok := l.seen[key]
	if ok && now.Sub(st.last) < l.interval {
		st.suppressed++
		return false, 0
	}
	suppressed := 0
	if ok {
		suppressed = st.suppressed
	}
	l.seen[key] = &sampleState{last: now}
	return true, suppressed
}
