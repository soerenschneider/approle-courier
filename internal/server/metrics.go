package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "approle_courier"

// Vault error kinds, used as the "kind" label of vault_errors_total.
const (
	vaultErrNotFound    = "not_found"
	vaultErrRejected    = "rejected"
	vaultErrSealed      = "sealed"
	vaultErrUnreachable = "unreachable"
	vaultErrUnexpected  = "unexpected"
)

type metrics struct {
	httpRequests        *prometheus.CounterVec
	httpDuration        *prometheus.HistogramVec
	httpInFlight        prometheus.Gauge
	challengesIssued    prometheus.Counter
	challengesRejected  *prometheus.CounterVec
	authFailures        *prometheus.CounterVec
	secretIDsIssued     *prometheus.CounterVec
	secretIDsDenied     *prometheus.CounterVec
	secretIDsSuperseded prometheus.Counter
	supersedeErrors     prometheus.Counter
	registryErrors      prometheus.Counter
	vaultDuration       prometheus.Histogram
	vaultErrors         *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer, pending func() float64) (*metrics, error) {
	m := &metrics{
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "API requests by route pattern and status code.",
		}, []string{"route", "code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "API request latency by route pattern.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"route"}),
		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_in_flight",
			Help:      "API requests currently being served.",
		}),
		challengesIssued: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "challenges_issued_total",
			Help:      "Challenge tokens issued.",
		}),
		challengesRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "challenges_rejected_total",
			Help:      "Challenge requests rejected, by reason.",
		}, []string{"reason"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "auth_failures_total",
			Help:      "Requests rejected for a missing or invalid challenge token.",
		}, []string{"reason"}),
		secretIDsIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "secret_ids_issued_total",
			Help:      "Wrapped SecretIDs delivered, by AppRole mount and role.",
		}, []string{"mount", "role"}),
		secretIDsDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "secret_ids_denied_total",
			Help:      "Authenticated SecretID requests refused before reaching Vault, by reason.",
		}, []string{"reason"}),
		secretIDsSuperseded: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "secret_ids_superseded_total",
			Help:      "Still-valid SecretIDs destroyed because a new one was issued for their exclusive role.",
		}),
		supersedeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "secret_id_supersede_errors_total",
			Help:      "Failures listing, looking up or destroying the old SecretIDs of an exclusive role.",
		}),
		registryErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "registry_errors_total",
			Help:      "Registry lookups that failed because the registry could not be read or was invalid.",
		}),
		vaultDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "vault_request_duration_seconds",
			Help:      "Latency of Vault SecretID requests.",
			Buckets:   prometheus.DefBuckets,
		}),
		vaultErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "vault_errors_total",
			Help:      "Failed Vault SecretID requests, by kind.",
		}, []string{"kind"}),
	}
	pendingGauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "challenges_pending",
		Help:      "Challenge tokens issued but not yet redeemed or expired.",
	}, pending)

	for _, c := range []prometheus.Collector{
		m.httpRequests, m.httpDuration, m.httpInFlight,
		m.challengesIssued, m.challengesRejected, m.authFailures,
		m.secretIDsIssued, m.secretIDsDenied, m.secretIDsSuperseded, m.supersedeErrors,
		m.registryErrors, m.vaultDuration, m.vaultErrors,
		pendingGauge,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// instrument records request count, latency and in-flight requests. It must
// wrap the mux directly so r.Pattern is set once the mux has routed.
func (m *metrics) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		m.httpRequests.WithLabelValues(route, strconv.Itoa(sw.status)).Inc()
		m.httpDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
