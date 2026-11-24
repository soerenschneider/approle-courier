package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync/atomic"
	"time"
)

// readinessCheckTimeout bounds each readiness check.
const readinessCheckTimeout = 5 * time.Second

// health serves /healthz and /readyz on the API listener.
//
// /healthz reports that the process is serving. /readyz reports whether it
// can do useful work: every check passes and it is not shutting down. Load
// balancers should route on /readyz; restarts belong on /healthz only, since
// a Vault outage makes every replica unready and restarting does not help.
//
// The API listener is reachable by machines, so responses name failed checks
// but not their errors; those are logged when readiness changes.
type health struct {
	checks       map[string]func(context.Context) error
	log          *slog.Logger
	shuttingDown atomic.Bool
	// unready is the last /readyz result, so only changes are logged.
	unready atomic.Bool
}

func (h *health) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeStatus(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", h.ready)
}

func (h *health) ready(w http.ResponseWriter, r *http.Request) {
	if h.shuttingDown.Load() {
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "shutting down"})
		return
	}
	errs := map[string]string{}
	for name, check := range h.checks {
		ctx, cancel := context.WithTimeout(r.Context(), readinessCheckTimeout)
		err := check(ctx)
		cancel()
		if err != nil {
			errs[name] = err.Error()
		}
	}
	if len(errs) > 0 {
		if !h.unready.Swap(true) {
			h.log.Warn("not ready", "failed", errs)
		}
		failed := slices.Sorted(maps.Keys(errs))
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "failed": failed})
		return
	}
	if h.unready.Swap(false) {
		h.log.Info("ready again")
	}
	writeStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func writeStatus(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// tokenNotExpired fails once the token's lease has ended, e.g. because
// renewal and re-login kept failing. A token without expiry always passes.
func tokenNotExpired(expiry func() time.Time) func(context.Context) error {
	return func(context.Context) error {
		if exp := expiry(); !exp.IsZero() && !time.Now().Before(exp) {
			return errors.New("vault token expired at " + exp.UTC().Format(time.RFC3339))
		}
		return nil
	}
}
