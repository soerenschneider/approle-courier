package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// publicRoutes lists the routes that do not require a challenge token.
// Everything else is authenticated, so new routes are protected by default.
var publicRoutes = map[string]bool{
	"POST /v1/auth/challenge": true,
}

var errUnauthenticated = errors.New("invalid or expired challenge token")

type machineIDKey struct{}

// MachineID returns the authenticated machine for the request, if any.
func MachineID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(machineIDKey{}).(string)
	return id, ok
}

// authenticate redeems the bearer challenge token and stores the owning
// machine ID in the request context. It runs inside the mux, where
// r.Pattern is set, and before the request body is read or decoded, so an
// unauthenticated caller only ever gets 401 on protected routes.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicRoutes[r.Pattern] {
			next.ServeHTTP(w, r)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			s.rejectAuth(r.Context(), "missing_token", r.Pattern)
			unauthorized(w, "missing bearer token")
			return
		}
		machineID, ok := s.challenges.redeem(token, s.now())
		if !ok {
			s.rejectAuth(r.Context(), "invalid_token", r.Pattern)
			unauthorized(w, errUnauthenticated.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), machineIDKey{}, machineID)))
	})
}

// rejectAuth counts and logs a failed authentication. The caller is
// unauthenticated, so the log is sampled; the token is never logged.
func (s *Server) rejectAuth(ctx context.Context, reason, route string) {
	s.metrics.authFailures.WithLabelValues(reason).Inc()
	s.audit(ctx, true, reason, "route", route)
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, msg)
}
