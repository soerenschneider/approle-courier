// Package server implements the approle-courier API on top of the generated
// strict server bindings in internal/api.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"

	"github.com/soerenschneider/approle-courier/internal/api"
)

// maxBodyBytes caps request bodies; both operations take small JSON objects.
const maxBodyBytes = 64 << 10

const (
	defaultChallengeTTL = time.Minute
	defaultWrapTTL      = 5 * time.Minute
	defaultMaxWrapTTL   = 15 * time.Minute

	defaultChallengeRate  = 1
	defaultChallengeBurst = 20
)

// Config holds the server's dependencies and limits.
type Config struct {
	Keys       AgeKeyStore
	Authorizer Authorizer
	Vault      SecretIDIssuer
	Log        *slog.Logger
	// Metrics is where the server registers its Prometheus collectors. If
	// nil, metrics are collected but not exported.
	Metrics prometheus.Registerer

	// ChallengeTTL is how long a challenge token stays valid. Default 1m.
	ChallengeTTL time.Duration
	// MaxWrapTTL caps the requested wrap_ttl. Default 15m.
	MaxWrapTTL time.Duration
	// MaxSecretIDUses caps the SecretID's num_uses and is used when the
	// caller sets none. 0 means no limit: the role decides.
	MaxSecretIDUses int
	// MaxSecretIDTTL caps the SecretID's ttl and is used when the caller
	// sets none. 0 means no limit: the role decides.
	MaxSecretIDTTL time.Duration

	// TrustedProxies are reverse proxies whose X-Forwarded-For header is
	// used to find the client address. Requests from any other address are
	// attributed to the connection's peer, and the header is ignored.
	TrustedProxies []netip.Prefix
	// ChallengeRate is the sustained rate, per second, of challenge requests
	// allowed per client network (an IPv4 address or IPv6 /64). Default 1.
	ChallengeRate float64
	// ChallengeBurst is how many challenge requests a client network may
	// make at once before ChallengeRate applies. Default 20.
	ChallengeBurst int

	// MachineSecretIDs is how many SecretIDs one machine may create per
	// MachineSecretIDWindow; the allowance refills gradually. 0 means no
	// limit.
	MachineSecretIDs      int
	MachineSecretIDWindow time.Duration
	// BindClientAddress lists "mount/role" patterns (path.Match syntax, e.g.
	// "approle/*") whose SecretIDs, and the tokens issued with them, only
	// work from the address that requested them. Only useful if Vault sees
	// machines at the same address as this server.
	BindClientAddress []string
	// ExclusiveSecretID lists "mount/role" patterns whose roles keep a
	// single SecretID: issuing one destroys the role's other SecretIDs. Each
	// matching role must belong to exactly one machine in the registry.
	ExclusiveSecretID []string
}

// Server implements api.StrictServerInterface.
type Server struct {
	keys       AgeKeyStore
	authz      Authorizer
	vault      SecretIDIssuer
	log        *slog.Logger
	challenges *challengeStore
	limiter    *keyedLimiter[netip.Prefix]
	sampler    *logSampler
	metrics    *metrics
	maxWrapTTL time.Duration
	now        func() time.Time

	maxSecretIDUses   int
	maxSecretIDTTL    time.Duration
	issueTimeout      time.Duration
	machineLimiter    *keyedLimiter[string] // nil: no limit
	bindClientAddress []string
	exclusiveSecretID []string
	exclusiveLocks    keyedMutex

	trustedProxies []netip.Prefix
}

var _ api.StrictServerInterface = (*Server)(nil)

func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	s := &Server{
		keys:       cfg.Keys,
		authz:      cfg.Authorizer,
		vault:      cfg.Vault,
		log:        cfg.Log,
		challenges: newChallengeStore(cfg.ChallengeTTL),
		limiter:    newKeyedLimiter[netip.Prefix](rate.Limit(cfg.ChallengeRate), cfg.ChallengeBurst),
		sampler:    newLogSampler(auditSampleInterval),
		maxWrapTTL: cfg.MaxWrapTTL,
		now:        time.Now,

		trustedProxies:  cfg.TrustedProxies,
		maxSecretIDUses: cfg.MaxSecretIDUses,
		maxSecretIDTTL:  cfg.MaxSecretIDTTL,
		issueTimeout:    vaultIssueTimeout,

		bindClientAddress: cfg.BindClientAddress,
		exclusiveSecretID: cfg.ExclusiveSecretID,
	}
	if cfg.MachineSecretIDs > 0 {
		perSecond := float64(cfg.MachineSecretIDs) / cfg.MachineSecretIDWindow.Seconds()
		s.machineLimiter = newKeyedLimiter[string](rate.Limit(perSecond), cfg.MachineSecretIDs)
	}
	m, err := newMetrics(cfg.Metrics, func() float64 { return float64(s.challenges.count(s.now())) })
	if err != nil {
		return nil, fmt.Errorf("server: register metrics: %w", err)
	}
	s.metrics = m
	return s, nil
}

func (cfg *Config) validate() error {
	if cfg.Keys == nil || cfg.Authorizer == nil || cfg.Vault == nil {
		return errors.New("server: Keys, Authorizer and Vault are required")
	}
	if cfg.MaxSecretIDUses < 0 || cfg.MaxSecretIDTTL < 0 {
		return errors.New("server: MaxSecretIDUses and MaxSecretIDTTL must not be negative")
	}
	if cfg.MachineSecretIDs < 0 || (cfg.MachineSecretIDs > 0 && cfg.MachineSecretIDWindow <= 0) {
		return errors.New("server: MachineSecretIDs must not be negative and needs a positive MachineSecretIDWindow")
	}
	return errors.Join(
		validRolePatterns("BindClientAddress", cfg.BindClientAddress),
		validRolePatterns("ExclusiveSecretID", cfg.ExclusiveSecretID),
	)
}

// setDefaults fills in unset optional fields.
func (cfg *Config) setDefaults() {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = prometheus.NewRegistry()
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = defaultChallengeTTL
	}
	if cfg.MaxWrapTTL <= 0 {
		cfg.MaxWrapTTL = defaultMaxWrapTTL
	}
	if cfg.ChallengeRate <= 0 {
		cfg.ChallengeRate = defaultChallengeRate
	}
	if cfg.ChallengeBurst <= 0 {
		cfg.ChallengeBurst = defaultChallengeBurst
	}
}

// Handler returns the HTTP handler serving all API routes on a stdlib mux.
func (s *Server) Handler() http.Handler {
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.requestError,
		ResponseErrorHandlerFunc: s.responseError,
	})
	h := api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter: http.NewServeMux(),
		// The last middleware runs first: authenticate, then the body check.
		Middlewares:      []api.MiddlewareFunc{s.rejectUnknownFields, s.authenticate},
		ErrorHandlerFunc: s.requestError,
	})
	// instrument must wrap the mux directly: it reads r.Pattern, which the
	// mux sets on the *http.Request it is given.
	return http.MaxBytesHandler(s.withClientIP(s.metrics.instrument(h)), maxBodyBytes)
}

// requestError handles errors decoding path parameters or the request body.
func (s *Server) requestError(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, http.StatusBadRequest, err.Error())
}

// responseError handles errors returned by handlers. Details are logged, not
// returned, so internal failures do not leak to callers.
func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody(msg))
}

func errorBody(msg string) api.Error {
	return api.Error{Errors: []string{msg}}
}
