package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/soerenschneider/approle-courier/internal"
	"github.com/soerenschneider/approle-courier/internal/registry"
	"github.com/soerenschneider/approle-courier/internal/server"
	"github.com/soerenschneider/approle-courier/internal/vault"
)

func main() {
	cfg, printConfig, printVersion, err := loadConfig(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if printVersion {
		fmt.Println(internal.BuildVersion)
		return
	}
	if printConfig {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cfg)
		return
	}

	log, err := newLogger(cfg.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	log.Info("starting approle-courier", "version", internal.BuildVersion, "commit", internal.CommitHash)
	if err := run(cfg, log); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// newLogger returns a logger writing to stderr in the configured format and
// level.
func newLogger(cfg logConfig) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch cfg.Format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	}
	return nil, fmt.Errorf("log format %q: want json or text", cfg.Format)
}

func run(cfg config, log *slog.Logger) error {
	trusted, err := parsePrefixes(cfg.Listen.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted proxies: %w", err)
	}
	if cfg.Listen.ProxyProtocol && len(trusted) == 0 {
		return errors.New("proxy protocol requires trusted proxies")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	promReg := prometheus.NewRegistry()
	promReg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	vc, closeVault, err := vaultClient(cfg, promReg, log)
	if err != nil {
		return err
	}
	// Deferred so it runs after the HTTP servers have shut down and no
	// request uses the token any more.
	defer closeVault()
	health := &health{log: log, checks: map[string]func(context.Context) error{
		"vault_token": tokenNotExpired(vc.TokenExpiry),
	}}
	reg, err := newRegistry(cfg.Registry, vc, health, log)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg.serverConfig(reg, vc, log, promReg, trusted))
	if err != nil {
		return err
	}

	tlsConfig, err := newTLSConfig(cfg.Listen, promReg, log)
	if err != nil {
		return err
	}
	apiMux := http.NewServeMux()
	health.register(apiMux)
	apiMux.Handle("/", srv.Handler())
	servers, err := newServers(cfg.Listen, trusted, apiMux, tlsConfig, promReg)
	if err != nil {
		return err
	}
	return serve(ctx, servers, health, time.Duration(cfg.Listen.DrainDelay), log)
}

// newRegistry returns the machine registry, loaded from the KV v2 secret if
// one is configured and from the file otherwise. It must be readable at
// startup and is added to the readiness checks.
func newRegistry(cfg registryConfig, vc *vault.Client, health *health, log *slog.Logger) (*registry.Registry, error) {
	var source registry.Source = registry.FileSource{Path: cfg.File}
	if cfg.KVPath != "" {
		source = registry.KVSource{Reader: vc, Mount: cfg.KVMount, Path: cfg.KVPath}
	}
	reg := registry.New(source, time.Duration(cfg.CacheTTL))
	checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := reg.Check(checkCtx); err != nil {
		return nil, err
	}
	log.Info("loaded machine registry", "source", source.String(), "cache_ttl", time.Duration(cfg.CacheTTL).String())
	health.checks["registry"] = reg.Check
	return reg, nil
}

// newTLSConfig returns the API listener's TLS configuration, or nil if TLS
// is not configured, and exports the certificate's expiry as a metric.
func newTLSConfig(cfg listenConfig, reg prometheus.Registerer, log *slog.Logger) (*tls.Config, error) {
	if cfg.TLSCert == "" && cfg.TLSKey == "" {
		return nil, nil
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil, errors.New("tls_cert and tls_key must be set together")
	}
	certs, err := newCertReloader(cfg.TLSCert, cfg.TLSKey, log)
	if err != nil {
		return nil, err
	}
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "approle_courier",
		Name:      "tls_cert_expiry_timestamp_seconds",
		Help:      "Unix time at which the API listener's TLS certificate expires.",
	}, func() float64 { return float64(certs.expiry().Unix()) }))
	return certs.tlsConfig(), nil
}

// listeningServer is an HTTP server with its listener already bound.
type listeningServer struct {
	*http.Server
	ln            net.Listener
	proxyProtocol bool
}

// newServers binds the API listener and, unless disabled, the metrics
// listener. Metrics get their own listener so they can stay off the API's
// network exposure.
func newServers(cfg listenConfig, trusted []netip.Prefix, api http.Handler, tlsConfig *tls.Config, promReg *prometheus.Registry) ([]listeningServer, error) {
	apiLn, err := listen(cfg.API, cfg.ProxyProtocol, trusted)
	if err != nil {
		return nil, err
	}
	servers := []listeningServer{{
		Server: &http.Server{
			Handler:           api,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		ln:            apiLn,
		proxyProtocol: cfg.ProxyProtocol,
	}}
	if cfg.Metrics == "" {
		return servers, nil
	}
	metricsLn, err := listen(cfg.Metrics, false, nil)
	if err != nil {
		apiLn.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{Registry: promReg}))
	return append(servers, listeningServer{
		Server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		ln: metricsLn,
	}), nil
}

// serve runs servers until one fails or ctx is done, then shuts them all
// down. On ctx being done, /readyz reports not ready for drainDelay first
// while requests are still served, so load balancers stop sending requests
// before the listeners close.
func serve(ctx context.Context, servers []listeningServer, health *health, drainDelay time.Duration, log *slog.Logger) error {
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			tls := s.TLSConfig != nil
			log.Info("listening", "addr", s.ln.Addr().String(), "tls", tls, "proxy_protocol", s.proxyProtocol)
			if tls {
				// TLS sits on top of the PROXY protocol listener: the PROXY
				// header precedes the TLS handshake on the wire.
				errc <- s.ServeTLS(s.ln, "", "")
			} else {
				errc <- s.Serve(s.ln)
			}
		}()
	}

	var runErr error
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case <-ctx.Done():
		health.shuttingDown.Store(true)
		if drainDelay > 0 {
			log.Info("draining before shutdown", "delay", drainDelay.String())
			time.Sleep(drainDelay)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		runErr = errors.Join(runErr, s.Shutdown(shutdownCtx))
	}
	return runErr
}

// useAppRole reports whether to log in with AppRole (a role_id is
// configured) rather than use the static token, and checks that exactly one
// of them is configured completely.
func useAppRole(cfg appRoleConfig, token string) (bool, error) {
	switch {
	case cfg.RoleID == "" && token == "":
		return false, errors.New("no vault credentials: set -vault-approle-role-id or $BAO_TOKEN")
	case cfg.RoleID == "":
		return false, nil
	case token != "":
		return false, errors.New("set either -vault-approle-role-id or $BAO_TOKEN, not both")
	case cfg.SecretIDFile == "":
		return false, errors.New("-vault-approle-secret-id-file is required with -vault-approle-role-id")
	}
	return true, nil
}

// vaultClient returns a client authenticated with AppRole or with a static
// token from the environment, and a function to call on shutdown.
//
// With AppRole, the token is kept fresh in the background, its expiry is
// exported as a metric, and the close function stops the renewal and revokes
// the token. A static token is left alone.
func vaultClient(cfg config, reg prometheus.Registerer, log *slog.Logger) (*vault.Client, func(), error) {
	token := cmp.Or(os.Getenv("BAO_TOKEN"), os.Getenv("VAULT_TOKEN"))
	if cfg.Vault.Timeout <= 0 {
		return nil, nil, errors.New("vault timeout must be positive")
	}
	vc, err := vault.New(cfg.Vault.Address, token, &http.Client{Timeout: time.Duration(cfg.Vault.Timeout)})
	if err != nil {
		return nil, nil, err
	}
	useAppRole, err := useAppRole(cfg.Vault.AppRole, token)
	if err != nil {
		return nil, nil, err
	}
	if !useAppRole {
		log.Info("authenticating to vault with a static token")
		return vc, func() {}, nil
	}

	a := vault.AppRole{
		Mount:  cfg.Vault.AppRole.Mount,
		RoleID: cfg.Vault.AppRole.RoleID,
		SecretID: func() (string, error) {
			b, err := os.ReadFile(cfg.Vault.AppRole.SecretIDFile) //nolint:gosec // G703: path is set by the operator in the config, not by clients.
			return strings.TrimSpace(string(b)), err
		},
	}
	loginCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	auth, err := vc.LoginAppRole(loginCtx, a)
	if err != nil {
		return nil, nil, err
	}
	log.Info("logged in to vault with approle", "mount", a.Mount, "lease", auth.LeaseDuration.String(), "renewable", auth.Renewable)

	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "approle_courier",
		Name:      "vault_token_expiry_timestamp_seconds",
		Help:      "Unix time at which the service's Vault token expires; +Inf if it does not expire.",
	}, func() float64 {
		exp := vc.TokenExpiry()
		if exp.IsZero() {
			return math.Inf(1)
		}
		return float64(exp.UnixNano()) / 1e9
	}))

	keepAliveCtx, stopKeepAlive := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		vc.KeepAlive(keepAliveCtx, a, auth, log)
	}()

	return vc, func() {
		// Stop renewal first so it cannot log in again after the revoke.
		stopKeepAlive()
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := vc.RevokeSelf(ctx); err != nil {
			log.Warn("revoking vault token failed; it expires on its own", "err", err)
			return
		}
		log.Info("revoked vault token")
	}, nil
}
