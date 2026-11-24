package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/soerenschneider/approle-courier/internal/registry"
	"github.com/soerenschneider/approle-courier/internal/server"
	"github.com/soerenschneider/approle-courier/internal/vault"
)

// config is the service configuration. It is built from defaults, an
// optional JSON file (-config) and command-line flags, in increasing order
// of precedence. Secrets do not belong in it: the Vault token comes from the
// environment and the AppRole secret_id from a file.
//
// Example file, with every field optional:
//
//	{
//	  "listen": {
//	    "api": ":8080",
//	    "metrics": ":9090",
//	    "tls_cert": "/etc/approle-courier/tls/cert.pem",
//	    "tls_key": "/etc/approle-courier/tls/key.pem",
//	    "trusted_proxies": ["10.0.0.0/24"],
//	    "proxy_protocol": false,
//	    "drain_delay": "5s"
//	  },
//	  "limits": {
//	    "max_wrap_ttl": "15m",
//	    "max_secret_id_uses": 1,
//	    "max_secret_id_ttl": "1h",
//	    "machine_secret_ids": 10,
//	    "machine_secret_ids_window": "1h",
//	    "bind_client_address": ["approle/*"],
//	    "exclusive_secret_id": ["approle/vm-*"],
//	    "challenge_ttl": "1m",
//	    "challenge_rate": 1,
//	    "challenge_burst": 20
//	  },
//	  "log": {
//	    "level": "info",
//	    "format": "json"
//	  },
//	  "registry": {
//	    "file": "machines.json",
//	    "kv_mount": "secret",
//	    "kv_path": "approle-courier/registry",
//	    "cache_ttl": "10s"
//	  },
//	  "vault": {
//	    "address": "https://openbao.example.com:8200",
//	    "timeout": "10s",
//	    "approle": {
//	      "mount": "approle-service",
//	      "role_id": "approle-courier",
//	      "secret_id_file": "/run/secrets/approle-courier-secret-id"
//	    }
//	  }
//	}
type config struct {
	Listen   listenConfig   `json:"listen"`
	Limits   limitsConfig   `json:"limits"`
	Log      logConfig      `json:"log"`
	Registry registryConfig `json:"registry"`
	Vault    vaultConfig    `json:"vault"`
}

type logConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type listenConfig struct {
	API            string     `json:"api"`
	Metrics        string     `json:"metrics"`
	TLSCert        string     `json:"tls_cert"`
	TLSKey         string     `json:"tls_key"`
	TrustedProxies stringList `json:"trusted_proxies"`
	ProxyProtocol  bool       `json:"proxy_protocol"`
	DrainDelay     duration   `json:"drain_delay"`
}

type limitsConfig struct {
	MaxWrapTTL             duration   `json:"max_wrap_ttl"`
	MaxSecretIDUses        int        `json:"max_secret_id_uses"`
	MaxSecretIDTTL         duration   `json:"max_secret_id_ttl"`
	MachineSecretIDs       int        `json:"machine_secret_ids"`
	MachineSecretIDsWindow duration   `json:"machine_secret_ids_window"`
	BindClientAddress      stringList `json:"bind_client_address"`
	ExclusiveSecretID      stringList `json:"exclusive_secret_id"`
	ChallengeTTL           duration   `json:"challenge_ttl"`
	ChallengeRate          float64    `json:"challenge_rate"`
	ChallengeBurst         int        `json:"challenge_burst"`
}

type registryConfig struct {
	File     string   `json:"file"`
	KVMount  string   `json:"kv_mount"`
	KVPath   string   `json:"kv_path"`
	CacheTTL duration `json:"cache_ttl"`
}

type vaultConfig struct {
	Address string        `json:"address"`
	Timeout duration      `json:"timeout"`
	AppRole appRoleConfig `json:"approle"`
}

type appRoleConfig struct {
	Mount        string `json:"mount"`
	RoleID       string `json:"role_id"`
	SecretIDFile string `json:"secret_id_file"`
}

// serverConfig translates c into the server's configuration, combined with
// the server's dependencies. trusted is c.Listen.TrustedProxies, parsed.
func (c config) serverConfig(reg *registry.Registry, vc *vault.Client, log *slog.Logger, metrics prometheus.Registerer, trusted []netip.Prefix) server.Config {
	return server.Config{
		Keys:       reg,
		Authorizer: reg,
		Vault:      vc,
		Log:        log,
		Metrics:    metrics,

		TrustedProxies: trusted,
		ChallengeTTL:   time.Duration(c.Limits.ChallengeTTL),
		ChallengeRate:  c.Limits.ChallengeRate,
		ChallengeBurst: c.Limits.ChallengeBurst,

		MaxWrapTTL:            time.Duration(c.Limits.MaxWrapTTL),
		MaxSecretIDUses:       c.Limits.MaxSecretIDUses,
		MaxSecretIDTTL:        time.Duration(c.Limits.MaxSecretIDTTL),
		MachineSecretIDs:      c.Limits.MachineSecretIDs,
		MachineSecretIDWindow: time.Duration(c.Limits.MachineSecretIDsWindow),
		BindClientAddress:     c.Limits.BindClientAddress,
		ExclusiveSecretID:     c.Limits.ExclusiveSecretID,
	}
}

func defaultConfig(getenv func(string) string) config {
	return config{
		Listen: listenConfig{API: ":8080", Metrics: ":9090", DrainDelay: duration(5 * time.Second)},
		Limits: limitsConfig{
			MaxWrapTTL:             duration(15 * time.Minute),
			MaxSecretIDUses:        1,
			MaxSecretIDTTL:         duration(time.Hour),
			MachineSecretIDs:       10,
			MachineSecretIDsWindow: duration(time.Hour),
			ChallengeTTL:           duration(time.Minute),
			ChallengeRate:          1,
			ChallengeBurst:         20,
		},
		Log: logConfig{Level: "info", Format: "json"},
		Registry: registryConfig{
			File:     "machines.json",
			KVMount:  "secret",
			CacheTTL: duration(5 * time.Minute),
		},
		Vault: vaultConfig{
			Address: cmp.Or(getenv("BAO_ADDR"), getenv("VAULT_ADDR"), "http://127.0.0.1:8200"),
			Timeout: duration(10 * time.Second),
			AppRole: appRoleConfig{Mount: "approle", RoleID: getenv("BAO_ROLE_ID")},
		},
	}
}

// bindFlags registers a flag for every field of c, defaulting to its current
// value.
func bindFlags(fs *flag.FlagSet, c *config) {
	fs.StringVar(&c.Listen.API, "addr", c.Listen.API, "listen address")
	fs.StringVar(&c.Listen.Metrics, "metrics-addr", c.Listen.Metrics, "listen address for Prometheus metrics on /metrics; empty disables it")
	fs.StringVar(&c.Listen.TLSCert, "tls-cert", c.Listen.TLSCert, "PEM certificate (chain) the API listener serves over TLS; reloaded when the file changes. Requires -tls-key")
	fs.StringVar(&c.Listen.TLSKey, "tls-key", c.Listen.TLSKey, "PEM private key for -tls-cert")
	fs.Var(&c.Listen.TrustedProxies, "trusted-proxies", "comma-separated addresses or CIDRs of reverse proxies whose X-Forwarded-For header (or PROXY protocol header, with -proxy-protocol) gives the client address")
	fs.BoolVar(&c.Listen.ProxyProtocol, "proxy-protocol", c.Listen.ProxyProtocol, "require a PROXY protocol header on API connections from -trusted-proxies (HAProxy send-proxy/send-proxy-v2)")
	fs.Var(&c.Listen.DrainDelay, "drain-delay", "on SIGTERM, how long /readyz reports not ready while requests are still served, before the listeners close")

	fs.Var(&c.Limits.MaxWrapTTL, "max-wrap-ttl", "maximum wrap_ttl a caller may request")
	fs.IntVar(&c.Limits.MaxSecretIDUses, "max-secret-id-uses", c.Limits.MaxSecretIDUses, "maximum num_uses of a created SecretID, and the value used when the caller sets none; 0 leaves it to the role")
	fs.Var(&c.Limits.MaxSecretIDTTL, "max-secret-id-ttl", "maximum ttl of a created SecretID, and the value used when the caller sets none; 0 leaves it to the role")
	fs.IntVar(&c.Limits.MachineSecretIDs, "machine-secret-ids", c.Limits.MachineSecretIDs, "SecretIDs one machine may create per -machine-secret-ids-window, refilling gradually; 0 disables the limit")
	fs.Var(&c.Limits.MachineSecretIDsWindow, "machine-secret-ids-window", "window for -machine-secret-ids")
	fs.Var(&c.Limits.BindClientAddress, "bind-client-address", "comma-separated mount/role patterns (e.g. approle/*) whose SecretIDs and tokens only work from the requesting address; requires that Vault sees machines at the same address")
	fs.Var(&c.Limits.ExclusiveSecretID, "exclusive-secret-id", "comma-separated mount/role patterns (e.g. approle/vm-*) of roles that keep a single SecretID: issuing one destroys the role's other SecretIDs; each such role must belong to exactly one machine")
	fs.Var(&c.Limits.ChallengeTTL, "challenge-ttl", "how long a challenge token stays valid")
	fs.Float64Var(&c.Limits.ChallengeRate, "challenge-rate", c.Limits.ChallengeRate, "challenge requests per second allowed per client address (IPv6: per /64)")
	fs.IntVar(&c.Limits.ChallengeBurst, "challenge-burst", c.Limits.ChallengeBurst, "challenge requests a client address may make at once before -challenge-rate applies")

	fs.StringVar(&c.Log.Level, "log-level", c.Log.Level, "log level: debug, info, warn or error")
	fs.StringVar(&c.Log.Format, "log-format", c.Log.Format, "log format: json or text")

	fs.StringVar(&c.Registry.File, "registry", c.Registry.File, "path to the machine registry file; ignored if -registry-kv-path is set")
	fs.StringVar(&c.Registry.KVMount, "registry-kv-mount", c.Registry.KVMount, "KV v2 mount holding the machine registry secret")
	fs.StringVar(&c.Registry.KVPath, "registry-kv-path", c.Registry.KVPath, "path of the KV v2 secret holding the machine registry; if set, the registry is read from Vault instead of -registry")
	fs.Var(&c.Registry.CacheTTL, "registry-cache-ttl", "how long the registry is cached before the file or KV secret is read again")

	fs.StringVar(&c.Vault.Address, "vault-addr", c.Vault.Address, "Vault/OpenBao address (default $BAO_ADDR, then $VAULT_ADDR)")
	fs.Var(&c.Vault.Timeout, "vault-timeout", "timeout of a single Vault request; all Vault calls for one SecretID request are additionally bounded by 20s")
	fs.StringVar(&c.Vault.AppRole.Mount, "vault-approle-mount", c.Vault.AppRole.Mount, "AppRole auth mount this service logs in with")
	fs.StringVar(&c.Vault.AppRole.RoleID, "vault-approle-role-id", c.Vault.AppRole.RoleID, "role_id this service logs in with (default $BAO_ROLE_ID); if set, AppRole is used instead of $BAO_TOKEN")
	fs.StringVar(&c.Vault.AppRole.SecretIDFile, "vault-approle-secret-id-file", c.Vault.AppRole.SecretIDFile, "file containing the secret_id for -vault-approle-role-id; re-read on every login")
}

// loadConfig builds the configuration from args (without the program name).
// printConfig and printVersion report whether -print-config and -version
// were given.
func loadConfig(args []string, getenv func(string) string) (cfg config, printConfig, printVersion bool, err error) {
	flags := defaultConfig(getenv)
	fs := flag.NewFlagSet("approle-courier", flag.ContinueOnError)
	var path string
	fs.StringVar(&path, "config", "", "JSON config file; flags given on the command line override it")
	fs.BoolVar(&printConfig, "print-config", false, "print the effective configuration as JSON and exit")
	fs.BoolVar(&printVersion, "version", false, "print the version and exit")
	bindFlags(fs, &flags)
	if err := fs.Parse(args); err != nil {
		return config{}, false, false, err
	}
	if fs.NArg() > 0 {
		return config{}, false, false, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if path == "" {
		return flags, printConfig, printVersion, nil
	}

	// Apply the file to the defaults, then re-apply the flags that were given
	// explicitly; fs's values still hold what they were set to.
	cfg = defaultConfig(getenv)
	if err := decodeConfigFile(path, &cfg); err != nil {
		return config{}, false, false, err
	}
	explicit := flag.NewFlagSet("", flag.ContinueOnError)
	bindFlags(explicit, &cfg)
	fs.Visit(func(f *flag.Flag) {
		if explicit.Lookup(f.Name) != nil {
			err = errors.Join(err, explicit.Set(f.Name, f.Value.String()))
		}
	})
	return cfg, printConfig, printVersion, err
}

// decodeConfigFile decodes the JSON file at path into c, leaving fields the
// file does not mention unchanged. Unknown fields are an error, so typos do
// not go unnoticed.
func decodeConfigFile(path string, c *config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("config %s: unexpected data after the JSON object", path)
	}
	return nil
}

// duration is a time.Duration written as a string like "90s" in JSON and on
// the command line.
type duration time.Duration

func (d duration) String() string { return time.Duration(d).String() }

func (d *duration) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(v)
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf(`duration must be a string like "90s": %w`, err)
	}
	return d.Set(s)
}

// stringList is a JSON array of strings, given on the command line as a
// comma-separated list that replaces the whole list.
type stringList []string

func (l stringList) String() string { return strings.Join(l, ",") }

func (l *stringList) Set(s string) error {
	*l = nil
	for f := range strings.SplitSeq(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			*l = append(*l, f)
		}
	}
	return nil
}
