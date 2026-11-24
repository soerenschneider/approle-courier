package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/soerenschneider/approle-courier/internal/registry"
	"github.com/soerenschneider/approle-courier/internal/server"
	"github.com/soerenschneider/approle-courier/internal/vault"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, printConfig, _, err := loadConfig(nil, env(map[string]string{"VAULT_ADDR": "https://vault:8200", "BAO_ROLE_ID": "svc"}))
	if err != nil {
		t.Fatal(err)
	}
	want := defaultConfig(env(nil))
	want.Vault.Address = "https://vault:8200"
	want.Vault.AppRole.RoleID = "svc"
	if printConfig || !reflect.DeepEqual(cfg, want) {
		t.Errorf("cfg = %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigPrecedence(t *testing.T) {
	path := writeConfig(t, `{
		"listen": {"api": ":8443", "trusted_proxies": ["10.0.0.0/24"]},
		"limits": {"max_wrap_ttl": "5m", "challenge_burst": 50},
		"registry": {"kv_path": "approle-courier/registry"},
		"vault": {"address": "https://from-file:8200", "approle": {"role_id": "file-role"}}
	}`)
	cfg, _, _, err := loadConfig([]string{
		"-config", path,
		"-challenge-burst", "7",
		"-trusted-proxies", "192.0.2.1, 192.0.2.2",
	}, env(map[string]string{"BAO_ADDR": "https://from-env:8200", "BAO_ROLE_ID": "env-role"}))
	if err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"file over default", cfg.Listen.API, ":8443"},
		{"file over env", cfg.Vault.Address, "https://from-file:8200"},
		{"file over env role", cfg.Vault.AppRole.RoleID, "file-role"},
		{"file duration", time.Duration(cfg.Limits.MaxWrapTTL), 5 * time.Minute},
		{"flag over file", cfg.Limits.ChallengeBurst, 7},
		{"flag list over file", []string(cfg.Listen.TrustedProxies), []string{"192.0.2.1", "192.0.2.2"}},
		{"default kept", cfg.Listen.Metrics, ":9090"},
		{"default duration kept", cfg.Registry.CacheTTL, defaultConfig(env(nil)).Registry.CacheTTL},
		{"default mount kept", cfg.Registry.KVMount, "secret"},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":   `{"listen": {"apii": ":8080"}}`,
		"bad duration":    `{"limits": {"max_wrap_ttl": "5 minutes"}}`,
		"number duration": `{"limits": {"max_wrap_ttl": 300}}`,
		"trailing data":   `{} {}`,
		"not json":        `addr = ":8080"`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := loadConfig([]string{"-config", writeConfig(t, content)}, env(nil)); err == nil {
				t.Fatal("no error")
			}
		})
	}
	if _, _, _, err := loadConfig([]string{"-config", "/does/not/exist.json"}, env(nil)); err == nil || !strings.Contains(err.Error(), "config") {
		t.Errorf("missing file: err = %v", err)
	}
	if _, _, _, err := loadConfig([]string{"stray"}, env(nil)); err == nil {
		t.Error("stray argument accepted")
	}
}

func TestNewLogger(t *testing.T) {
	for _, c := range []logConfig{{"info", "json"}, {"debug", "text"}, {"WARN", "json"}} {
		if _, err := newLogger(c); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, c := range []logConfig{{"verbose", "json"}, {"info", "xml"}} {
		if _, err := newLogger(c); err == nil {
			t.Errorf("%+v: accepted", c)
		}
	}
}

func TestLoadConfigNewLimits(t *testing.T) {
	path := writeConfig(t, `{"limits": {"challenge_ttl": "30s", "machine_secret_ids": 3, "bind_client_address": ["approle/*"]}, "log": {"level": "debug"}}`)
	cfg, _, _, err := loadConfig([]string{"-config", path, "-log-format", "text"}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Limits.ChallengeTTL) != 30*time.Second || cfg.Limits.MachineSecretIDs != 3 ||
		time.Duration(cfg.Limits.MachineSecretIDsWindow) != time.Hour || !reflect.DeepEqual([]string(cfg.Limits.BindClientAddress), []string{"approle/*"}) ||
		cfg.Log != (logConfig{Level: "debug", Format: "text"}) {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestServerConfig(t *testing.T) {
	path := writeConfig(t, `{"limits": {
		"max_wrap_ttl": "2m", "max_secret_id_uses": 3, "max_secret_id_ttl": "4m",
		"machine_secret_ids": 5, "machine_secret_ids_window": "6m", "bind_client_address": ["approle/x"],
		"exclusive_secret_id": ["approle/vm-*"],
		"challenge_ttl": "7s", "challenge_rate": 8, "challenge_burst": 9
	}}`)
	cfg, _, _, err := loadConfig([]string{"-config", path}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	got := cfg.serverConfig(nil, nil, nil, nil, trusted)
	want := server.Config{
		// nil pointers in non-nil interfaces
		Keys:                  (*registry.Registry)(nil),
		Authorizer:            (*registry.Registry)(nil),
		Vault:                 (*vault.Client)(nil),
		TrustedProxies:        trusted,
		ChallengeTTL:          7 * time.Second,
		ChallengeRate:         8,
		ChallengeBurst:        9,
		MaxWrapTTL:            2 * time.Minute,
		MaxSecretIDUses:       3,
		MaxSecretIDTTL:        4 * time.Minute,
		MachineSecretIDs:      5,
		MachineSecretIDWindow: 6 * time.Minute,
		BindClientAddress:     []string{"approle/x"},
		ExclusiveSecretID:     []string{"approle/vm-*"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("serverConfig =\n%+v\nwant\n%+v", got, want)
	}
}
