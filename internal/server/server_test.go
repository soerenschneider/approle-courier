package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/soerenschneider/approle-courier/internal/vault"
	"github.com/soerenschneider/approle-courier/pkg/client"
)

type fakeKeys map[string]string

func (f fakeKeys) AgeRecipient(_ context.Context, id string) (string, error) {
	r, ok := f[id]
	if !ok {
		return "", ErrUnknownMachine
	}
	return r, nil
}

type fakeAuthz map[string]string // machine -> "mount/role"

func (f fakeAuthz) Authorized(_ context.Context, id, mount, role string) (bool, error) {
	return f[id] == mount+"/"+role, nil
}

func (f fakeAuthz) MachinesWithRole(_ context.Context, mount, role string) ([]string, error) {
	var ids []string
	for id, r := range f {
		if r == mount+"/"+role {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

type fakeVault struct {
	err     error
	mount   string
	wrapTTL time.Duration
	req     vault.SecretIDRequest
	calls   int

	// Role limits, enforced with OpenBao's error messages; 0 is unlimited.
	roleTTL     time.Duration
	roleNumUses int
	// hang makes calls block until their context is done.
	hang bool

	// secretIDs are the existing SecretIDs by accessor; WrappedSecretID
	// adds to them. destroyErr fails DestroySecretIDAccessor.
	secretIDs  map[string]*vault.SecretIDInfo
	destroyErr error
}

func (f *fakeVault) ListSecretIDAccessors(context.Context, string, string) ([]string, error) {
	return slices.Sorted(maps.Keys(f.secretIDs)), nil
}

func (f *fakeVault) LookupSecretIDAccessor(_ context.Context, _, _, accessor string) (*vault.SecretIDInfo, error) {
	info, ok := f.secretIDs[accessor]
	if !ok {
		return nil, vault.ErrSecretIDNotFound
	}
	return info, nil
}

func (f *fakeVault) DestroySecretIDAccessor(_ context.Context, _, _, accessor string) error {
	if f.destroyErr != nil {
		return f.destroyErr
	}
	if _, ok := f.secretIDs[accessor]; !ok {
		return vault.ErrSecretIDNotFound
	}
	delete(f.secretIDs, accessor)
	return nil
}

func (f *fakeVault) WrappedSecretID(ctx context.Context, mount, role string, wrapTTL time.Duration, req vault.SecretIDRequest) (*vault.WrapInfo, error) {
	f.calls++
	if f.hang {
		<-ctx.Done()
		return nil, &url.Error{Op: "Post", URL: "http://vault", Err: ctx.Err()}
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.roleTTL > 0 && req.TTL > f.roleTTL {
		return nil, &vault.Error{StatusCode: 400, Errors: []string{"ttl cannot be longer than the role's secret_id_ttl"}}
	}
	if f.roleNumUses > 0 && req.NumUses != nil && (*req.NumUses == 0 || *req.NumUses > f.roleNumUses) {
		return nil, &vault.Error{StatusCode: 400, Errors: []string{"num_uses cannot be higher than the role's secret_id_num_uses"}}
	}
	f.mount, f.wrapTTL, f.req = mount, wrapTTL, req
	if f.secretIDs == nil {
		f.secretIDs = map[string]*vault.SecretIDInfo{}
	}
	info := &vault.SecretIDInfo{Metadata: maps.Clone(req.Metadata)}
	if req.TTL > 0 {
		info.ExpirationTime = time.Now().Add(req.TTL)
	}
	f.secretIDs[fmt.Sprintf("acc-%d", f.calls)] = info
	return &vault.WrapInfo{ //nolint:gosec // G101: fake token for tests.
		Token:        "hvs.wrapping-token",
		Accessor:     "wrap-accessor",
		TTL:          int(wrapTTL / time.Second),
		CreationTime: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC),
		CreationPath: "auth/" + mount + "/role/" + role + "/secret-id",
	}, nil
}

type harness struct {
	c   *client.ClientWithResponses
	id  *age.X25519Identity
	vlt *fakeVault
	srv *Server
	url string
}

func newHarness(t *testing.T, opts ...func(*Config)) *harness {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vlt := &fakeVault{}
	cfg := Config{
		Keys:       fakeKeys{"node-42": id.Recipient().String()},
		Authorizer: fakeAuthz{"node-42": "approle/my-role"},
		Vault:      vlt,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c, err := client.NewClientWithResponses(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{c: c, id: id, vlt: vlt, srv: srv, url: ts.URL}
}

func (h *harness) decrypt(t *testing.T, ciphertext string) string {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(ciphertext)), h.id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// login requests a challenge and returns the decrypted bearer token.
func (h *harness) login(t *testing.T) string {
	t.Helper()
	resp, err := h.c.CreateChallengeWithResponse(context.Background(), client.CreateChallengeJSONRequestBody{MachineId: "node-42"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.JSON201 == nil {
		t.Fatalf("challenge: status = %d, body = %s", resp.StatusCode(), resp.Body)
	}
	return h.decrypt(t, resp.JSON201.Challenge.Value)
}

func bearer(token string) client.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
}

func durationOf(t *testing.T, s string) *client.Duration {
	t.Helper()
	var d client.Duration
	if err := d.FromDuration1(s); err != nil {
		t.Fatal(err)
	}
	return &d
}

func TestCreateWrappedSecretId(t *testing.T) {
	h := newHarness(t)
	token := h.login(t)

	numUses := 1
	resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{
		WrapTtl:  durationOf(t, "2m"),
		SecretId: &client.SecretIdOptions{NumUses: &numUses},
	}, bearer(token))
	if err != nil {
		t.Fatal(err)
	}
	if resp.JSON201 == nil {
		t.Fatalf("status = %d, body = %s", resp.StatusCode(), resp.Body)
	}
	if got := resp.HTTPResponse.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := h.decrypt(t, resp.JSON201.EncryptedWrapToken.Value); got != "hvs.wrapping-token" {
		t.Errorf("decrypted wrap token = %q", got)
	}
	if resp.JSON201.WrapInfo.Accessor != "wrap-accessor" || resp.JSON201.WrapInfo.Ttl != 120 {
		t.Errorf("wrap_info = %+v", resp.JSON201.WrapInfo)
	}
	if h.vlt.wrapTTL != 2*time.Minute {
		t.Errorf("vault wrapTTL = %s", h.vlt.wrapTTL)
	}
	if md := h.vlt.req.Metadata; len(md) != 1 || md["machine_id"] != "node-42" {
		t.Errorf("vault metadata = %v", md)
	}
	if h.vlt.mount != "approle" {
		t.Errorf("vault mount = %q, want default approle", h.vlt.mount)
	}

	// The token is single-use.
	resp, err = h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(token))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusUnauthorized {
		t.Errorf("reused token: status = %d, want 401", resp.StatusCode())
	}
}

func TestCreateWrappedSecretIdErrors(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		body     client.CreateWrappedSecretIdJSONRequestBody
		vaultErr error
		want     int
	}{
		{name: "forbidden role", role: "other-role", want: http.StatusForbidden},
		{name: "leading dot role", role: ".hidden", want: http.StatusBadRequest},
		{name: "bad wrap_ttl", role: "my-role", body: client.CreateWrappedSecretIdJSONRequestBody{WrapTtl: durationOf(t, "5d")}, want: http.StatusBadRequest},
		{name: "wrap_ttl too long", role: "my-role", body: client.CreateWrappedSecretIdJSONRequestBody{WrapTtl: durationOf(t, "1h")}, want: http.StatusUnprocessableEntity},
		{name: "vault role missing", role: "my-role", vaultErr: &vault.Error{StatusCode: 400, Errors: []string{`role "my-role" does not exist`}}, want: http.StatusNotFound},
		{name: "vault rejects options", role: "my-role", vaultErr: &vault.Error{StatusCode: 400, Errors: []string{"bad ttl"}}, want: http.StatusUnprocessableEntity},
		{name: "vault sealed", role: "my-role", vaultErr: &vault.Error{StatusCode: 503}, want: http.StatusServiceUnavailable},
		{name: "vault denied", role: "my-role", vaultErr: &vault.Error{StatusCode: 403}, want: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vlt.err = tt.vaultErr
			resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), tt.role, nil, tt.body, bearer(h.login(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode() != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode(), tt.want, resp.Body)
			}
		})
	}
}

func TestCreateWrappedSecretIdRequiresToken(t *testing.T) {
	h := newHarness(t)

	for name, editors := range map[string][]client.RequestEditorFn{
		"missing": nil,
		"unknown": {bearer("not-a-real-token")},
	} {
		resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, editors...)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode() != http.StatusUnauthorized || resp.JSON401 == nil {
			t.Fatalf("%s: status = %d, body = %s", name, resp.StatusCode(), resp.Body)
		}
		if got := resp.HTTPResponse.Header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("%s: WWW-Authenticate = %q", name, got)
		}
	}
}

func TestCreateChallengeErrors(t *testing.T) {
	h := newHarness(t)

	for id, want := range map[string]int{"": http.StatusBadRequest, "../x": http.StatusBadRequest, "node-7": http.StatusNotFound} {
		resp, err := h.c.CreateChallengeWithResponse(context.Background(), client.CreateChallengeJSONRequestBody{MachineId: id})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode() != want {
			t.Errorf("machine_id %q: status = %d, want %d", id, resp.StatusCode(), want)
		}
	}
}

func TestCreateChallengeRateLimit(t *testing.T) {
	h := newHarness(t)
	for range maxPendingChallenges {
		h.login(t)
	}
	resp, err := h.c.CreateChallengeWithResponse(context.Background(), client.CreateChallengeJSONRequestBody{MachineId: "node-42"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusTooManyRequests || resp.HTTPResponse.Header.Get("Retry-After") != "60" {
		t.Fatalf("status = %d, Retry-After = %q", resp.StatusCode(), resp.HTTPResponse.Header.Get("Retry-After"))
	}
}

func TestChallengeExpiry(t *testing.T) {
	c := newChallengeStore(time.Minute)
	now := time.Now()
	token, _, err := c.issue("node-42", netip.MustParsePrefix("192.0.2.1/32"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.redeem(token, now.Add(time.Minute)); ok {
		t.Fatal("expired token redeemed")
	}
	if len(c.byHash) != 0 || len(c.pending) != 0 {
		t.Fatalf("store not cleaned up: %d tokens, %d pending", len(c.byHash), len(c.pending))
	}
}

func TestMetrics(t *testing.T) {
	h := newHarness(t)
	m := h.srv.metrics

	token := h.login(t)
	if got := testutil.ToFloat64(m.challengesIssued); got != 1 {
		t.Errorf("challenges_issued_total = %v, want 1", got)
	}
	if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(token)); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.secretIDsIssued.WithLabelValues("approle", "my-role")); got != 1 {
		t.Errorf("secret_ids_issued_total = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.vaultDuration); got != 1 {
		t.Errorf("vault_request_duration_seconds series = %d, want 1", got)
	}

	// Reusing the token fails authentication.
	if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(token)); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.authFailures.WithLabelValues("invalid_token")); got != 1 {
		t.Errorf("auth_failures_total{reason=invalid_token} = %v, want 1", got)
	}

	h.vlt.err = &vault.Error{StatusCode: 503}
	if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t))); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.vaultErrors.WithLabelValues(vaultErrSealed)); got != 1 {
		t.Errorf("vault_errors_total{kind=sealed} = %v, want 1", got)
	}

	route := "POST /v1/approle/roles/{role_name}/secret-id"
	for code, want := range map[string]float64{"201": 1, "401": 1, "503": 1} {
		if got := testutil.ToFloat64(m.httpRequests.WithLabelValues(route, code)); got != want {
			t.Errorf("http_requests_total{code=%s} = %v, want %v", code, got, want)
		}
	}
}

func TestChallengesPendingGauge(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.login(t)
	if got := h.srv.challenges.count(h.srv.now()); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
}

func TestCreateWrappedSecretIdMount(t *testing.T) {
	tests := []struct {
		mount string
		want  int
	}{
		{mount: "approle", want: http.StatusCreated},
		{mount: "other", want: http.StatusForbidden},
		{mount: "", want: http.StatusBadRequest},
		{mount: "..", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.mount, func(t *testing.T) {
			h := newHarness(t)
			params := &client.CreateWrappedSecretIdParams{Mount: &tt.mount}
			resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", params, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode() != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode(), tt.want, resp.Body)
			}
		})
	}
}

// downRegistry fails every lookup as an unreadable registry would.
type downRegistry struct{}

func (downRegistry) AgeRecipient(context.Context, string) (string, error) {
	return "", fmt.Errorf("%w: vault down", ErrRegistryUnavailable)
}

func (downRegistry) Authorized(context.Context, string, string, string) (bool, error) {
	return false, fmt.Errorf("%w: vault down", ErrRegistryUnavailable)
}

func (downRegistry) MachinesWithRole(context.Context, string, string) ([]string, error) {
	return nil, fmt.Errorf("%w: vault down", ErrRegistryUnavailable)
}

func TestRegistryUnavailable(t *testing.T) {
	check := func(t *testing.T, h *harness, resp *http.Response) {
		t.Helper()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("status = %d, Retry-After = %q", resp.StatusCode, resp.Header.Get("Retry-After"))
		}
		if got := testutil.ToFloat64(h.srv.metrics.registryErrors); got != 1 {
			t.Errorf("registry_errors_total = %v, want 1", got)
		}
	}

	t.Run("challenge", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Keys = downRegistry{} })
		resp, err := h.c.CreateChallengeWithResponse(context.Background(), client.CreateChallengeJSONRequestBody{MachineId: "node-42"})
		if err != nil {
			t.Fatal(err)
		}
		check(t, h, resp.HTTPResponse)
	})

	t.Run("secret-id", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Authorizer = downRegistry{} })
		resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
		if err != nil {
			t.Fatal(err)
		}
		check(t, h, resp.HTTPResponse)
	})
}

func TestChallengeLockoutByThirdParty(t *testing.T) {
	c := newChallengeStore(time.Minute)
	now := time.Now()
	attacker := netip.MustParsePrefix("203.0.113.7/32")
	machine := netip.MustParsePrefix("192.0.2.42/32")

	for range maxPendingChallenges {
		if _, _, err := c.issue("node-42", attacker, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := c.issue("node-42", attacker, now); !errors.Is(err, errTooManyChallenges) {
		t.Fatalf("attacker over limit: err = %v", err)
	}
	if _, _, err := c.issue("node-42", machine, now); err != nil {
		t.Fatalf("machine locked out by attacker: %v", err)
	}
}

func TestChallengeStoreFull(t *testing.T) {
	c := newChallengeStore(time.Minute)
	c.maxTotal = 2
	now := time.Now()
	for i := range 2 {
		if _, _, err := c.issue(fmt.Sprintf("node-%d", i), netip.MustParsePrefix("192.0.2.1/32"), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := c.issue("node-9", netip.MustParsePrefix("192.0.2.1/32"), now); !errors.Is(err, errChallengeStoreFull) {
		t.Fatalf("err = %v, want errChallengeStoreFull", err)
	}
	// Expired challenges are swept and free up room.
	if _, _, err := c.issue("node-9", netip.MustParsePrefix("192.0.2.1/32"), now.Add(time.Minute)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestChallengeClientRateLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.ChallengeRate, c.ChallengeBurst = 0.1, 2 })
	for i := range 3 {
		resp, err := h.c.CreateChallengeWithResponse(context.Background(), client.CreateChallengeJSONRequestBody{MachineId: "node-7"})
		if err != nil {
			t.Fatal(err)
		}
		want := http.StatusNotFound // unknown machine, but not rate limited
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode() != want {
			t.Fatalf("request %d: status = %d, want %d", i, resp.StatusCode(), want)
		}
		if i == 2 && resp.HTTPResponse.Header.Get("Retry-After") != "10" {
			t.Errorf("Retry-After = %q, want 10", resp.HTTPResponse.Header.Get("Retry-After"))
		}
	}
	if got := testutil.ToFloat64(h.srv.metrics.challengesRejected.WithLabelValues("client_rate_limited")); got != 1 {
		t.Errorf("challenges_rejected_total{reason=client_rate_limited} = %v, want 1", got)
	}
}

func intPtr(n int) *int { return &n }

func TestSecretIDLimits(t *testing.T) {
	limits := func(c *Config) { c.MaxSecretIDUses, c.MaxSecretIDTTL = 1, time.Hour }
	tests := []struct {
		name        string
		opts        *client.SecretIdOptions
		roleTTL     time.Duration
		roleNumUses int
		want        int
		wantTTL     time.Duration // sent to Vault on the last call
		wantNumUses *int
		wantCalls   int
	}{
		{name: "defaults to limits", want: http.StatusCreated, wantTTL: time.Hour, wantNumUses: intPtr(1), wantCalls: 1},
		{name: "within limits", opts: &client.SecretIdOptions{Ttl: durationOf(t, "10m"), NumUses: intPtr(1)}, want: http.StatusCreated, wantTTL: 10 * time.Minute, wantNumUses: intPtr(1), wantCalls: 1},
		{name: "ttl above limit", opts: &client.SecretIdOptions{Ttl: durationOf(t, "2h")}, want: http.StatusUnprocessableEntity},
		{name: "num_uses above limit", opts: &client.SecretIdOptions{NumUses: intPtr(2)}, want: http.StatusUnprocessableEntity},
		{name: "unlimited num_uses", opts: &client.SecretIdOptions{NumUses: intPtr(0)}, want: http.StatusUnprocessableEntity},
		{
			name: "stricter role ttl: default dropped", roleTTL: 10 * time.Minute,
			want: http.StatusCreated, wantTTL: 0, wantNumUses: intPtr(1), wantCalls: 2,
		},
		{
			name: "stricter role ttl: explicit ttl kept", roleTTL: 10 * time.Minute,
			opts: &client.SecretIdOptions{Ttl: durationOf(t, "30m")},
			want: http.StatusUnprocessableEntity, wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, limits)
			h.vlt.roleTTL, h.vlt.roleNumUses = tt.roleTTL, tt.roleNumUses
			resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil,
				client.CreateWrappedSecretIdJSONRequestBody{SecretId: tt.opts}, bearer(h.login(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode() != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode(), tt.want, resp.Body)
			}
			if h.vlt.calls != tt.wantCalls {
				t.Errorf("vault calls = %d, want %d", h.vlt.calls, tt.wantCalls)
			}
			if tt.want != http.StatusCreated {
				return
			}
			if h.vlt.req.TTL != tt.wantTTL {
				t.Errorf("vault ttl = %s, want %s", h.vlt.req.TTL, tt.wantTTL)
			}
			if got := h.vlt.req.NumUses; (got == nil) != (tt.wantNumUses == nil) || (got != nil && *got != *tt.wantNumUses) {
				t.Errorf("vault num_uses = %v, want %v", got, tt.wantNumUses)
			}
		})
	}
}

func TestSecretIDLimitsStricterRoleNumUses(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxSecretIDUses = 5 })
	h.vlt.roleNumUses = 3
	resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusCreated || h.vlt.calls != 2 || h.vlt.req.NumUses != nil {
		t.Fatalf("status = %d, calls = %d, num_uses = %v; want 201 after retrying without num_uses", resp.StatusCode(), h.vlt.calls, h.vlt.req.NumUses)
	}
}

func TestVaultIssueTimeout(t *testing.T) {
	h := newHarness(t)
	h.srv.issueTimeout = 50 * time.Millisecond
	h.vlt.hang = true
	start := time.Now()
	resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body = %s", resp.StatusCode(), resp.Body)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("request took %s; deadline not applied", d)
	}
}

func TestRejectUnknownFields(t *testing.T) {
	h := newHarness(t)
	post := func(path, body string, token string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, h.url+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	tests := []struct {
		name, path, body string
		auth             bool
	}{
		{name: "challenge top-level", path: "/v1/auth/challenge", body: `{"machine_id":"node-42","recipient":"age1x"}`},
		{name: "secret-id top-level", path: "/v1/approle/roles/my-role/secret-id", body: `{"wrap_tll":"1m"}`, auth: true},
		{name: "secret-id nested", path: "/v1/approle/roles/my-role/secret-id", body: `{"secret_id":{"metadata":{"a":"b"}}}`, auth: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			if tt.auth {
				token = h.login(t)
			}
			if code := post(tt.path, tt.body, token); code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", code)
			}
		})
	}
	if h.vlt.calls != 0 {
		t.Errorf("vault called %d times for rejected bodies", h.vlt.calls)
	}

	// The body is passed on intact after the check.
	if code := post("/v1/approle/roles/my-role/secret-id", `{"secret_id":{"num_uses":1}}`, h.login(t)); code != http.StatusCreated {
		t.Errorf("valid body: status = %d, want 201", code)
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func withLogs(buf *syncBuffer) func(*Config) {
	return func(c *Config) { c.Log = slog.New(slog.NewJSONHandler(buf, nil)) }
}

// rejections returns the "request rejected" log lines with the given reason.
func rejections(t *testing.T, logs, reason string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["msg"] == "request rejected" && m["reason"] == reason {
			out = append(out, m)
		}
	}
	return out
}

func TestAuditLog(t *testing.T) {
	var logs syncBuffer
	h := newHarness(t, withLogs(&logs))
	now := time.Now()
	h.srv.now = func() time.Time { return now }

	// Authenticated refusals are logged every time, with machine and role.
	for range 2 {
		if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "other-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t))); err != nil {
			t.Fatal(err)
		}
	}
	forbidden := rejections(t, logs.String(), "forbidden")
	if len(forbidden) != 2 || forbidden[0]["machine_id"] != "node-42" || forbidden[0]["role"] != "other-role" || forbidden[0]["client_ip"] != "127.0.0.1" {
		t.Errorf("forbidden lines = %v", forbidden)
	}

	// Unauthenticated failures are sampled per reason and client.
	for range 3 {
		if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer("secret-guess")); err != nil {
			t.Fatal(err)
		}
	}
	if got := rejections(t, logs.String(), "invalid_token"); len(got) != 1 {
		t.Fatalf("invalid_token lines = %d, want 1 (sampled)", len(got))
	}
	now = now.Add(auditSampleInterval)
	if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer("secret-guess")); err != nil {
		t.Fatal(err)
	}
	got := rejections(t, logs.String(), "invalid_token")
	if len(got) != 2 || got[1]["suppressed"] != float64(2) {
		t.Errorf("after interval: lines = %v, want a second line with suppressed=2", got)
	}
	if strings.Contains(logs.String(), "secret-guess") {
		t.Error("bearer token written to the log")
	}
}

func TestMachineSecretIDLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MachineSecretIDs, c.MachineSecretIDWindow = 2, time.Hour })
	for i := range 3 {
		resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
		if err != nil {
			t.Fatal(err)
		}
		want := http.StatusCreated
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode() != want {
			t.Fatalf("request %d: status = %d, want %d", i, resp.StatusCode(), want)
		}
		if i == 2 && resp.HTTPResponse.Header.Get("Retry-After") != "1800" {
			t.Errorf("Retry-After = %q, want 1800 (one SecretID per 30m)", resp.HTTPResponse.Header.Get("Retry-After"))
		}
	}
	if h.vlt.calls != 2 {
		t.Errorf("vault calls = %d, want 2", h.vlt.calls)
	}
}

func TestBindClientAddress(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		opts     *client.SecretIdOptions
		want     int
		wantCIDR []string
	}{
		{name: "bound", patterns: []string{"approle/*"}, want: http.StatusCreated, wantCIDR: []string{"127.0.0.1/32"}},
		{name: "other role not bound", patterns: []string{"approle/db"}, want: http.StatusCreated},
		{name: "caller cidrs rejected", patterns: []string{"approle/my-role"}, opts: &client.SecretIdOptions{CidrList: &[]string{"10.0.0.0/8"}}, want: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.BindClientAddress = tt.patterns })
			resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{SecretId: tt.opts}, bearer(h.login(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode() != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode(), tt.want, resp.Body)
			}
			if tt.want != http.StatusCreated {
				return
			}
			if fmt.Sprint(h.vlt.req.CIDRList) != fmt.Sprint(tt.wantCIDR) || fmt.Sprint(h.vlt.req.TokenBoundCIDRs) != fmt.Sprint(tt.wantCIDR) {
				t.Errorf("cidr_list = %v, token_bound_cidrs = %v, want %v", h.vlt.req.CIDRList, h.vlt.req.TokenBoundCIDRs, tt.wantCIDR)
			}
		})
	}
}

func TestInvalidConfig(t *testing.T) {
	base := Config{Keys: fakeKeys{}, Authorizer: fakeAuthz{}, Vault: &fakeVault{}}
	for name, mod := range map[string]func(*Config){
		"bind pattern without role": func(c *Config) { c.BindClientAddress = []string{"approle"} },
		"bad bind pattern":          func(c *Config) { c.BindClientAddress = []string{"approle/["} },
		"machine limit no window":   func(c *Config) { c.MachineSecretIDs = 5 },
	} {
		c := base
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAuthenticationBeforeBody(t *testing.T) {
	h := newHarness(t)
	for name, body := range map[string]string{
		"unknown field": `{"secret_id":{"metadata":{"a":"b"}}}`,
		"malformed":     `{"wrap_ttl":`,
	} {
		req, err := http.NewRequest(http.MethodPost, h.url+"/v1/approle/roles/my-role/secret-id", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without token: status = %d, want 401", name, resp.StatusCode)
		}
	}
}

func TestExclusiveSecretID(t *testing.T) {
	var logs syncBuffer
	h := newHarness(t, withLogs(&logs), func(c *Config) { c.ExclusiveSecretID = []string{"approle/*"} })
	h.vlt.secretIDs = map[string]*vault.SecretIDInfo{
		// e.g. created by the machine itself, without metadata
		"still-valid": {ExpirationTime: time.Now().Add(24 * time.Hour)},
		"no-expiry":   {},
		"expired":     {ExpirationTime: time.Now().Add(-time.Hour)},
	}

	resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", resp.StatusCode(), resp.Body)
	}
	// Only the new SecretID is left, and it carries its issue ID.
	if len(h.vlt.secretIDs) != 1 {
		t.Fatalf("secret-ids left = %v, want only the new one", slices.Sorted(maps.Keys(h.vlt.secretIDs)))
	}
	for _, info := range h.vlt.secretIDs {
		if info.Metadata[issueIDKey] == "" || info.Metadata["machine_id"] != "node-42" {
			t.Errorf("new secret-id metadata = %v", info.Metadata)
		}
	}
	// Two of the three destroyed SecretIDs were still valid.
	if got := testutil.ToFloat64(h.srv.metrics.secretIDsSuperseded); got != 2 {
		t.Errorf("secret_ids_superseded_total = %v, want 2", got)
	}
	if !strings.Contains(logs.String(), `"msg":"superseded still-valid secret-ids"`) || !strings.Contains(logs.String(), "still-valid") {
		t.Errorf("superseded secret-ids not logged:\n%s", logs.String())
	}

	// A second SecretID supersedes the first.
	if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t))); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.vlt.secretIDs["acc-1"]; ok || len(h.vlt.secretIDs) != 1 {
		t.Errorf("secret-ids after second issue = %v, want only acc-2", slices.Sorted(maps.Keys(h.vlt.secretIDs)))
	}
}

func TestExclusiveSecretIDErrors(t *testing.T) {
	t.Run("role assigned to several machines", func(t *testing.T) {
		h := newHarness(t, func(c *Config) {
			c.ExclusiveSecretID = []string{"approle/*"}
			c.Authorizer = fakeAuthz{"node-42": "approle/my-role", "node-43": "approle/my-role"}
		})
		resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode() != http.StatusInternalServerError || h.vlt.calls != 0 {
			t.Fatalf("status = %d, vault calls = %d; want 500 before any SecretID is created", resp.StatusCode(), h.vlt.calls)
		}
	})
	t.Run("destroy fails", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.ExclusiveSecretID = []string{"approle/*"} })
		h.vlt.secretIDs = map[string]*vault.SecretIDInfo{"old": {}}
		h.vlt.destroyErr = errors.New("permission denied")
		resp, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t)))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode() != http.StatusCreated {
			t.Fatalf("status = %d; the new SecretID must be delivered anyway", resp.StatusCode())
		}
		if got := testutil.ToFloat64(h.srv.metrics.supersedeErrors); got != 1 {
			t.Errorf("secret_id_supersede_errors_total = %v, want 1", got)
		}
	})
	t.Run("not exclusive", func(t *testing.T) {
		h := newHarness(t)
		h.vlt.secretIDs = map[string]*vault.SecretIDInfo{"old": {}}
		if _, err := h.c.CreateWrappedSecretIdWithResponse(context.Background(), "my-role", nil, client.CreateWrappedSecretIdJSONRequestBody{}, bearer(h.login(t))); err != nil {
			t.Fatal(err)
		}
		if _, ok := h.vlt.secretIDs["old"]; !ok {
			t.Error("secret-id of a non-exclusive role destroyed")
		}
	})
}
