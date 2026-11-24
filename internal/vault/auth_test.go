package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeAuthVault issues tokens "t1", "t2", ... on login and renews the
// current token while renewOK is true.
type fakeAuthVault struct {
	t *testing.T

	mu       sync.Mutex
	logins   int
	renewals int
	revoked  []string
	renewOK  bool
	lease    int
	current  string
}

func (f *fakeAuthVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.URL.Path {
	case "/v1/auth/approle/login":
		if r.Header.Get("X-Vault-Token") != "" {
			f.t.Errorf("login sent a token")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != "role" || body["secret_id"] != "secret" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":["invalid role or secret ID"]}`)
			return
		}
		f.logins++
		f.current = fmt.Sprintf("t%d", f.logins)
		fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":%d,"renewable":true}}`, f.current, f.lease)
	case "/v1/auth/token/renew-self":
		if r.Header.Get("X-Vault-Token") != f.current || !f.renewOK {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		f.renewals++
		fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":%d,"renewable":true}}`, f.current, f.lease)
	case "/v1/auth/token/revoke-self":
		f.revoked = append(f.revoked, r.Header.Get("X-Vault-Token"))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeAuthVault) state() (logins, renewals int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.renewals
}

func testAppRole(secret string) AppRole {
	return AppRole{Mount: "approle", RoleID: "role", SecretID: func() (string, error) { return secret, nil }}
}

func TestLoginAppRole(t *testing.T) {
	f := &fakeAuthVault{t: t, lease: 60}
	ts := httptest.NewServer(f)
	defer ts.Close()
	c, err := New(ts.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if !c.TokenExpiry().IsZero() {
		t.Errorf("expiry before login = %v", c.TokenExpiry())
	}
	before := time.Now()
	auth, err := c.LoginAppRole(context.Background(), testAppRole("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if auth.LeaseDuration != time.Minute || !auth.Renewable || c.currentToken() != "t1" {
		t.Fatalf("auth = %+v, token = %q", auth, c.currentToken())
	}
	if exp := c.TokenExpiry(); exp.Before(before.Add(time.Minute)) || exp.After(time.Now().Add(time.Minute)) {
		t.Errorf("expiry = %v, want about a minute from now", exp)
	}
	if _, err := c.LoginAppRole(context.Background(), testAppRole("wrong")); err == nil {
		t.Fatal("login with wrong secret_id succeeded")
	}
	if c.currentToken() != "t1" {
		t.Errorf("failed login replaced token: %q", c.currentToken())
	}
}

func TestKeepAlive(t *testing.T) {
	f := &fakeAuthVault{t: t, lease: 1, renewOK: true}
	ts := httptest.NewServer(f)
	defer ts.Close()
	c, err := New(ts.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a := testAppRole("secret")
	auth, err := c.LoginAppRole(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.KeepAlive(ctx, a, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "renewal", func() bool { _, r := f.state(); return r >= 1 })

	// Renewal starts failing: KeepAlive logs in again for a new token.
	f.mu.Lock()
	f.renewOK = false
	f.mu.Unlock()
	waitFor(t, "re-login with a new token", func() bool { return c.currentToken() == "t2" })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRevokeSelf(t *testing.T) {
	f := &fakeAuthVault{t: t, lease: 60}
	ts := httptest.NewServer(f)
	defer ts.Close()
	c, err := New(ts.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoginAppRole(context.Background(), testAppRole("secret")); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "t1" {
		t.Errorf("revoked = %v, want [t1]", f.revoked)
	}
	if c.currentToken() != "" || !c.TokenExpiry().IsZero() {
		t.Errorf("token = %q, expiry = %v after revoke", c.currentToken(), c.TokenExpiry())
	}
}
