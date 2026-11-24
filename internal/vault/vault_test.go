package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWrappedSecretID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/approle/role/my-role/secret-id" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "s.token" || r.Header.Get("X-Vault-Wrap-TTL") != "300" {
			t.Errorf("headers = %v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["metadata"] != `{"machine_id":"node-42"}` || body["ttl"] != float64(3600) {
			t.Errorf("body = %v", body)
		}
		_, _ = w.Write([]byte(`{"wrap_info":{"token":"hvs.wrapped","accessor":"acc","ttl":300,"creation_time":"2026-10-22T09:00:00Z","creation_path":"auth/approle/role/my-role/secret-id"}}`))
	}))
	defer ts.Close()

	c, err := New(ts.URL, "s.token", nil)
	if err != nil {
		t.Fatal(err)
	}
	wi, err := c.WrappedSecretID(context.Background(), "approle", "my-role", 5*time.Minute, SecretIDRequest{
		Metadata: map[string]string{"machine_id": "node-42"},
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wi.Token != "hvs.wrapped" || wi.Accessor != "acc" || wi.TTL != 300 {
		t.Fatalf("wrap info = %+v", wi)
	}
}

func TestWrappedSecretIDError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["role \"x\" does not exist"]}`))
	}))
	defer ts.Close()

	c, err := New(ts.URL, "s.token", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.WrappedSecretID(context.Background(), "approle", "x", time.Minute, SecretIDRequest{})
	var verr *Error
	if !errors.As(err, &verr) || verr.StatusCode != 400 || len(verr.Errors) != 1 {
		t.Fatalf("err = %v", err)
	}
}

func TestReadKV2(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "s.token":
			t.Errorf("request = %s, headers = %v", r.Method, r.Header)
		case r.URL.Path == "/v1/secret/data/approle-courier/registry":
			_, _ = w.Write([]byte(`{"data":{"data":{"machines":{}},"metadata":{"version":3}}}`))
		case r.URL.Path == "/v1/secret/data/deleted":
			// Vault answers 404 with metadata for a deleted latest version.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":{"data":null,"metadata":{"deletion_time":"2026-10-22T09:00:00Z"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer ts.Close()

	c, err := New(ts.URL, "s.token", nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.ReadKV2(context.Background(), "secret", "approle-courier/registry")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"machines":{}}` {
		t.Errorf("data = %s", data)
	}
	for _, path := range []string{"deleted", "missing"} {
		_, err := c.ReadKV2(context.Background(), "secret", path)
		var verr *Error
		if !errors.As(err, &verr) || verr.StatusCode != http.StatusNotFound {
			t.Errorf("%s: err = %v", path, err)
		}
	}
}

func TestSecretIDAccessors(t *testing.T) {
	// Responses as observed from OpenBao.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.URL.Path == "/v1/auth/approle/role/vm1/secret-id" && r.URL.Query().Get("list") == "true":
			_, _ = w.Write([]byte(`{"data":{"keys":["acc-1","acc-2"]}}`))
		case r.URL.Path == "/v1/auth/approle/role/empty/secret-id":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		case strings.HasSuffix(r.URL.Path, "/secret-id-accessor/lookup") && body["secret_id_accessor"] == "acc-1":
			_, _ = w.Write([]byte(`{"data":{"metadata":{"machine_id":"vm1"},"expiration_time":"2026-10-30T22:01:26+01:00"}}`))
		case strings.HasSuffix(r.URL.Path, "/secret-id-accessor/lookup"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":{"error":"failed to find accessor entry for secret_id_accessor: \"x\""}}`))
		case strings.HasSuffix(r.URL.Path, "/secret-id-accessor/destroy") && body["secret_id_accessor"] == "acc-1":
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/secret-id-accessor/destroy"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":["1 error occurred:\n\t* failed to find accessor entry for secret_id_accessor: \"x\"\n\n"]}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
	}))
	defer ts.Close()
	c, err := New(ts.URL, "s.token", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if keys, err := c.ListSecretIDAccessors(ctx, "approle", "vm1"); err != nil || len(keys) != 2 {
		t.Errorf("list = %v, %v", keys, err)
	}
	if keys, err := c.ListSecretIDAccessors(ctx, "approle", "empty"); err != nil || len(keys) != 0 {
		t.Errorf("list empty = %v, %v", keys, err)
	}
	info, err := c.LookupSecretIDAccessor(ctx, "approle", "vm1", "acc-1")
	if err != nil || info.Metadata["machine_id"] != "vm1" || info.ExpirationTime.IsZero() {
		t.Errorf("lookup = %+v, %v", info, err)
	}
	if _, err := c.LookupSecretIDAccessor(ctx, "approle", "vm1", "gone"); !errors.Is(err, ErrSecretIDNotFound) {
		t.Errorf("lookup gone: err = %v", err)
	}
	if err := c.DestroySecretIDAccessor(ctx, "approle", "vm1", "acc-1"); err != nil {
		t.Errorf("destroy: %v", err)
	}
	if err := c.DestroySecretIDAccessor(ctx, "approle", "vm1", "gone"); !errors.Is(err, ErrSecretIDNotFound) {
		t.Errorf("destroy gone: err = %v", err)
	}
}
