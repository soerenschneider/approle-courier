package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealth(t *testing.T) {
	var registryErr error
	expiry := time.Now().Add(time.Hour)
	var logs strings.Builder
	h := &health{log: slog.New(slog.NewTextHandler(&logs, nil)), checks: map[string]func(context.Context) error{
		"registry":    func(context.Context) error { return registryErr },
		"vault_token": tokenNotExpired(func() time.Time { return expiry }),
	}}
	mux := http.NewServeMux()
	h.register(mux)

	get := func(path string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return rec.Code, body
	}

	if code, _ := get("/readyz"); code != http.StatusOK {
		t.Errorf("ready: status = %d", code)
	}

	registryErr = errors.New("vault down")
	expiry = time.Now().Add(-time.Minute)
	code, body := get("/readyz")
	if code != http.StatusServiceUnavailable || fmt.Sprint(body["failed"]) != "[registry vault_token]" {
		t.Errorf("unready: status = %d, body = %v", code, body)
	}
	if strings.Contains(fmt.Sprint(body), "vault down") {
		t.Errorf("error details exposed: %v", body)
	}
	get("/readyz")
	if n := strings.Count(logs.String(), "not ready"); n != 1 || !strings.Contains(logs.String(), "vault down") {
		t.Errorf("want one log line with the error, got:\n%s", logs.String())
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz while unready: status = %d, want 200", code)
	}

	registryErr, expiry = nil, time.Time{}
	h.shuttingDown.Store(true)
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || body["status"] != "shutting down" {
		t.Errorf("shutting down: status = %d, body = %v", code, body)
	}
}
