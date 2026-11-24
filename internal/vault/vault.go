// Package vault is a minimal Vault/OpenBao HTTP client for issuing
// response-wrapped AppRole SecretIDs.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxResponseBytes caps response bodies read from Vault.
const maxResponseBytes = 8 << 20

// Client talks to a single Vault/OpenBao server. Its token is either static
// or obtained with LoginAppRole and kept fresh with KeepAlive; it can be
// replaced while requests are in flight.
type Client struct {
	addr  *url.URL
	token atomic.Pointer[string]
	// expiry is when the token's lease ends, in Unix nanoseconds; 0 if unknown
	// or the token does not expire.
	expiry atomic.Int64
	http   *http.Client
}

// New returns a client for the server at addr. token may be empty if the
// client logs in with LoginAppRole before use. If hc is nil a client with a
// 30 second timeout is used.
func New(addr, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse vault address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("vault address %q: scheme must be http or https", addr)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := &Client{addr: u, http: hc}
	c.setToken(token)
	return c, nil
}

func (c *Client) setToken(token string) { c.token.Store(&token) }

func (c *Client) currentToken() string { return *c.token.Load() }

// do sends a request with an optional JSON body and decodes a 2xx response
// into out, if non-nil. token, if non-empty, is sent as X-Vault-Token.
// Non-2xx responses are returned as *Error.
func (c *Client) do(ctx context.Context, method string, u *url.URL, token string, header http.Header, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return err
	}
	maps.Copy(req.Header, header)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.NewDecoder(lr).Decode(&e)
		return &Error{StatusCode: resp.StatusCode, Errors: e.Errors}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(lr).Decode(out); err != nil {
		return fmt.Errorf("vault: decode response: %w", err)
	}
	return nil
}

// SecretIDRequest holds the optional SecretID parameters.
type SecretIDRequest struct {
	Metadata        map[string]string
	CIDRList        []string
	TokenBoundCIDRs []string
	TTL             time.Duration
	NumUses         *int
}

// WrapInfo is the response-wrapping information returned by Vault.
type WrapInfo struct {
	Token        string    `json:"token"`
	Accessor     string    `json:"accessor"`
	TTL          int       `json:"ttl"`
	CreationTime time.Time `json:"creation_time"`
	CreationPath string    `json:"creation_path"`
}

// Error is a non-2xx response from Vault.
type Error struct {
	StatusCode int
	Errors     []string
}

func (e *Error) Error() string {
	return fmt.Sprintf("vault: status %d: %s", e.StatusCode, strings.Join(e.Errors, "; "))
}

// WrappedSecretID creates a SecretID for role on the AppRole mount and
// returns it response-wrapped with wrapTTL. The SecretID itself is never
// visible to this client.
func (c *Client) WrappedSecretID(ctx context.Context, mount, role string, wrapTTL time.Duration, req SecretIDRequest) (*WrapInfo, error) {
	body := map[string]any{}
	if len(req.Metadata) > 0 {
		// Vault expects metadata as a JSON-encoded string.
		md, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, err
		}
		body["metadata"] = string(md)
	}
	if len(req.CIDRList) > 0 {
		body["cidr_list"] = req.CIDRList
	}
	if len(req.TokenBoundCIDRs) > 0 {
		body["token_bound_cidrs"] = req.TokenBoundCIDRs
	}
	if req.TTL > 0 {
		body["ttl"] = int(req.TTL / time.Second)
	}
	if req.NumUses != nil {
		body["num_uses"] = *req.NumUses
	}
	u := c.addr.JoinPath("v1", "auth", mount, "role", role, "secret-id")
	header := http.Header{"X-Vault-Wrap-Ttl": {strconv.Itoa(int(wrapTTL / time.Second))}}
	var out struct {
		WrapInfo *WrapInfo `json:"wrap_info"`
	}
	if err := c.do(ctx, http.MethodPost, u, c.currentToken(), header, body, &out); err != nil {
		return nil, err
	}
	if out.WrapInfo == nil || out.WrapInfo.Token == "" {
		return nil, errors.New("vault: response was not wrapped")
	}
	return out.WrapInfo, nil
}

// ReadKV2 returns the data of the latest version of the KV v2 secret at path
// on mount. A missing or deleted secret is an *Error with StatusCode 404.
func (c *Client) ReadKV2(ctx context.Context, mount, path string) (json.RawMessage, error) {
	u := c.addr.JoinPath("v1", mount, "data", path)
	var out struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, u, c.currentToken(), nil, nil, &out); err != nil {
		return nil, err
	}
	if len(out.Data.Data) == 0 || string(out.Data.Data) == "null" {
		return nil, &Error{StatusCode: http.StatusNotFound, Errors: []string{"secret has no data"}}
	}
	return out.Data.Data, nil
}
