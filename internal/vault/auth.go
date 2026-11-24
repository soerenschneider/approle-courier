package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	// renewFraction of a token's lease elapses before it is renewed.
	renewFraction = 2.0 / 3.0
	// minLoginBackoff and maxLoginBackoff bound the delay between failed
	// login attempts.
	minLoginBackoff = time.Second
	maxLoginBackoff = 30 * time.Second
)

// AppRole holds the credentials the client logs in with.
type AppRole struct {
	// Mount is the AppRole auth mount, without the "auth/" prefix.
	Mount  string
	RoleID string
	// SecretID returns the SecretID. It is called on every login, so a
	// rotated SecretID is picked up without a restart.
	SecretID func() (string, error)
}

// Auth describes the client's current token.
type Auth struct {
	LeaseDuration time.Duration
	Renewable     bool
}

type authResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginAppRole logs in with a and makes the resulting token the client's
// token.
func (c *Client) LoginAppRole(ctx context.Context, a AppRole) (*Auth, error) {
	secretID, err := a.SecretID()
	if err != nil {
		return nil, fmt.Errorf("vault: read approle secret_id: %w", err)
	}
	u := c.addr.JoinPath("v1", "auth", a.Mount, "login")
	var out authResponse
	body := map[string]string{"role_id": a.RoleID, "secret_id": secretID}
	start := time.Now()
	if err := c.do(ctx, http.MethodPost, u, "", nil, body, &out); err != nil {
		return nil, fmt.Errorf("vault: approle login: %w", err)
	}
	if out.Auth == nil || out.Auth.ClientToken == "" {
		return nil, errors.New("vault: approle login returned no token")
	}
	c.setToken(out.Auth.ClientToken)
	return c.recordAuth(&out, start), nil
}

// renewSelf renews the client's token.
func (c *Client) renewSelf(ctx context.Context) (*Auth, error) {
	u := c.addr.JoinPath("v1", "auth", "token", "renew-self")
	var out authResponse
	start := time.Now()
	if err := c.do(ctx, http.MethodPost, u, c.currentToken(), nil, struct{}{}, &out); err != nil {
		return nil, fmt.Errorf("vault: renew token: %w", err)
	}
	if out.Auth == nil {
		return nil, errors.New("vault: token renewal returned no auth")
	}
	return c.recordAuth(&out, start), nil
}

// recordAuth converts a login or renewal response and records the token's
// expiry, counting the lease from start, when the request was sent.
func (c *Client) recordAuth(out *authResponse, start time.Time) *Auth {
	auth := &Auth{
		LeaseDuration: time.Duration(out.Auth.LeaseDuration) * time.Second,
		Renewable:     out.Auth.Renewable,
	}
	var expiry int64
	if auth.LeaseDuration > 0 {
		expiry = start.Add(auth.LeaseDuration).UnixNano()
	}
	c.expiry.Store(expiry)
	return auth
}

// TokenExpiry returns when the current token's lease ends. It is the zero
// time for a static token or one that does not expire.
func (c *Client) TokenExpiry() time.Time {
	if ns := c.expiry.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// RevokeSelf revokes the client's token and clears it. Call it only once
// nothing else uses the client, and after KeepAlive has returned, which
// would otherwise log in again.
func (c *Client) RevokeSelf(ctx context.Context) error {
	u := c.addr.JoinPath("v1", "auth", "token", "revoke-self")
	if err := c.do(ctx, http.MethodPost, u, c.currentToken(), nil, struct{}{}, nil); err != nil {
		return fmt.Errorf("vault: revoke token: %w", err)
	}
	c.setToken("")
	c.expiry.Store(0)
	return nil
}

// KeepAlive keeps the token from a's login valid until ctx is done. auth is
// the result of the initial LoginAppRole.
//
// The token is renewed after two thirds of its lease. When it cannot be
// renewed (not renewable, renewal failed, or its max TTL leaves less than a
// third of the original lease) KeepAlive logs in again, retrying with
// backoff. Requests keep using the old token until a new one is obtained.
func (c *Client) KeepAlive(ctx context.Context, a AppRole, auth *Auth, log *slog.Logger) {
	loginTTL := auth.LeaseDuration
	for {
		if auth.LeaseDuration <= 0 {
			log.Info("vault token does not expire; not renewing")
			return
		}
		expires := time.Now().Add(auth.LeaseDuration)
		if !sleep(ctx, time.Duration(float64(auth.LeaseDuration)*renewFraction)) {
			return
		}

		if auth.Renewable {
			renewed, err := c.renewSelf(ctx)
			switch {
			case err != nil:
				log.Warn("vault token renewal failed; logging in again", "err", err)
			case renewed.LeaseDuration < loginTTL/3:
				log.Info("vault token is near its max TTL; logging in again", "lease", renewed.LeaseDuration.String())
			default:
				log.Debug("renewed vault token", "lease", renewed.LeaseDuration.String())
				auth = renewed
				continue
			}
		}

		var ok bool
		if auth, ok = c.relogin(ctx, a, expires, log); !ok {
			return
		}
		loginTTL = auth.LeaseDuration
	}
}

// relogin logs in with a until it succeeds or ctx is done. expires is when
// the current token stops working, for logging.
func (c *Client) relogin(ctx context.Context, a AppRole, expires time.Time, log *slog.Logger) (*Auth, bool) {
	backoff := minLoginBackoff
	for {
		auth, err := c.LoginAppRole(ctx, a)
		if err == nil {
			log.Info("logged in to vault with approle", "lease", auth.LeaseDuration.String())
			return auth, true
		}
		if ctx.Err() != nil {
			return nil, false
		}
		log.Error("vault approle login failed", "err", err, "retry_in", backoff, "token_expires_at", expires)
		if !sleep(ctx, backoff) {
			return nil, false
		}
		backoff = min(2*backoff, maxLoginBackoff)
	}
}

// sleep waits for d and reports whether it did so before ctx was done.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
