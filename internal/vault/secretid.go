package vault

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrSecretIDNotFound is returned when a SecretID no longer exists, e.g.
// because it was used up, expired or destroyed concurrently.
var ErrSecretIDNotFound = errors.New("vault: secret-id not found")

// SecretIDInfo is what Vault reports about an existing SecretID.
type SecretIDInfo struct {
	Metadata map[string]string `json:"metadata"`
	// ExpirationTime is the zero time if the SecretID does not expire.
	ExpirationTime time.Time `json:"expiration_time"`
}

// ListSecretIDAccessors returns the accessors of the role's SecretIDs.
func (c *Client) ListSecretIDAccessors(ctx context.Context, mount, role string) ([]string, error) {
	u := c.addr.JoinPath("v1", "auth", mount, "role", role, "secret-id")
	u.RawQuery = "list=true"
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, u, c.currentToken(), nil, nil, &out)
	var verr *Error
	if errors.As(err, &verr) && verr.StatusCode == http.StatusNotFound {
		// Vault answers 404 if the role has no SecretIDs.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return out.Data.Keys, nil
}

// LookupSecretIDAccessor returns information about the SecretID with the
// given accessor, or ErrSecretIDNotFound.
func (c *Client) LookupSecretIDAccessor(ctx context.Context, mount, role, accessor string) (*SecretIDInfo, error) {
	u := c.addr.JoinPath("v1", "auth", mount, "role", role, "secret-id-accessor", "lookup")
	var out struct {
		Data *SecretIDInfo `json:"data"`
	}
	err := c.do(ctx, http.MethodPost, u, c.currentToken(), nil, map[string]string{"secret_id_accessor": accessor}, &out)
	var verr *Error
	if errors.As(err, &verr) && verr.StatusCode == http.StatusNotFound {
		return nil, ErrSecretIDNotFound
	}
	if err != nil {
		return nil, err
	}
	if out.Data == nil {
		return nil, ErrSecretIDNotFound
	}
	return out.Data, nil
}

// DestroySecretIDAccessor destroys the SecretID with the given accessor. It
// returns ErrSecretIDNotFound if it no longer exists.
func (c *Client) DestroySecretIDAccessor(ctx context.Context, mount, role, accessor string) error {
	u := c.addr.JoinPath("v1", "auth", mount, "role", role, "secret-id-accessor", "destroy")
	err := c.do(ctx, http.MethodPost, u, c.currentToken(), nil, map[string]string{"secret_id_accessor": accessor}, nil)
	var verr *Error
	// OpenBao and Vault answer 500, not 404, for an unknown accessor.
	if errors.As(err, &verr) && (verr.StatusCode == http.StatusNotFound ||
		strings.Contains(strings.Join(verr.Errors, " "), "failed to find accessor entry")) {
		return ErrSecretIDNotFound
	}
	return err
}
