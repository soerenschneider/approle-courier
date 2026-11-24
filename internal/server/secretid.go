package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/soerenschneider/approle-courier/internal/vault"
)

// vaultIssueTimeout bounds all Vault calls made for one SecretID request,
// including retries. It must stay below the API server's WriteTimeout (30s
// in main), or a SecretID could be created whose response never reaches the
// caller.
const vaultIssueTimeout = 20 * time.Second

// Vault's errors when a requested option exceeds the role's own limit.
const (
	vaultTTLTooLong     = "ttl cannot be longer than the role's secret_id_ttl"
	vaultNumUsesTooHigh = "num_uses cannot be higher than the role's secret_id_num_uses"
)

// defaultedOptions records which SecretID options the server filled in
// because the caller left them out.
type defaultedOptions struct {
	ttl     bool
	numUses bool
}

// limitViolation is a requested SecretID option above the server's limit.
type limitViolation struct {
	reason string // metrics label
	msg    string
}

// applySecretIDLimits checks the requested ttl and num_uses against the
// server's limits and sets options the caller left out to the limit, so the
// limit holds even if the role itself allows more (or no limit at all).
func (s *Server) applySecretIDLimits(req *vault.SecretIDRequest) (defaultedOptions, *limitViolation) {
	var d defaultedOptions
	if s.maxSecretIDUses > 0 {
		switch {
		case req.NumUses == nil:
			n := s.maxSecretIDUses
			req.NumUses, d.numUses = &n, true
		case *req.NumUses == 0 || *req.NumUses > s.maxSecretIDUses:
			// 0 means unlimited to Vault.
			return d, &limitViolation{"num_uses_too_high", fmt.Sprintf("secret_id.num_uses must be between 1 and %d", s.maxSecretIDUses)}
		}
	}
	if s.maxSecretIDTTL > 0 {
		switch {
		case req.TTL == 0:
			req.TTL, d.ttl = s.maxSecretIDTTL, true
		case req.TTL > s.maxSecretIDTTL:
			return d, &limitViolation{"ttl_too_long", fmt.Sprintf("secret_id.ttl exceeds maximum of %s", s.maxSecretIDTTL)}
		}
	}
	return d, nil
}

// wrappedSecretID requests the SecretID from Vault. If Vault rejects an
// option the server filled in because the role's own limit is lower, it
// retries without that option: the role's limit then applies, and it is
// stricter than the server's. Options the caller set are never dropped.
func (s *Server) wrappedSecretID(ctx context.Context, mount, role string, wrapTTL time.Duration, req vault.SecretIDRequest, d defaultedOptions) (*vault.WrapInfo, error) {
	for {
		start := time.Now()
		wi, err := s.vault.WrappedSecretID(ctx, mount, role, wrapTTL, req)
		s.metrics.vaultDuration.Observe(time.Since(start).Seconds())

		var verr *vault.Error
		if err == nil || !errors.As(err, &verr) || verr.StatusCode != 400 {
			return wi, err
		}
		msg := strings.Join(verr.Errors, " ")
		switch {
		case d.ttl && strings.Contains(msg, vaultTTLTooLong):
			req.TTL, d.ttl = 0, false
		case d.numUses && strings.Contains(msg, vaultNumUsesTooHigh):
			req.NumUses, d.numUses = nil, false
		default:
			return nil, err
		}
	}
}

// matchesRole reports whether "mount/role" matches one of patterns
// (path.Match syntax, e.g. "approle/*").
func matchesRole(patterns []string, mount, role string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, mount+"/"+role); ok {
			return true
		}
	}
	return false
}

// bindToClient restricts the SecretID and the tokens issued with it to
// client. It returns false, leaving req unchanged, if the caller set either
// CIDR list itself.
func bindToClient(req *vault.SecretIDRequest, client netip.Addr) bool {
	if len(req.CIDRList) > 0 || len(req.TokenBoundCIDRs) > 0 {
		return false
	}
	cidr := netip.PrefixFrom(client, client.BitLen()).String()
	req.CIDRList, req.TokenBoundCIDRs = []string{cidr}, []string{cidr}
	return true
}

// validRolePatterns checks patterns for matchesRole; option names them in
// the error.
func validRolePatterns(option string, patterns []string) error {
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil || strings.Count(p, "/") != 1 {
			return fmt.Errorf("server: %s: invalid pattern %q: want mount/role, e.g. \"approle/*\"", option, p)
		}
	}
	return nil
}
