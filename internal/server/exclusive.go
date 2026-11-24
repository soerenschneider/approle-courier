package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/soerenschneider/approle-courier/internal/vault"
)

// issueIDKey is the SecretID metadata key holding a random ID per issued
// SecretID, so the new SecretID of an exclusive role can be told apart from
// the ones it supersedes: its accessor is inside the wrapped response and
// never visible to this server.
const issueIDKey = "issue_id"

// checkExclusive refuses an exclusive role that the registry assigns to
// more than one machine: superseding would destroy the other machines'
// SecretIDs.
func (s *Server) checkExclusive(ctx context.Context, p secretIDParams) (registryDown bool, err error) {
	machines, err := s.authz.MachinesWithRole(ctx, p.mount, p.role)
	if s.registryUnavailable(ctx, err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up machines with role %s/%s: %w", p.mount, p.role, err)
	}
	if len(machines) != 1 {
		return false, fmt.Errorf("role %s/%s is exclusive but assigned to %d machines %v; each exclusive role must belong to exactly one machine", p.mount, p.role, len(machines), machines)
	}
	return false, nil
}

// newIssueID returns a random ID for issueIDKey.
func newIssueID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// supersedeSecretIDs destroys every SecretID of p's role except the one
// whose metadata carries issueID. Destroyed SecretIDs that were still valid
// are counted and logged: normally a machine only comes back for a new
// SecretID once its old one has expired, so a still-valid one points to a
// reinstalled machine or to someone else using the machine's key.
//
// Errors are logged and counted, not returned: the new SecretID is
// delivered either way.
func (s *Server) supersedeSecretIDs(ctx context.Context, machineID string, p secretIDParams, issueID string) {
	accessors, err := s.vault.ListSecretIDAccessors(ctx, p.mount, p.role)
	if err != nil {
		s.metrics.supersedeErrors.Inc()
		s.log.ErrorContext(ctx, "listing secret-ids to supersede failed", "machine_id", machineID, "mount", p.mount, "role", p.role, "err", err)
		return
	}
	var superseded []string
	for _, accessor := range accessors {
		stillValid, err := s.supersede(ctx, p, accessor, issueID)
		if err != nil {
			s.metrics.supersedeErrors.Inc()
			s.log.ErrorContext(ctx, "superseding secret-id failed", "machine_id", machineID, "mount", p.mount, "role", p.role, "accessor", accessor, "err", err)
			continue
		}
		if stillValid {
			superseded = append(superseded, accessor)
		}
	}
	if len(superseded) > 0 {
		s.metrics.secretIDsSuperseded.Add(float64(len(superseded)))
		s.log.WarnContext(ctx, "superseded still-valid secret-ids", "client_ip", clientIPFrom(ctx), "machine_id", machineID,
			"mount", p.mount, "role", p.role, "count", len(superseded), "accessors", superseded)
	}
}

// supersede destroys the SecretID with accessor unless it is the new one,
// reporting whether it was still valid.
func (s *Server) supersede(ctx context.Context, p secretIDParams, accessor, issueID string) (bool, error) {
	info, err := s.vault.LookupSecretIDAccessor(ctx, p.mount, p.role, accessor)
	if errors.Is(err, vault.ErrSecretIDNotFound) {
		return false, nil // used up or expired meanwhile
	}
	if err != nil {
		return false, err
	}
	if info.Metadata[issueIDKey] == issueID {
		return false, nil
	}
	err = s.vault.DestroySecretIDAccessor(ctx, p.mount, p.role, accessor)
	if errors.Is(err, vault.ErrSecretIDNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.ExpirationTime.IsZero() || info.ExpirationTime.After(s.now()), nil
}

// keyedMutex serializes work per key. Keys are mount/role pairs that passed
// authorization, so their number is bounded by the registry.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[string]*sync.Mutex)
	}
	l, ok := k.locks[key]
	if !ok {
		l = &sync.Mutex{}
		k.locks[key] = l
	}
	k.mu.Unlock()
	l.Lock()
	return l.Unlock
}
