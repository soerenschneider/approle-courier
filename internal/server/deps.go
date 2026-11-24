package server

import (
	"context"
	"errors"
	"time"

	"github.com/soerenschneider/approle-courier/internal/vault"
)

// ErrUnknownMachine is returned by AgeKeyStore when no machine is registered
// under the given ID.
var ErrUnknownMachine = errors.New("unknown machine")

// ErrRegistryUnavailable is wrapped by AgeKeyStore and Authorizer errors when
// the registry cannot currently be read or is invalid. Requests fail with 503
// instead of 500, since retrying later may succeed.
var ErrRegistryUnavailable = errors.New("registry unavailable")

// AgeKeyStore retrieves the age public key registered for a machine.
type AgeKeyStore interface {
	// AgeRecipient returns the machine's age X25519 recipient ("age1...") or
	// ErrUnknownMachine.
	AgeRecipient(ctx context.Context, machineID string) (string, error)
}

// Authorizer decides which AppRole roles a machine may request SecretIDs for.
type Authorizer interface {
	Authorized(ctx context.Context, machineID, mount, role string) (bool, error)
	// MachinesWithRole returns the machines that may request SecretIDs for
	// mount/role.
	MachinesWithRole(ctx context.Context, mount, role string) ([]string, error)
}

// SecretIDIssuer creates response-wrapped AppRole SecretIDs and manages the
// existing SecretIDs of a role.
type SecretIDIssuer interface {
	WrappedSecretID(ctx context.Context, mount, role string, wrapTTL time.Duration, req vault.SecretIDRequest) (*vault.WrapInfo, error)
	ListSecretIDAccessors(ctx context.Context, mount, role string) ([]string, error)
	// LookupSecretIDAccessor and DestroySecretIDAccessor return
	// vault.ErrSecretIDNotFound if the SecretID no longer exists.
	LookupSecretIDAccessor(ctx context.Context, mount, role, accessor string) (*vault.SecretIDInfo, error)
	DestroySecretIDAccessor(ctx context.Context, mount, role, accessor string) error
}
