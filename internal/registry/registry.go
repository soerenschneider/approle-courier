// Package registry provides the machine registry: the registered machines,
// their age recipients and the AppRole roles they may request. Registry
// implements server.AgeKeyStore and server.Authorizer.
//
// The registry document is loaded from a Source, a file (FileSource) or a
// Vault KV v2 secret (KVSource). Both hold the same JSON document, keyed by
// machine ID:
//
//	{
//	  "node-42": {
//	    "age_recipient": "age1...",
//	    "roles": {"approle": ["my-role"]}
//	  }
//	}
//
// where "roles" maps an AppRole mount to the role names the machine may
// request SecretIDs for.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"filippo.io/age"

	"github.com/soerenschneider/approle-courier/internal/server"
)

// Source loads the raw registry document.
type Source interface {
	Load(ctx context.Context) ([]byte, error)
	// String describes the source for logs and errors.
	String() string
}

type Machine struct {
	AgeRecipient string              `json:"age_recipient"`
	Roles        map[string][]string `json:"roles"`
}

// Registry serves lookups from a Source's document, cached for a TTL, so a
// machine removed from the source stops being accepted within one TTL.
//
// Errors fail closed: if the source cannot be read or its document is
// invalid, lookups return an error wrapping server.ErrRegistryUnavailable
// instead of serving a stale document.
type Registry struct {
	source Source
	ttl    time.Duration
	now    func() time.Time

	// cur is the cached document. Lookups read it without locking; a
	// snapshot is never modified once stored.
	cur atomic.Pointer[snapshot]
	// sem is held while loading the source, so concurrent cache misses
	// trigger at most one load.
	sem chan struct{}
}

// snapshot is a loaded document and when it expires.
type snapshot struct {
	machines map[string]Machine
	expires  time.Time
}

var (
	_ server.AgeKeyStore = (*Registry)(nil)
	_ server.Authorizer  = (*Registry)(nil)
)

// New returns a registry loading source at most once per ttl; with ttl <= 0
// every lookup loads it. New does not load the source; call Check for that.
func New(source Source, ttl time.Duration) *Registry {
	return &Registry{
		source: source,
		ttl:    ttl,
		now:    time.Now,
		sem:    make(chan struct{}, 1),
	}
}

// Check loads the registry, returning any error reading or validating it.
func (r *Registry) Check(ctx context.Context) error {
	_, err := r.load(ctx)
	return err
}

func (r *Registry) AgeRecipient(ctx context.Context, machineID string) (string, error) {
	machines, err := r.load(ctx)
	if err != nil {
		return "", err
	}
	m, ok := machines[machineID]
	if !ok {
		return "", server.ErrUnknownMachine
	}
	return m.AgeRecipient, nil
}

func (r *Registry) Authorized(ctx context.Context, machineID, mount, role string) (bool, error) {
	machines, err := r.load(ctx)
	if err != nil {
		return false, err
	}
	m, ok := machines[machineID]
	return ok && slices.Contains(m.Roles[mount], role), nil
}

// MachinesWithRole returns the IDs of the machines that may request
// SecretIDs for mount/role, sorted.
func (r *Registry) MachinesWithRole(ctx context.Context, mount, role string) ([]string, error) {
	machines, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for id, m := range machines {
		if slices.Contains(m.Roles[mount], role) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// load returns the cached document, loading it from the source if the cache
// has expired. Cache hits do not wait for anything.
func (r *Registry) load(ctx context.Context) (map[string]Machine, error) {
	if m, ok := r.cached(); ok {
		return m, nil
	}
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.sem }()

	// Another caller may have loaded the source while we waited.
	if m, ok := r.cached(); ok {
		return m, nil
	}
	b, err := r.source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", server.ErrRegistryUnavailable, r.source, err)
	}
	machines, err := parse(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", server.ErrRegistryUnavailable, r.source, err)
	}
	// On failure above the expired snapshot stays in place but is never
	// served, so errors fail closed.
	r.cur.Store(&snapshot{machines: machines, expires: r.now().Add(r.ttl)})
	return machines, nil
}

// cached returns the cached document if it has not expired.
func (r *Registry) cached() (map[string]Machine, bool) {
	s := r.cur.Load()
	if s == nil || !r.now().Before(s.expires) {
		return nil, false
	}
	return s.machines, true
}

// parse decodes and validates a registry document. Any invalid entry rejects
// the whole document.
func parse(b []byte) (map[string]Machine, error) {
	var machines map[string]Machine
	if err := json.Unmarshal(b, &machines); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	for id, m := range machines {
		if _, err := age.ParseX25519Recipient(m.AgeRecipient); err != nil {
			if id == "machines" && m.AgeRecipient == "" {
				return nil, errors.New(`old layout: move the entries under "machines" to the top level`)
			}
			return nil, fmt.Errorf("machine %q: %w", id, err)
		}
	}
	if machines == nil {
		// The document "null" is valid JSON; treat it as empty.
		machines = map[string]Machine{}
	}
	return machines, nil
}
