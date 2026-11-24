package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	// maxPendingChallenges bounds outstanding challenges per machine and
	// client network. Counting per client network means a third party who
	// knows a machine ID cannot use up the machine's own allowance.
	maxPendingChallenges = 5
	// defaultMaxTotalChallenges bounds the store as a whole, so memory stays
	// bounded however many client networks send requests.
	defaultMaxTotalChallenges = 100_000
)

var (
	errTooManyChallenges  = errors.New("too many pending challenges")
	errChallengeStoreFull = errors.New("challenge store is full")
)

// pendingKey identifies whose challenges count towards maxPendingChallenges.
type pendingKey struct {
	machineID string
	client    netip.Prefix
}

type challenge struct {
	pendingKey
	expiresAt time.Time
}

// challengeStore keeps single-use challenge tokens in memory, indexed by the
// SHA-256 of the token so plaintext tokens are never stored. It is local to
// one process: with several replicas, a challenge must be redeemed on the
// replica that issued it.
type challengeStore struct {
	ttl      time.Duration
	maxTotal int

	mu      sync.Mutex
	byHash  map[[sha256.Size]byte]challenge
	pending map[pendingKey]int
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{
		ttl:      ttl,
		maxTotal: defaultMaxTotalChallenges,
		byHash:   make(map[[sha256.Size]byte]challenge),
		pending:  make(map[pendingKey]int),
	}
}

// issue creates a new token for machineID, requested from client.
func (c *challengeStore) issue(machineID string, client netip.Prefix, now time.Time) (token string, expiresAt time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sweep(now)
	key := pendingKey{machineID: machineID, client: client}
	if c.pending[key] >= maxPendingChallenges {
		return "", time.Time{}, errTooManyChallenges
	}
	if len(c.byHash) >= c.maxTotal {
		return "", time.Time{}, errChallengeStoreFull
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	expiresAt = now.Add(c.ttl)
	c.byHash[sha256.Sum256([]byte(token))] = challenge{pendingKey: key, expiresAt: expiresAt}
	c.pending[key]++
	return token, expiresAt, nil
}

// redeem consumes token and returns the machine it was issued to. A token
// can be redeemed at most once, and only before it expires.
func (c *challengeStore) redeem(token string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	h := sha256.Sum256([]byte(token))
	ch, ok := c.byHash[h]
	if !ok {
		return "", false
	}
	c.remove(h, ch)
	if !now.Before(ch.expiresAt) {
		return "", false
	}
	return ch.machineID, true
}

// count returns the number of unexpired tokens.
func (c *challengeStore) count(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, ch := range c.byHash {
		if now.Before(ch.expiresAt) {
			n++
		}
	}
	return n
}

// sweep removes expired tokens. c.mu must be held; sync.Mutex is not
// reentrant, so sweep must not lock it itself.
func (c *challengeStore) sweep(now time.Time) {
	for h, ch := range c.byHash {
		if !now.Before(ch.expiresAt) {
			c.remove(h, ch)
		}
	}
}

// remove deletes a token and releases its pending slot. c.mu must be held.
func (c *challengeStore) remove(h [sha256.Size]byte, ch challenge) {
	delete(c.byHash, h)
	if c.pending[ch.pendingKey]--; c.pending[ch.pendingKey] <= 0 {
		delete(c.pending, ch.pendingKey)
	}
}
