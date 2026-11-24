package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/soerenschneider/approle-courier/internal/api"
	"github.com/soerenschneider/approle-courier/internal/vault"
)

// namePattern matches machine IDs, mounts and role names. A leading dot is
// rejected so "." and ".." cannot reach the Vault request path.
var (
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)
	durationPattern = regexp.MustCompile(`^[0-9]+(s|m|h)$`)
)

const maxNameLen = 128

// retryAfterSeconds is the Retry-After sent with 503 responses.
const retryAfterSeconds = 5

// defaultMount is the AppRole auth mount used when the request names none.
const defaultMount = "approle"

var noStore = "no-store"

func validName(s string) bool {
	return len(s) <= maxNameLen && namePattern.MatchString(s)
}

// CreateChallenge implements POST /v1/auth/challenge.
func (s *Server) CreateChallenge(ctx context.Context, req api.CreateChallengeRequestObject) (api.CreateChallengeResponseObject, error) {
	machineID := req.Body.MachineId
	client := clientNetwork(clientIPFrom(ctx))
	if ok, wait := s.limiter.allow(client, s.now()); !ok {
		s.rejectChallenge(ctx, "client_rate_limited", machineID)
		return challengeTooManyRequests("too many challenge requests from this address", retryAfterFor(wait)), nil
	}
	if !validName(machineID) {
		s.rejectChallenge(ctx, "invalid_machine_id", machineID)
		return api.CreateChallenge400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(errorBody("invalid machine_id"))}, nil
	}
	recipient, r, resp, err := s.challengeRecipient(ctx, machineID)
	if resp != nil || err != nil {
		return resp, err
	}
	token, expiresAt, resp, err := s.issueChallenge(ctx, machineID, client)
	if resp != nil || err != nil {
		return resp, err
	}

	ciphertext, err := ageEncrypt(r, token)
	if err != nil {
		return nil, fmt.Errorf("encrypt challenge: %w", err)
	}
	s.metrics.challengesIssued.Inc()
	return api.CreateChallenge201JSONResponse{
		Body: api.ChallengeResponse{
			MachineId: machineID,
			Recipient: recipient,
			Challenge: api.AgeCiphertext{Format: api.AgeCiphertextFormatAgeArmor, Value: ciphertext},
			ExpiresAt: expiresAt.UTC(),
		},
		Headers: api.CreateChallenge201ResponseHeaders{CacheControl: &noStore},
	}, nil
}

// challengeRecipient looks up machineID's age recipient. A non-nil response
// ends the request.
func (s *Server) challengeRecipient(ctx context.Context, machineID string) (string, *age.X25519Recipient, api.CreateChallengeResponseObject, error) {
	recipient, err := s.keys.AgeRecipient(ctx, machineID)
	switch {
	case errors.Is(err, ErrUnknownMachine):
		s.rejectChallenge(ctx, "unknown_machine", machineID)
		return "", nil, api.CreateChallenge404JSONResponse{MachineNotFoundJSONResponse: api.MachineNotFoundJSONResponse(errorBody("unknown machine"))}, nil
	case s.registryUnavailable(ctx, err):
		return "", nil, api.CreateChallenge503JSONResponse{ServiceUnavailableJSONResponse: unavailable("machine registry is unavailable")}, nil
	case err != nil:
		return "", nil, nil, fmt.Errorf("look up age recipient for %q: %w", machineID, err)
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", nil, nil, fmt.Errorf("machine %q: %w", machineID, err)
	}
	return recipient, r, nil, nil
}

// issueChallenge creates a challenge token. A non-nil response ends the
// request.
func (s *Server) issueChallenge(ctx context.Context, machineID string, client netip.Prefix) (string, time.Time, api.CreateChallengeResponseObject, error) {
	token, expiresAt, err := s.challenges.issue(machineID, client, s.now())
	switch {
	case errors.Is(err, errTooManyChallenges):
		s.rejectChallenge(ctx, "rate_limited", machineID)
		return "", time.Time{}, challengeTooManyRequests(err.Error(), retryAfterFor(s.challenges.ttl)), nil
	case errors.Is(err, errChallengeStoreFull):
		s.rejectChallenge(ctx, "store_full", machineID)
		return "", time.Time{}, api.CreateChallenge503JSONResponse{ServiceUnavailableJSONResponse: unavailable(err.Error())}, nil
	case err != nil:
		return "", time.Time{}, nil, fmt.Errorf("issue challenge: %w", err)
	}
	return token, expiresAt, nil, nil
}

func challengeTooManyRequests(msg string, retryAfter int) api.CreateChallenge429JSONResponse {
	return api.CreateChallenge429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse{
		Body:    errorBody(msg),
		Headers: api.TooManyRequestsResponseHeaders{RetryAfter: &retryAfter},
	}}
}

// secretIDParams is a validated SecretID request.
type secretIDParams struct {
	mount, role string
	wrapTTL     time.Duration
	req         vault.SecretIDRequest
	defaulted   defaultedOptions
}

// CreateWrappedSecretId implements
// POST /v1/approle/roles/{role_name}/secret-id.
func (s *Server) CreateWrappedSecretId(ctx context.Context, req api.CreateWrappedSecretIdRequestObject) (api.CreateWrappedSecretIdResponseObject, error) {
	machineID, ok := MachineID(ctx)
	if !ok {
		return nil, errors.New("no authenticated machine in context")
	}
	p, resp, err := s.checkSecretIDRequest(ctx, machineID, req)
	if resp != nil || err != nil {
		return resp, err
	}
	// Resolve the recipient before calling Vault so no SecretID is created
	// that could not be delivered.
	recipient, r, resp, err := s.secretIDRecipient(ctx, machineID, p)
	if resp != nil || err != nil {
		return resp, err
	}
	wi, resp, err := s.issueSecretID(ctx, machineID, p)
	if resp != nil || err != nil {
		return resp, err
	}

	ciphertext, err := ageEncrypt(r, wi.Token)
	if err != nil {
		return nil, fmt.Errorf("encrypt wrapping token (accessor %s): %w", wi.Accessor, err)
	}
	s.metrics.secretIDsIssued.WithLabelValues(p.mount, p.role).Inc()
	s.log.InfoContext(ctx, "issued wrapped secret-id", "client_ip", clientIPFrom(ctx), "machine_id", machineID, "mount", p.mount, "role", p.role,
		"wrap_accessor", wi.Accessor, "bound_cidrs", p.req.CIDRList)

	return api.CreateWrappedSecretId201JSONResponse{
		Body: api.WrappedSecretIdResponse{
			MachineId: machineID,
			Mount:     p.mount,
			RoleName:  p.role,
			EncryptedWrapToken: api.EncryptedWrapToken{
				Format:    api.EncryptedWrapTokenFormatAgeArmor,
				Recipient: recipient,
				Value:     ciphertext,
			},
			WrapInfo: api.WrapInfo{
				Accessor:     wi.Accessor,
				Ttl:          wi.TTL,
				CreationTime: wi.CreationTime,
				CreationPath: wi.CreationPath,
			},
		},
		Headers: api.CreateWrappedSecretId201ResponseHeaders{CacheControl: &noStore},
	}, nil
}

// checkSecretIDRequest runs the checks that need no Vault call, in order:
// mount and role names, authorization, options and limits, and the
// per-machine rate limit. A non-nil response ends the request.
func (s *Server) checkSecretIDRequest(ctx context.Context, machineID string, req api.CreateWrappedSecretIdRequestObject) (secretIDParams, api.CreateWrappedSecretIdResponseObject, error) {
	p, ok := secretIDTarget(req)
	if !ok {
		return p, s.secretIDBadRequest(ctx, machineID, p, "invalid mount or role_name"), nil
	}
	if resp, err := s.authorizeRole(ctx, machineID, p); resp != nil || err != nil {
		return p, resp, err
	}
	if matchesRole(s.exclusiveSecretID, p.mount, p.role) {
		registryDown, err := s.checkExclusive(ctx, p)
		if registryDown {
			return p, api.CreateWrappedSecretId503JSONResponse{ServiceUnavailableJSONResponse: unavailable("machine registry is unavailable")}, nil
		}
		if err != nil {
			return p, nil, err
		}
	}
	if resp := s.parseSecretIDOptions(ctx, machineID, req.Body, &p); resp != nil {
		return p, resp, nil
	}
	return p, s.machineRateLimit(ctx, machineID, p), nil
}

// secretIDTarget returns params with the requested mount (default
// "approle") and role, and whether both are valid names.
func secretIDTarget(req api.CreateWrappedSecretIdRequestObject) (secretIDParams, bool) {
	p := secretIDParams{mount: defaultMount, role: req.RoleName}
	if req.Params.Mount != nil {
		p.mount = *req.Params.Mount
	}
	return p, validName(p.mount) && validName(p.role)
}

// authorizeRole checks that machineID may request SecretIDs for p's role.
// A non-nil response ends the request.
func (s *Server) authorizeRole(ctx context.Context, machineID string, p secretIDParams) (api.CreateWrappedSecretIdResponseObject, error) {
	allowed, err := s.authz.Authorized(ctx, machineID, p.mount, p.role)
	switch {
	case s.registryUnavailable(ctx, err):
		return api.CreateWrappedSecretId503JSONResponse{ServiceUnavailableJSONResponse: unavailable("machine registry is unavailable")}, nil
	case err != nil:
		return nil, fmt.Errorf("authorize %q for %s/%s: %w", machineID, p.mount, p.role, err)
	case !allowed:
		s.rejectSecretID(ctx, "forbidden", machineID, p, "")
		return api.CreateWrappedSecretId403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody("machine is not authorized for this role"))}, nil
	}
	return nil, nil
}

// parseSecretIDOptions validates the request body into p, applies the
// server's limits and, for bound roles, binds the SecretID to the caller's
// address. A non-nil response ends the request.
func (s *Server) parseSecretIDOptions(ctx context.Context, machineID string, b *api.CreateWrappedSecretIdRequest, p *secretIDParams) api.CreateWrappedSecretIdResponseObject {
	var body api.CreateWrappedSecretIdRequest
	if b != nil {
		body = *b
	}
	p.wrapTTL = defaultWrapTTL
	if body.WrapTtl != nil {
		var err error
		if p.wrapTTL, err = parseDuration(*body.WrapTtl); err != nil {
			return s.secretIDBadRequest(ctx, machineID, *p, "wrap_ttl: "+err.Error())
		}
	}
	if p.wrapTTL > s.maxWrapTTL {
		return s.secretIDUnprocessable(ctx, "wrap_ttl_too_long", machineID, *p, fmt.Sprintf("wrap_ttl exceeds maximum of %s", s.maxWrapTTL))
	}
	var err error
	if p.req, err = secretIDRequest(machineID, body.SecretId); err != nil {
		return s.secretIDBadRequest(ctx, machineID, *p, err.Error())
	}
	var violation *limitViolation
	if p.defaulted, violation = s.applySecretIDLimits(&p.req); violation != nil {
		return s.secretIDUnprocessable(ctx, violation.reason, machineID, *p, violation.msg)
	}
	if matchesRole(s.bindClientAddress, p.mount, p.role) && !bindToClient(&p.req, clientIPFrom(ctx)) {
		return s.secretIDUnprocessable(ctx, "cidr_not_allowed", machineID, *p, "cidr_list and token_bound_cidrs are set by the server for this role")
	}
	return nil
}

// machineRateLimit applies the per-machine SecretID limit. A non-nil
// response ends the request.
func (s *Server) machineRateLimit(ctx context.Context, machineID string, p secretIDParams) api.CreateWrappedSecretIdResponseObject {
	if s.machineLimiter == nil {
		return nil
	}
	ok, wait := s.machineLimiter.allow(machineID, s.now())
	if ok {
		return nil
	}
	s.rejectSecretID(ctx, "machine_rate_limited", machineID, p, "")
	retryAfter := retryAfterFor(wait)
	return api.CreateWrappedSecretId429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse{
		Body:    errorBody("too many SecretIDs for this machine"),
		Headers: api.TooManyRequestsResponseHeaders{RetryAfter: &retryAfter},
	}}
}

// secretIDRecipient looks up machineID's age recipient. A non-nil response
// ends the request.
func (s *Server) secretIDRecipient(ctx context.Context, machineID string, p secretIDParams) (string, *age.X25519Recipient, api.CreateWrappedSecretIdResponseObject, error) {
	recipient, err := s.keys.AgeRecipient(ctx, machineID)
	switch {
	case errors.Is(err, ErrUnknownMachine):
		// Deregistered after the challenge was issued.
		s.rejectSecretID(ctx, "unknown_machine", machineID, p, "")
		return "", nil, api.CreateWrappedSecretId403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody("unknown machine"))}, nil
	case s.registryUnavailable(ctx, err):
		return "", nil, api.CreateWrappedSecretId503JSONResponse{ServiceUnavailableJSONResponse: unavailable("machine registry is unavailable")}, nil
	case err != nil:
		return "", nil, nil, fmt.Errorf("look up age recipient for %q: %w", machineID, err)
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", nil, nil, fmt.Errorf("machine %q: %w", machineID, err)
	}
	return recipient, r, nil, nil
}

// issueSecretID creates the wrapped SecretID in Vault and, for exclusive
// roles, destroys the role's other SecretIDs. A non-nil response ends the
// request.
func (s *Server) issueSecretID(ctx context.Context, machineID string, p secretIDParams) (*vault.WrapInfo, api.CreateWrappedSecretIdResponseObject, error) {
	// One deadline for all Vault calls of the request, superseding included.
	vaultCtx, cancel := context.WithTimeout(ctx, s.issueTimeout)
	defer cancel()

	exclusive := matchesRole(s.exclusiveSecretID, p.mount, p.role)
	var issueID string
	if exclusive {
		// Concurrent requests for the role would supersede each other's
		// new SecretID.
		defer s.exclusiveLocks.lock(p.mount + "/" + p.role)()
		var err error
		if issueID, err = newIssueID(); err != nil {
			return nil, nil, fmt.Errorf("generate issue id: %w", err)
		}
		p.req.Metadata[issueIDKey] = issueID
	}

	wi, err := s.wrappedSecretID(vaultCtx, p.mount, p.role, p.wrapTTL, p.req, p.defaulted)
	if err != nil {
		kind := classifyVaultError(err)
		s.metrics.vaultErrors.WithLabelValues(kind).Inc()
		s.log.WarnContext(ctx, "vault secret-id request failed", "machine_id", machineID, "mount", p.mount, "role", p.role, "err", err)
		return nil, vaultErrorResponse(kind, err), nil
	}
	if exclusive {
		s.supersedeSecretIDs(vaultCtx, machineID, p, issueID)
	}
	return wi, nil, nil
}

// registryUnavailable reports whether err is a registry outage, logging and
// counting it if so.
func (s *Server) registryUnavailable(ctx context.Context, err error) bool {
	if !errors.Is(err, ErrRegistryUnavailable) {
		return false
	}
	s.metrics.registryErrors.Inc()
	s.log.WarnContext(ctx, "machine registry unavailable", "err", err)
	return true
}

func unavailable(msg string) api.ServiceUnavailableJSONResponse {
	retryAfter := retryAfterSeconds
	return api.ServiceUnavailableJSONResponse{
		Body:    errorBody(msg),
		Headers: api.ServiceUnavailableResponseHeaders{RetryAfter: &retryAfter},
	}
}

func (s *Server) secretIDBadRequest(ctx context.Context, machineID string, p secretIDParams, msg string) api.CreateWrappedSecretId400JSONResponse {
	s.rejectSecretID(ctx, "bad_request", machineID, p, msg)
	return api.CreateWrappedSecretId400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(errorBody(msg))}
}

func (s *Server) secretIDUnprocessable(ctx context.Context, reason, machineID string, p secretIDParams, msg string) api.CreateWrappedSecretId422JSONResponse {
	s.rejectSecretID(ctx, reason, machineID, p, msg)
	return api.CreateWrappedSecretId422JSONResponse{UnprocessableEntityJSONResponse: api.UnprocessableEntityJSONResponse(errorBody(msg))}
}

// classifyVaultError returns the vault error kind for err.
func classifyVaultError(err error) string {
	var verr *vault.Error
	var uerr *url.Error
	switch {
	case errors.As(err, &verr):
		switch {
		case verr.StatusCode == 404,
			verr.StatusCode == 400 && strings.Contains(strings.Join(verr.Errors, " "), "does not exist"):
			return vaultErrNotFound
		case verr.StatusCode == 400:
			return vaultErrRejected
		case verr.StatusCode == 503:
			return vaultErrSealed
		}
	case errors.As(err, &uerr):
		return vaultErrUnreachable
	}
	return vaultErrUnexpected
}

// vaultErrorResponse maps a Vault failure of the given kind to the API's
// error responses.
func vaultErrorResponse(kind string, err error) api.CreateWrappedSecretIdResponseObject {
	switch kind {
	case vaultErrNotFound:
		return api.CreateWrappedSecretId404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody("mount or role not found"))}
	case vaultErrRejected:
		var verr *vault.Error
		errors.As(err, &verr)
		return api.CreateWrappedSecretId422JSONResponse{UnprocessableEntityJSONResponse: api.UnprocessableEntityJSONResponse(api.Error{Errors: verr.Errors})}
	case vaultErrSealed:
		return api.CreateWrappedSecretId503JSONResponse{ServiceUnavailableJSONResponse: unavailable("vault is sealed or in standby")}
	case vaultErrUnreachable:
		return api.CreateWrappedSecretId503JSONResponse{ServiceUnavailableJSONResponse: unavailable("vault is unreachable")}
	}
	return api.CreateWrappedSecretId502JSONResponse{BadGatewayJSONResponse: api.BadGatewayJSONResponse(errorBody("unexpected vault error"))}
}

func secretIDRequest(machineID string, opts *api.SecretIdOptions) (vault.SecretIDRequest, error) {
	// Metadata is server-controlled only, so policies and audit can trust it.
	req := vault.SecretIDRequest{Metadata: map[string]string{"machine_id": machineID}}
	if opts != nil {
		if opts.CidrList != nil {
			req.CIDRList = *opts.CidrList
		}
		if opts.TokenBoundCidrs != nil {
			req.TokenBoundCIDRs = *opts.TokenBoundCidrs
		}
		if opts.Ttl != nil {
			ttl, err := parseDuration(*opts.Ttl)
			if err != nil {
				return req, fmt.Errorf("secret_id.ttl: %w", err)
			}
			req.TTL = ttl
		}
		if opts.NumUses != nil {
			if *opts.NumUses < 0 {
				return req, errors.New("secret_id.num_uses must not be negative")
			}
			req.NumUses = opts.NumUses
		}
	}
	return req, nil
}

// parseDuration accepts whole seconds as an integer or a string like "90s",
// "5m" or "24h".
func parseDuration(d api.Duration) (time.Duration, error) {
	if n, err := d.AsDuration0(); err == nil {
		// int64: on 32-bit platforms int cannot hold the bound.
		if n < 1 || int64(n) > math.MaxInt64/int64(time.Second) {
			return 0, errors.New("must be a positive number of seconds")
		}
		return time.Duration(n) * time.Second, nil
	}
	s, err := d.AsDuration1()
	if err != nil || !durationPattern.MatchString(s) {
		return 0, errors.New(`must be seconds or a duration like "90s", "5m", "24h"`)
	}
	dur, err := time.ParseDuration(s)
	if err != nil || dur <= 0 {
		return 0, errors.New("must be a positive duration")
	}
	return dur, nil
}
