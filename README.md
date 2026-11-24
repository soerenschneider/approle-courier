# approle-courier

Hands out AppRole SecretIDs to machines, so they can bootstrap their access to
[OpenBao](https://openbao.org)/Vault without anyone copying secrets around.

## Table of Contents

1. [Overview](#overview)
1. [Quickstart](#quickstart)
1. [Configuration](#configuration)
   1. [Sources and precedence](#sources-and-precedence)
   1. [Example](#example)
   1. [Reference](#reference)
1. [Vault setup](#vault-setup)
   1. [Authenticating approle-courier](#authenticating-approle-courier)
   1. [Machine roles](#machine-roles)
   1. [Machine registry](#machine-registry)
1. [Running behind HAProxy](#running-behind-haproxy)
1. [Limits](#limits)
1. [Operations](#operations)
1. [Machine side](#machine-side)
1. [Releases](#releases)
1. [Development Workflow](#development-workflow)

## Overview

Each machine is registered with an ID, the public key of its
[age](https://age-encryption.org) identity, and the AppRole roles it may use.
To get a SecretID, a machine:

1. requests a challenge for its machine ID. approle-courier returns a random,
   single-use token encrypted to the machine's registered age key, so only
   that machine can read it.
2. sends the decrypted token as `Authorization: Bearer` to request a SecretID
   for one of its roles. approle-courier asks Vault for a new SecretID,
   *response-wrapped*, and returns the wrapping token, again encrypted to the
   machine's age key.
3. decrypts the wrapping token and unwraps the SecretID at Vault itself.

The SecretID never passes through approle-courier in plain text: it only ever
sees the single-use wrapping token, and only in encrypted form on the wire.

The API is described in [api/openapi.yaml](api/openapi.yaml).

## Quickstart

A complete local setup (OpenBao in dev mode, HAProxy and approle-courier) runs
with docker compose:

```bash
make e2e                               # start, run the machine flow, tear down

docker compose up -d --build --wait    # or keep it running
docker compose run --rm e2e
docker compose down -v
```

[testenv/init.sh](testenv/init.sh) shows the complete Vault configuration
used there, and [testenv/e2e.sh](testenv/e2e.sh) a machine's side of the flow.
OpenBao runs in dev mode (in-memory, root token `root`): never use this setup
for anything but local testing.

## Configuration

### Sources and precedence

Settings come from, in increasing order of precedence:

1. built-in defaults
2. environment variables, for the Vault address and role ID only
3. a JSON config file given with `-config`
4. flags given on the command line

So a deployment can keep its settings in a file and still override one for a
test run: `approle-courier -config prod.json -log-level debug`. Unknown keys in
the file are an error, so typos fail at startup.

`-print-config` prints the effective configuration (all sources merged) and
exits; use it to check what a deployment will actually run with.

Secrets never go in the config file: the Vault token comes from the
environment, and the AppRole secret_id from a file whose path is configured.

### Example

Every field is optional; this shows a typical production setup with the
registry in Vault, behind HAProxy passing TLS through:

```json
{
  "listen": {
    "api": ":8300",
    "metrics": ":9090",
    "tls_cert": "/etc/approle-courier/tls/cert.pem",
    "tls_key": "/etc/approle-courier/tls/key.pem",
    "proxy_protocol": true,
    "trusted_proxies": ["127.0.0.1", "10.0.1.11", "10.0.1.12", "10.0.1.13"],
    "drain_delay": "5s"
  },
  "limits": {
    "max_secret_id_uses": 1,
    "max_secret_id_ttl": "1h",
    "machine_secret_ids": 10,
    "machine_secret_ids_window": "1h"
  },
  "registry": {
    "kv_mount": "secret",
    "kv_path": "approle-courier/registry",
    "cache_ttl": "30s"
  },
  "vault": {
    "address": "https://openbao.example.com:8200",
    "approle": {
      "mount": "approle-service",
      "role_id": "approle-courier",
      "secret_id_file": "/run/secrets/approle-courier-secret-id"
    }
  }
}
```

### Reference

Durations are strings like `"90s"`, `"15m"` or `"1h"`, in the file and on the
command line. Lists are JSON arrays in the file and comma-separated on the
command line.

#### `listen`

| Key | Flag | Default | Description |
|---|---|---|---|
| `api` | `-addr` | `:8080` | Address of the API, which also serves `/healthz` and `/readyz`. |
| `metrics` | `-metrics-addr` | `:9090` | Address of the Prometheus `/metrics` endpoint. Empty disables it. |
| `trusted_proxies` | `-trusted-proxies` | none | Addresses or CIDRs of reverse proxies whose `X-Forwarded-For` header (or PROXY protocol header) gives the client address. See [Running behind HAProxy](#running-behind-haproxy). |
| `tls_cert` | `-tls-cert` | none | PEM certificate (chain) the API listener serves over TLS. Re-read within 10s when the file changes; if the new certificate and key do not match yet, the previous one is served. Requires `tls_key`. Without both, the API is plain HTTP. |
| `tls_key` | `-tls-key` | none | PEM private key for `tls_cert`. |
| `proxy_protocol` | `-proxy-protocol` | `false` | Require a PROXY protocol (v1/v2) header on API connections from `trusted_proxies`; reject it from anyone else. |
| `drain_delay` | `-drain-delay` | `5s` | On SIGTERM, how long `/readyz` reports not ready while requests are still served, so load balancers stop sending traffic before the listeners close. |

#### `limits`

| Key | Flag | Default | Description |
|---|---|---|---|
| `max_wrap_ttl` | `-max-wrap-ttl` | `15m` | Longest `wrap_ttl` a machine may request for the wrapping token. |
| `max_secret_id_uses` | `-max-secret-id-uses` | `1` | Highest `num_uses` of a created SecretID; also used when the machine sets none. `0` leaves it to the role. |
| `max_secret_id_ttl` | `-max-secret-id-ttl` | `1h` | Longest `ttl` of a created SecretID; also used when the machine sets none. `0` leaves it to the role. |
| `machine_secret_ids` | `-machine-secret-ids` | `10` | SecretIDs one machine may create per window, refilling gradually. `0` disables the limit. |
| `machine_secret_ids_window` | `-machine-secret-ids-window` | `1h` | Window for `machine_secret_ids`. |
| `bind_client_address` | `-bind-client-address` | none | `mount/role` patterns (e.g. `approle/*`) whose SecretIDs, and the tokens issued with them, only work from the address that requested them. Only works if Vault sees machines at the same address as approle-courier (no NAT in between). |
| `exclusive_secret_id` | `-exclusive-secret-id` | none | `mount/role` patterns (e.g. `approle/vm-*`) of roles that keep a single SecretID: issuing one destroys the role's other SecretIDs. Each matching role must belong to exactly one machine in the registry. See [Limits](#limits). |
| `challenge_ttl` | `-challenge-ttl` | `1m` | How long a challenge token stays valid. |
| `challenge_rate` | `-challenge-rate` | `1` | Challenge requests per second allowed per client address (IPv6: per /64). |
| `challenge_burst` | `-challenge-burst` | `20` | Challenge requests a client address may make at once before `challenge_rate` applies. |

#### `log`

| Key | Flag | Default | Description |
|---|---|---|---|
| `level` | `-log-level` | `info` | `debug`, `info`, `warn` or `error`. |
| `format` | `-log-format` | `json` | `json` or `text`. |

#### `registry`

| Key | Flag | Default | Description |
|---|---|---|---|
| `file` | `-registry` | `machines.json` | Registry file. Ignored if `kv_path` is set. |
| `kv_mount` | `-registry-kv-mount` | `secret` | KV v2 mount holding the registry secret. |
| `kv_path` | `-registry-kv-path` | none | Path of the KV v2 secret holding the registry. If set, the registry is read from Vault instead of the file. |
| `cache_ttl` | `-registry-cache-ttl` | `5m` | How long the registry is cached before the file or secret is read again. This is also how long a removed machine can still get challenges, so keep it short (e.g. `30s`) if revocation should be quick. |

#### `vault`

| Key | Flag | Default | Description |
|---|---|---|---|
| `address` | `-vault-addr` | `$BAO_ADDR`, then `$VAULT_ADDR`, then `http://127.0.0.1:8200` | Vault/OpenBao address. |
| `timeout` | `-vault-timeout` | `10s` | Timeout of a single Vault request. All Vault calls for one SecretID request are additionally bounded by 20s. |
| `approle.mount` | `-vault-approle-mount` | `approle` | AppRole auth mount approle-courier logs in with. |
| `approle.role_id` | `-vault-approle-role-id` | `$BAO_ROLE_ID` | Role ID approle-courier logs in with. If set, AppRole is used. |
| `approle.secret_id_file` | `-vault-approle-secret-id-file` | none | File containing the secret_id. Required with `role_id`; re-read on every login, so it can be rotated without a restart. |

#### Environment variables

| Variable | Used for |
|---|---|
| `BAO_ADDR`, `VAULT_ADDR` | Default of `vault.address`. |
| `BAO_ROLE_ID` | Default of `vault.approle.role_id`. |
| `BAO_TOKEN`, `VAULT_TOKEN` | Static Vault token, used if no role ID is configured. Setting both a token and a role ID is an error. |

#### Other flags

| Flag | Description |
|---|---|
| `-config` | JSON config file. |
| `-print-config` | Print the effective configuration as JSON and exit. |
| `-version` | Print the version and exit. |

## Vault setup

### Authenticating approle-courier

approle-courier authenticates either with a static token (`BAO_TOKEN`) or, for
production, with its own AppRole. With AppRole it renews its token in the
background, logs in again when the token reaches its max TTL, and revokes the
token on shutdown.

Give it its own AppRole mount, separate from the one machines get SecretIDs
for, so no machine can ever obtain approle-courier's identity:

```bash
bao auth enable -path=approle-service approle

bao policy write approle-courier - <<'EOF'
# Read the machine registry, if it is kept in KV.
path "secret/data/approle-courier/registry" { capabilities = ["read"] }
# Create SecretIDs for the machine roles ("list" only for exclusive_secret_id).
path "auth/approle/role/+/secret-id" { capabilities = ["update", "list"] }
# Only for exclusive_secret_id: find and destroy a role's old SecretIDs.
path "auth/approle/role/+/secret-id-accessor/lookup" { capabilities = ["update"] }
path "auth/approle/role/+/secret-id-accessor/destroy" { capabilities = ["update"] }
EOF

bao write auth/approle-service/role/approle-courier \
    token_policies=approle-courier token_ttl=1h token_max_ttl=24h \
    secret_id_bound_cidrs=<approle-courier's address>/32

bao read -field=role_id auth/approle-service/role/approle-courier/role-id
bao write -f -field=secret_id auth/approle-service/role/approle-courier/secret-id \
    > /run/secrets/approle-courier-secret-id
```

The SecretID must be reusable (no `secret_id_num_uses=1`, no short
`secret_id_ttl`): approle-courier logs in again every time its token reaches
`token_max_ttl`.

### Machine roles

Machine roles live on the `approle` mount (or any other; machines pick it with
the `mount` query parameter). Recommended settings:

```bash
bao write auth/approle/role/my-role \
    token_policies=my-policy token_ttl=10m \
    secret_id_num_uses=1 secret_id_ttl=10m
```

approle-courier caps SecretIDs at `limits.max_secret_id_uses` and
`limits.max_secret_id_ttl` regardless of the role, but setting the role's own
limits as well is cheap insurance. A role's stricter limit always wins.

### Machine registry

The registry says which machines exist, their age public key and which roles
(per AppRole mount) they may request:

```json
{
  "node-42": {
    "age_recipient": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    "roles": {"approle": ["my-role"]}
  },
  "db-01.example.com": {
    "age_recipient": "age1...",
    "roles": {"approle": ["db"], "approle-infra": ["backup"]}
  }
}
```

It is kept either in a file (`registry.file`) or in one Vault KV v2 secret
(`registry.kv_path`), in the same format. Either way it is re-read after
`registry.cache_ttl`, so changes, including removing a machine, take effect
without a restart. If it cannot be read or is invalid, requests fail with 503
rather than using stale data.

- **File**: replace it atomically (write a temporary file, then rename), so a
  half-written file is never read.
- **KV**: write the whole document as the secret's data, replacing the
  previous version:

  ```bash
  bao kv put -mount=secret approle-courier/registry @registry.json
  ```

  Nothing the machine tokens can reach may be allowed to write this secret.

Each machine generates its age identity once (`age-keygen -o key.txt`); only
the public key (`age-keygen -y key.txt`) goes into the registry. Add it
through a reviewed change (e.g. a pull request to your inventory), not
automatically from the machine: the registry decides who can get SecretIDs.

## Running behind HAProxy

Rate limits and the audit log work per client address, so behind a proxy
approle-courier needs the real one. List the proxies in
`listen.trusted_proxies`; headers from anyone else are ignored. Without this,
all machines behind the proxy share one rate limit.

HAProxy terminates TLS and forwards plain HTTP. It can pass the client
address on in two ways:

- **PROXY protocol** (recommended): enable `listen.proxy_protocol` and add
  `send-proxy-v2` to the servers; health checks then need `check-send-proxy`.
- **`X-Forwarded-For`**: `option forwardfor`, with `proxy_protocol` off.
  approle-courier reads the header from the right and stops at the first
  address that is not a trusted proxy, so client-supplied values cannot
  spoof it.

```
frontend approle_courier_https
    mode http
    bind :8443 ssl crt /etc/haproxy/approle-courier.pem
    default_backend approle_courier

backend approle_courier
    mode http
    option httpchk GET /readyz
    http-check expect status 200
    server bb 10.0.2.5:8300 send-proxy-v2 check check-send-proxy inter 2s fall 2 rise 2
```

[testenv/haproxy.cfg](testenv/haproxy.cfg) is a working example; the compose
setup runs exactly this. If traffic between HAProxy and approle-courier must
be encrypted too, approle-courier can terminate TLS itself
(`listen.tls_cert`, `listen.tls_key`), with `ssl` on the HAProxy servers.

### Running on the OpenBao nodes

[contrib/ansible/haproxy-approle-courier.cfg.j2](contrib/ansible/haproxy-approle-courier.cfg.j2)
adds approle-courier to the HAProxy that already fronts OpenBao on each node:
a frontend on its own port (`haproxy_approle_courier_port`) terminating TLS
with `haproxy_cert_file`, and a backend with every node that sets
`approle_courier_enabled`. The client address reaches nodes that set
`approle_courier_proxy_protocol` with the PROXY protocol as above, and the
others in `X-Forwarded-For`. approle-courier then runs on each node with
every OpenBao node's address in `trusted_proxies`;
[contrib/ansible/approle-courier.json.j2](contrib/ansible/approle-courier.json.j2)
renders that configuration. TLS between HAProxy and approle-courier is
optional: set `approle_courier_tls_cert` and `approle_courier_tls_key` on a
node and HAProxy connects to it with `ssl`, verified against
`haproxy_approle_courier_ca_file`.

Challenges are kept in memory per instance, so a machine's challenge and its
SecretID request must reach the same node. The backend uses `balance source`
with `hash-type consistent`, so every HAProxy sends a client to the same node,
as long as all nodes list the same servers in the same order. If a node fails,
only its clients move; a bootstrap in progress at that moment gets a 401 and
has to start over.

## Limits

- **Challenge requests** are limited per client address (`challenge_rate`,
  `challenge_burst`). Each address may also hold at most 5 pending challenges
  per machine, so a third party who knows a machine ID cannot lock that
  machine out.
- **SecretIDs per machine** are limited (`machine_secret_ids` per
  `machine_secret_ids_window`), so a stolen machine key yields a trickle, not a
  flood.
- **SecretID options**: `num_uses` and `ttl` are capped and default to the cap.
  If the role's own limit is stricter, the role's applies.
- **Address binding** (`bind_client_address`): for matching roles,
  `cidr_list` and `token_bound_cidrs` are set to the machine's address.
  Machines cannot set them themselves for those roles.
- **Exclusive roles** (`exclusive_secret_id`): for roles that belong to a
  single machine, issuing a SecretID destroys the role's other SecretIDs, so
  there is only ever one. The new SecretID is created first, so the machine
  is never left without one. Requests for the same role are serialized
  within one instance. This suits machines that keep their own SecretID and
  rotate it (e.g. with sc-agent), with approle-courier as the fallback when
  that SecretID expired, say after a long downtime: then there is nothing
  left to destroy. Destroying a SecretID that was *still valid* is logged
  (`superseded still-valid secret-ids`, with the accessors) and counted in
  `approle_courier_secret_ids_superseded_total`. It means the machine still
  had working credentials but asked for new ones: it was reinstalled (any
  copy of the old SecretID is now useless) or someone else is using its key.
  Investigate either way. Tokens already issued with a destroyed SecretID
  stay valid until they expire.
- **Request bodies** with unknown fields are rejected with 400. On
  authenticated routes this happens only after the token is checked, so
  unauthenticated callers only ever get 401.

Exceeding a limit returns 429 with `Retry-After`.

## Operations

### Endpoints

| Endpoint | Listener | Description |
|---|---|---|
| `/healthz` | API | 200 while the process is serving. Use for restarts. |
| `/readyz` | API | 200 if the registry is readable and the Vault token valid, 503 otherwise or while shutting down. Use for load balancing, not restarts: a Vault outage makes every replica unready. Responses name failed checks; details are logged. |
| `/metrics` | metrics | Prometheus metrics. |

### Metrics

All prefixed with `approle_courier_`, besides the standard Go and process
metrics:

| Metric | Labels | Description |
|---|---|---|
| `http_requests_total` | `route`, `code` | API requests. |
| `http_request_duration_seconds` | `route` | API latency. |
| `http_requests_in_flight` | | Requests being served. |
| `challenges_issued_total` | | Challenge tokens issued. |
| `challenges_rejected_total` | `reason` | Rejected challenge requests. |
| `challenges_pending` | | Unexpired, unredeemed challenges. |
| `auth_failures_total` | `reason` | Missing or invalid bearer tokens. |
| `secret_ids_issued_total` | `mount`, `role` | SecretIDs delivered. |
| `secret_ids_denied_total` | `reason` | Refused SecretID requests from authenticated machines. |
| `secret_ids_superseded_total` | | Still-valid SecretIDs destroyed because a new one was issued for their exclusive role. |
| `secret_id_supersede_errors_total` | | Failures finding or destroying the old SecretIDs of an exclusive role. The new SecretID is delivered anyway. |
| `registry_errors_total` | | Lookups that failed because the registry was unreadable or invalid. |
| `vault_request_duration_seconds` | | Latency of Vault SecretID requests. |
| `vault_errors_total` | `kind` | Failed Vault requests: `not_found`, `rejected`, `sealed`, `unreachable`, `unexpected`. |
| `vault_token_expiry_timestamp_seconds` | | When approle-courier's own token expires (AppRole only). |
| `tls_cert_expiry_timestamp_seconds` | | When the API listener's TLS certificate expires (TLS only). |

Suggested alerts:

```promql
# Token renewal is failing.
approle_courier_vault_token_expiry_timestamp_seconds - time() < 300
# The TLS certificate was not renewed in time.
approle_courier_tls_cert_expiry_timestamp_seconds - time() < 7 * 86400
# The registry cannot be read.
increase(approle_courier_registry_errors_total[5m]) > 0
# A machine keeps hitting its SecretID limit, e.g. with a stolen key.
increase(approle_courier_secret_ids_denied_total{reason="machine_rate_limited"}[1h]) > 0
# A machine with still-valid credentials got new ones: reinstall or stolen key.
increase(approle_courier_secret_ids_superseded_total[1h]) > 0
# Old SecretIDs of exclusive roles could not be destroyed.
increase(approle_courier_secret_id_supersede_errors_total[1h]) > 0
```

### Audit log

Every rejected request is logged as `request rejected`, with a `reason` that
matches the metrics labels, the client address and, where known, machine,
mount and role. Tokens are never logged.

- Rejections of authenticated machines are always logged: `forbidden`,
  `bad_request`, `wrap_ttl_too_long`, `num_uses_too_high`, `ttl_too_long`,
  `cidr_not_allowed`, `machine_rate_limited`, `unknown_machine`,
  `invalid_body`.
- Rejections of unauthenticated requests are logged at most once per reason
  and client address per minute, with a `suppressed` count, so they cannot
  flood the logs: `missing_token`, `invalid_token`, `invalid_body`,
  `client_rate_limited`, `invalid_machine_id`, `unknown_machine`,
  `rate_limited`, `store_full`.

Successful issuance is logged as `issued wrapped secret-id`, with the wrapping
token's accessor.

### Revoking a machine

Remove it from the registry. It stops getting challenges within
`registry.cache_ttl`. SecretIDs it already holds stay valid until they are
used up or expire (`limits.max_secret_id_ttl`); revoke them in Vault for an
immediate cut-off.

### Shutdown

On SIGTERM, approle-courier reports not ready for `listen.drain_delay`, then
stops accepting requests, finishes running ones and revokes its Vault token.
Give it at least `drain_delay` + 15s to stop (e.g. `stop_grace_period` in
compose, `terminationGracePeriodSeconds` in Kubernetes).

## Machine side

What a machine does, with `curl`, `jq` and `age`:

```bash
BB=https://approle-courier.example.com
BAO_ADDR=https://openbao.example.com:8200

# 1. Get a challenge and decrypt it.
token=$(curl -sf -X POST "$BB/v1/auth/challenge" -d '{"machine_id":"node-42"}' |
    jq -r .challenge.value | age -d -i key.txt)

# 2. Request a wrapped SecretID for a role and decrypt the wrapping token.
resp=$(curl -sf -X POST "$BB/v1/approle/roles/my-role/secret-id" \
    -H "Authorization: Bearer $token" -d '{"wrap_ttl":"2m"}')
wrap=$(echo "$resp" | jq -r .encrypted_wrap_token.value | age -d -i key.txt)

# 3. Check where the wrapped response came from, then unwrap it.
curl -sf -X POST "$BAO_ADDR/v1/sys/wrapping/lookup" -d "{\"token\":\"$wrap\"}" |
    jq -r .data.creation_path    # must be auth/approle/role/my-role/secret-id
secret_id=$(curl -sf -X POST -H "X-Vault-Token: $wrap" "$BAO_ADDR/v1/sys/wrapping/unwrap" |
    jq -r .data.secret_id)
```

Check the `creation_path` before unwrapping: it proves the token wraps a
SecretID for the expected role. The SecretID is single-use by default, so the
machine logs in with it right away.

## Releases

Releases are made by
[release-please](https://github.com/googleapis/release-please): it keeps a
release pull request open that collects the changes merged to `main` since the
last release, with the version and `CHANGELOG.md` derived from
[Conventional Commit](https://www.conventionalcommits.org) messages (`fix:` for
patch, `feat:` for minor, `!` or `BREAKING CHANGE:` for major releases).
Merging that pull request tags the release, and
[.github/workflows/release-container.yaml](.github/workflows/release-container.yaml)
then publishes:

- the container image `ghcr.io/soerenschneider/approle-courier:<version>`,
  with SBOM and provenance attestations, signed with cosign
- Linux binaries, a `checksum.sha256` file and its cosign signature
  `checksum.sha256.sigstore.json`, attached to the GitHub release

Both are signed keyless: the signature certifies that the release workflow on
`main` produced them, so no key needs to be managed or trusted. Verify an
image:

```bash
cosign verify ghcr.io/soerenschneider/approle-courier:1.0.0 \
    --certificate-identity https://github.com/soerenschneider/approle-courier/.github/workflows/release-container.yaml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and binaries, then their checksums:

```bash
cosign verify-blob checksum.sha256 \
    --bundle checksum.sha256.sigstore.json \
    --certificate-identity https://github.com/soerenschneider/approle-courier/.github/workflows/release-container.yaml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksum.sha256
```

Images built from `main` between releases (tags `main` and `sha-<commit>`) are
signed by `.github/workflows/ci.yaml` instead; verify them with that workflow
in `--certificate-identity`.

A broken release can be rebuilt by running the release workflow manually with
its tag.

## Development Workflow

| Command | Description |
|---|---|
| `make build` | Build the binary, with version and commit embedded. |
| `make tests` | Run tests with the race detector and write coverage reports. |
| `make lint` | Run golangci-lint. |
| `make vulncheck` | Run govulncheck. |
| `make e2e` | Run the machine flow against the compose setup. |
| `make generate` | Regenerate server and client code from [api/openapi.yaml](api/openapi.yaml). |
| `make validate-openapi-spec` | Lint the OpenAPI spec with Spectral. |
| `make docker-build` | Build the container image. |
| `make cross-build` | Build release binaries for Linux (amd64, arm64, armv6, armv7). |

Server and client code are generated with
[oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) and should not be
edited by hand. CI checks that they match the spec.
