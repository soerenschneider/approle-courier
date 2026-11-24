#!/bin/sh
# Runs the full machine flow against the test setup, as node-42 would:
# challenge -> wrapped SecretID -> unwrap -> AppRole login -> read a secret.
set -eu
# Without pipefail, "curl ... | jq" succeeds even if curl fails.
set -o pipefail

: "${BB_ADDR:=http://approle-courier:8080}"
: "${BB_METRICS_ADDR:=http://approle-courier:9090}"
: "${BAO_ADDR:=http://openbao:8200}"
: "${MACHINE_KEY:=/machine/key.txt}"
: "${CA_CERT:=/certs/ca.pem}"
MACHINE_ID=node-42
ROLE=demo

# --cacert verifies approle-courier's TLS certificate; it has no effect on
# OpenBao's plain-HTTP dev listener.
post() { curl -sS --fail-with-body --cacert "$CA_CERT" -X POST -H 'Content-Type: application/json' "$@"; }
step() { printf '==> %s\n' "$*"; }

until curl -sf --cacert "$CA_CERT" -o /dev/null "$BB_ADDR/readyz"; do
	echo "waiting for approle-courier to be ready"
	sleep 1
done

# fetch_secret_id prints a new secret_id for $ROLE, going through the whole
# flow: challenge, wrapped secret_id, creation_path check, unwrap.
fetch_secret_id() {
	token=$(post "$BB_ADDR/v1/auth/challenge" -d "{\"machine_id\":\"$MACHINE_ID\"}" |
		jq -r .challenge.value | age -d -i "$MACHINE_KEY")
	resp=$(post "$BB_ADDR/v1/approle/roles/$ROLE/secret-id" -H "Authorization: Bearer $token" -d '{"wrap_ttl":"2m"}')
	wrap=$(echo "$resp" | jq -r .encrypted_wrap_token.value | age -d -i "$MACHINE_KEY")
	path=$(post "$BAO_ADDR/v1/sys/wrapping/lookup" -d "$(jq -n --arg t "$wrap" '{token: $t}')" | jq -r .data.creation_path)
	[ "$path" = "auth/approle/role/$ROLE/secret-id" ] || { echo "unexpected creation_path: $path" >&2; return 1; }
	post "$BAO_ADDR/v1/sys/wrapping/unwrap" -H "X-Vault-Token: $wrap" | jq -r .data.secret_id
}

# login prints a client token for secret_id $1.
login() {
	post "$BAO_ADDR/v1/auth/approle/login" -d "$(jq -n --arg s "$1" --arg r "$ROLE" '{role_id: $r, secret_id: $s}')" |
		jq -r .auth.client_token
}

step "fetch secret_id for role $ROLE (challenge, wrapped secret_id, creation_path check, unwrap)"
secret_id=$(fetch_secret_id)

step "log in with role $ROLE"
client_token=$(login "$secret_id")

step "read secret/demo/hello"
value=$(curl -sS --fail-with-body -H "X-Vault-Token: $client_token" "$BAO_ADDR/v1/secret/data/demo/hello" | jq -r .data.data.value)
[ "$value" = world ] || { echo "unexpected value: $value" >&2; exit 1; }

step "single-use secret_id is spent"
if login "$secret_id" >/dev/null 2>&1; then
	echo "secret_id was accepted twice" >&2
	exit 1
fi

step "exclusive role: a new secret_id supersedes the unused previous one"
old=$(fetch_secret_id)
new=$(fetch_secret_id)
if login "$old" >/dev/null 2>&1; then
	echo "superseded secret_id still works" >&2
	exit 1
fi
login "$new" >/dev/null

step "metrics"
curl -sS "$BB_METRICS_ADDR/metrics" | grep -E '^approle_courier_(secret_ids_issued_total|secret_ids_superseded_total|challenges_issued_total|vault_token_expiry)'

echo "OK"
