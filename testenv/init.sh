#!/bin/sh
# Configures the dev-mode OpenBao for the test setup. Safe to re-run.
#
#   approle          AppRole mount machines get SecretIDs for, with role "demo"
#                    (fixed role_id "demo") granting read on secret/demo/*
#   approle-service  separate AppRole mount for approle-courier itself, role
#                    "approle-courier" (fixed role_id "approle-courier"); its
#                    secret_id is written to $SERVICE_SECRET_ID_FILE
#   $CERT_DIR        test CA (ca.pem) and HAProxy's certificate with its
#                    key (haproxy.pem), valid for the name clients use
#   secret/approle-courier/registry
#                    machine registry with "node-42", whose age identity is
#                    generated once into $MACHINE_KEY
set -eu

: "${BAO_ADDR:=http://openbao:8200}"
: "${BAO_TOKEN:=root}"
: "${SERVICE_SECRET_ID_FILE:=/run/approle-courier/secret-id}"
: "${MACHINE_KEY:=/machine/key.txt}"
: "${CERT_DIR:=/certs}"

# api METHOD PATH [curl args...]
api() {
	method=$1 path=$2
	shift 2
	curl -sS --fail-with-body -X "$method" -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/$path" "$@"
}

until curl -sf "$BAO_ADDR/v1/sys/health" >/dev/null; do
	echo "waiting for openbao at $BAO_ADDR"
	sleep 1
done

for mount in approle approle-service; do
	if ! api GET sys/auth | jq -e --arg m "$mount/" '.data | has($m)' >/dev/null; then
		api POST "sys/auth/$mount" -d '{"type":"approle"}'
		echo "enabled auth/$mount"
	fi
done

api PUT sys/policies/acl/demo -d "$(jq -n '{policy: "path \"secret/data/demo/*\" { capabilities = [\"read\"] }"}')"
api PUT sys/policies/acl/approle-courier -d "$(jq -n '{policy: "
path \"secret/data/approle-courier/registry\" { capabilities = [\"read\"] }
path \"auth/approle/role/+/secret-id\" { capabilities = [\"update\", \"list\"] }
# Only needed for exclusive_secret_id roles: find and destroy old SecretIDs.
path \"auth/approle/role/+/secret-id-accessor/lookup\" { capabilities = [\"update\"] }
path \"auth/approle/role/+/secret-id-accessor/destroy\" { capabilities = [\"update\"] }
"}')"

# Machine role: single-use SecretIDs, short-lived tokens. secret_id_ttl is
# below approle-courier's default max_secret_id_ttl (1h) on purpose, so e2e
# covers the fallback to the role's stricter limit.
api POST auth/approle/role/demo -d '{"token_policies":["demo"],"token_ttl":"10m","secret_id_num_uses":1,"secret_id_ttl":"10m"}'
api POST auth/approle/role/demo/role-id -d '{"role_id":"demo"}'

# Service role: the SecretID must be reusable, since the service logs in
# again whenever its token reaches token_max_ttl.
api POST auth/approle-service/role/approle-courier -d '{"token_policies":["approle-courier"],"token_ttl":"1h","token_max_ttl":"24h"}'
api POST auth/approle-service/role/approle-courier/role-id -d '{"role_id":"approle-courier"}'
umask 077
api POST auth/approle-service/role/approle-courier/secret-id | jq -r .data.secret_id >"$SERVICE_SECRET_ID_FILE"
chown 65532:65532 "$SERVICE_SECRET_ID_FILE" # distroless "nonroot"
echo "wrote service secret_id to $SERVICE_SECRET_ID_FILE"

if [ ! -s "$MACHINE_KEY" ]; then
	age-keygen -o "$MACHINE_KEY" 2>/dev/null
	echo "generated machine age identity $MACHINE_KEY"
fi
recipient=$(age-keygen -y "$MACHINE_KEY")

api POST secret/data/approle-courier/registry -d "$(jq -n --arg r "$recipient" \
	'{data: {"node-42": {age_recipient: $r, roles: {approle: ["demo"]}}}}')" >/dev/null
api POST secret/data/demo/hello -d '{"data":{"value":"world"}}' >/dev/null
echo "registry: node-42 -> $recipient"

# TLS for HAProxy: a test CA and a certificate, regenerated when missing or
# about to expire. The CA key is not kept.
if ! openssl x509 -checkend 86400 -noout -in "$CERT_DIR/haproxy.pem" >/dev/null 2>&1; then
	(
		cd "$CERT_DIR"
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
			-subj "/CN=approle-courier test CA" -keyout ca-key.pem -out ca.pem 2>/dev/null
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-subj "/CN=haproxy" -keyout key.pem -out req.csr 2>/dev/null
		printf 'subjectAltName=DNS:haproxy,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >req.ext
		openssl x509 -req -in req.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 \
			-extfile req.ext -out cert.pem 2>/dev/null
		cat cert.pem key.pem >haproxy.pem # HAProxy wants certificate and key in one file
		rm -f ca-key.pem ca.srl req.csr req.ext cert.pem key.pem
		chmod 0644 ca.pem
		chown 99:99 haproxy.pem # the haproxy image's user
		chmod 0400 haproxy.pem
	)
	echo "generated test CA and HAProxy certificate in $CERT_DIR"
fi
