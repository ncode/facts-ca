#!/usr/bin/env bash
# End-to-end proof: build both binaries, run the CA server, and have the CLI
# bootstrap a cert over the Puppet CA v1 wire protocol, then use it for mTLS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
PORT="${PORT:-18140}"
HOST=localhost
trap 'kill "${SRV_PID:-0}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== build =="
go build -o "$TMP/facts-ca-server" "$ROOT/cmd/facts-ca-server"
go build -o "$TMP/facts-ca-cli"    "$ROOT/cmd/facts-ca-cli"

echo "== start server (autosign) =="
"$TMP/facts-ca-server" -init -cadir "$TMP/cadir" -listen "127.0.0.1:$PORT" \
  -hostname "$HOST" -autosign &
SRV_PID=$!

# Wait for the listener; fail fast if the server dies or never binds.
READY=false
for _ in $(seq 1 100); do
  if curl -sk "https://$HOST:$PORT/puppet-ca/v1/certificate/ca" >/dev/null 2>&1; then READY=true; break; fi
  if ! kill -0 "$SRV_PID" 2>/dev/null; then echo "FAIL: server exited before becoming ready"; exit 1; fi
  sleep 0.1
done
[ "$READY" = true ] || { echo "FAIL: server did not become ready on $HOST:$PORT"; exit 1; }

echo "== raw Puppet API (any Puppet agent / curl can hit this) =="
CA_PEM=$(curl -sk "https://$HOST:$PORT/puppet-ca/v1/certificate/ca")
echo "${CA_PEM%%$'\n'*}"
echo "  ^ CA cert served at /puppet-ca/v1/certificate/ca"

echo "== bootstrap node1.test (with Puppet trusted-fact extensions) =="
UUID=ED803750-E3C7-44F5-BB08-41A04433FE2E
BOOT=$("$TMP/facts-ca-cli" bootstrap --server "$HOST:$PORT" --certname node1.test \
  --ssldir "$TMP/ssl" --onetime --ext pp_role=web --ext "pp_uuid=$UUID")
echo "$BOOT"

echo "== assert the CA copied the extensions (OID + value) into the cert =="
DUMP=$(openssl x509 -in "$TMP/ssl/certs/node1.test.pem" -noout -text)
echo "$DUMP" | grep -q "1.3.6.1.4.1.34380.1.1.13" && echo "  ok: pp_role OID present"  || { echo "FAIL: pp_role OID"; exit 1; }
echo "$DUMP" | grep -q "$UUID"                     && echo "  ok: pp_uuid value in cert" || { echo "FAIL: pp_uuid value"; exit 1; }
echo "$BOOT" | grep -q "ext pp_role = web"         && echo "  ok: pp_role value=web"    || { echo "FAIL: pp_role value"; exit 1; }

echo "== ssldir layout =="
( cd "$TMP/ssl" && find . -type f | sort )
test -f "$TMP/ssl/certs/node1.test.pem"        || { echo "FAIL: no leaf cert"; exit 1; }
test -f "$TMP/ssl/certs/ca.pem"                || { echo "FAIL: no CA cert"; exit 1; }
test -f "$TMP/ssl/private_keys/node1.test.pem" || { echo "FAIL: no private key"; exit 1; }

echo "== mTLS admin: ca list (client cert verified by server) =="
"$TMP/facts-ca-cli" ca list --server "$HOST:$PORT" --ssldir "$TMP/ssl" | grep -q "node1.test" \
  && echo "  ok: node1.test listed via mTLS admin API" || { echo "FAIL: admin list"; exit 1; }

echo "== mTLS data path =="
MTLS_OUT=$("$TMP/facts-ca-cli" mtls --server "$HOST:$PORT" --ssldir "$TMP/ssl" \
  --url "https://$HOST:$PORT/puppet-ca/v1/certificate/ca")
echo "${MTLS_OUT%%$'\n'*}"

echo "== verify chain with openssl =="
openssl verify -CAfile "$TMP/ssl/certs/ca.pem" "$TMP/ssl/certs/node1.test.pem"

echo "ALL E2E CHECKS PASSED"
