#!/bin/sh
# End-to-end proof: build both binaries, run the CA server, and have the CLI
# bootstrap a cert over the Puppet CA v1 wire protocol, then use it for mTLS.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/facts-ca-e2e.XXXXXX")"
PORT="${PORT:-18140}"
HOST="${HOST:-localhost}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
ALLOW_REMOTE_LISTEN="${ALLOW_REMOTE_LISTEN:-}"
FACTS_CA_SERVER="${FACTS_CA_SERVER:-}"
FACTS_CA_CLI="${FACTS_CA_CLI:-}"
READY_TRIES="${READY_TRIES:-30}"
READY_SLEEP="${READY_SLEEP:-1}"
SRV_PID=

case "$PORT" in
  ''|*[!0-9]*)
    echo "invalid PORT: $PORT" >&2
    exit 1
    ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "invalid PORT: $PORT" >&2
  exit 1
fi
case "$READY_TRIES" in
  ''|*[!0-9]*)
    echo "invalid READY_TRIES: $READY_TRIES" >&2
    exit 1
    ;;
esac
if [ "$READY_TRIES" -lt 1 ]; then
  echo "invalid READY_TRIES: $READY_TRIES" >&2
  exit 1
fi
case "$READY_SLEEP" in
  ''|*[!0-9]*)
    echo "invalid READY_SLEEP: $READY_SLEEP" >&2
    exit 1
    ;;
esac
if [ "$READY_SLEEP" -lt 1 ]; then
  echo "invalid READY_SLEEP: $READY_SLEEP" >&2
  exit 1
fi
case "$HOST" in
  *:*)
    case "$HOST" in
      '['*']')
        ;;
      *)
        echo "invalid HOST for IPv6 URL; use bracketed form like [::1]: $HOST" >&2
        exit 1
        ;;
    esac
    ;;
esac
case "$LISTEN_HOST" in
  127.0.0.1|localhost|'[::1]')
    ;;
  *)
    if [ "$ALLOW_REMOTE_LISTEN" != "1" ]; then
      echo "refusing non-loopback LISTEN_HOST for autosign e2e: $LISTEN_HOST" >&2
      echo "set ALLOW_REMOTE_LISTEN=1 to opt in" >&2
      exit 1
    fi
    ;;
esac

cleanup() {
  if [ -n "$SRV_PID" ]; then
    kill "$SRV_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

if [ -z "$FACTS_CA_SERVER" ]; then
  echo "== build server =="
  go build -o "$TMP/facts-ca-server" "$ROOT/cmd/facts-ca-server"
  FACTS_CA_SERVER="$TMP/facts-ca-server"
fi
if [ -z "$FACTS_CA_CLI" ]; then
  echo "== build cli =="
  go build -o "$TMP/facts-ca-cli" "$ROOT/cmd/facts-ca-cli"
  FACTS_CA_CLI="$TMP/facts-ca-cli"
fi

echo "== start server (autosign) =="
"$FACTS_CA_SERVER" -init -cadir "$TMP/cadir" -listen "$LISTEN_HOST:$PORT" \
  -hostname "$HOST" -autosign &
SRV_PID=$!

echo "== bootstrap node1.test (with Puppet trusted-fact extensions) =="
UUID=ED803750-E3C7-44F5-BB08-41A04433FE2E
BOOT_FILE="$TMP/bootstrap.out"
BOOT_READY=false
tries=0
while [ "$tries" -lt "$READY_TRIES" ]; do
  if ! kill -0 "$SRV_PID" 2>/dev/null; then echo "FAIL: server exited before becoming ready"; exit 1; fi
  if "$FACTS_CA_CLI" bootstrap --server "$HOST:$PORT" --certname node1.test \
    --ssldir "$TMP/ssl" --onetime --ext pp_role=web --ext "pp_uuid=$UUID" >"$BOOT_FILE" 2>&1; then
    BOOT_READY=true
    break
  fi
  tries=$((tries + 1))
  sleep "$READY_SLEEP"
done
[ "$BOOT_READY" = true ] || { cat "$BOOT_FILE" 2>/dev/null || true; echo "FAIL: bootstrap did not complete on $HOST:$PORT"; exit 1; }
BOOT=$(cat "$BOOT_FILE")
echo "$BOOT"

if command -v curl >/dev/null 2>&1; then
  echo "== raw Puppet API (any Puppet agent / curl can hit this) =="
  CA_PEM=$(curl -sk "https://$HOST:$PORT/puppet-ca/v1/certificate/ca")
  printf '%s\n' "$CA_PEM" | sed -n '1p'
  echo "  ^ CA cert served at /puppet-ca/v1/certificate/ca"
fi

echo "== assert the CA copied the extensions (OID + value) into the cert =="
echo "$BOOT" | grep -q "ext pp_role = web"         && echo "  ok: pp_role value=web"    || { echo "FAIL: pp_role value"; exit 1; }
echo "$BOOT" | grep -q "ext pp_uuid = $UUID"        && echo "  ok: pp_uuid value in cert" || { echo "FAIL: pp_uuid value"; exit 1; }
if command -v openssl >/dev/null 2>&1; then
  DUMP=$(openssl x509 -in "$TMP/ssl/certs/node1.test.pem" -noout -text)
  echo "$DUMP" | grep -q "1.3.6.1.4.1.34380.1.1.13" && echo "  ok: pp_role OID present" || { echo "FAIL: pp_role OID"; exit 1; }
fi

echo "== ssldir layout =="
( cd "$TMP/ssl" && find . -type f | sort )
test -f "$TMP/ssl/certs/node1.test.pem"        || { echo "FAIL: no leaf cert"; exit 1; }
test -f "$TMP/ssl/certs/ca.pem"                || { echo "FAIL: no CA cert"; exit 1; }
test -f "$TMP/ssl/private_keys/node1.test.pem" || { echo "FAIL: no private key"; exit 1; }

echo "== mTLS admin: ca list (client cert verified by server) =="
"$FACTS_CA_CLI" ca list --server "$HOST:$PORT" --ssldir "$TMP/ssl" | grep -q "node1.test" \
  && echo "  ok: node1.test listed via mTLS admin API" || { echo "FAIL: admin list"; exit 1; }

echo "== mTLS data path =="
MTLS_OUT=$("$FACTS_CA_CLI" mtls --server "$HOST:$PORT" --ssldir "$TMP/ssl" \
  --url "https://$HOST:$PORT/puppet-ca/v1/certificate/ca")
printf '%s\n' "$MTLS_OUT" | sed -n '1p'

echo "== verify chain with openssl =="
if command -v openssl >/dev/null 2>&1; then
  openssl verify -CAfile "$TMP/ssl/certs/ca.pem" "$TMP/ssl/certs/node1.test.pem"
else
  echo "  skipped: openssl not installed"
fi

echo "ALL E2E CHECKS PASSED"
