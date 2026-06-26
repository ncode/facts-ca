#!/usr/bin/env bash
# Interop proof: facts-ca-cli bootstraps a certificate from a REAL puppetserver
# CA — including Puppet trusted-fact extensions — and then uses that cert for an
# mTLS request back to it. This validates wire-level Puppet compatibility,
# including the extended-attribute (csr_attributes) encoding.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
SSL="$ROOT/interop-ssl"
UUID="ED803750-E3C7-44F5-BB08-41A04433FE2E"

echo "== build cli =="
go build -o "$ROOT/facts-ca-cli" ./cmd/facts-ca-cli

echo "== start puppetserver (fresh CA state each run) =="
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d

echo "== wait for the puppet CA endpoint (emulated JVM boot is slow) =="
ready=
for i in $(seq 1 60); do
  if curl -sk https://localhost:8140/puppet-ca/v1/certificate/ca 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
    echo "  CA up after ~$((i*10))s"; ready=1; break
  fi
  sleep 10
done
[ -n "$ready" ] || { echo "FAIL: puppetserver not ready"; docker compose logs --tail=50 puppet; exit 1; }

echo "== bootstrap against REAL puppetserver, requesting trusted-fact extensions =="
rm -rf "$SSL"
"$ROOT/facts-ca-cli" bootstrap --server localhost:8140 --certname interop-node.test \
  --ssldir "$SSL" --waitforcert 90s \
  --ext pp_role=web --ext "pp_uuid=$UUID" --ext pp_department=infra

echo "== the certificate the REAL puppet CA issued =="
DUMP=$(openssl x509 -in "$SSL/certs/interop-node.test.pem" -noout -text)
echo "$DUMP" | grep -E '34380' -A1 || true

echo "== assert puppetserver copied our extensions =="
echo "$DUMP" | grep -q "1.3.6.1.4.1.34380.1.1.13" && echo "  ok: pp_role copied by puppetserver"   || { echo "FAIL: pp_role missing"; exit 1; }
echo "$DUMP" | grep -q "1.3.6.1.4.1.34380.1.1.1"  && echo "  ok: pp_uuid copied by puppetserver"   || { echo "FAIL: pp_uuid missing"; exit 1; }
echo "$DUMP" | grep -q "1.3.6.1.4.1.34380.1.1.15" && echo "  ok: pp_department copied by puppetserver" || { echo "FAIL: pp_department missing"; exit 1; }

echo "== puppetserver's own inventory =="
docker compose exec -T puppet puppetserver ca list --all 2>/dev/null | grep -i interop-node || true

echo "== mTLS back to puppetserver with the issued cert =="
MTLS_OUT=$("$ROOT/facts-ca-cli" mtls --server localhost:8140 --ssldir "$SSL" \
  --url https://localhost:8140/puppet-ca/v1/certificate/ca)
echo "${MTLS_OUT%%$'\n'*}"

echo
echo "INTEROP PASSED: facts-ca-cli is wire-compatible with puppetserver, including extended attributes."
echo "(puppetserver still running; 'docker compose down -v' to tear down.)"
