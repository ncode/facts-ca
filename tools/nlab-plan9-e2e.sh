#!/usr/bin/env bash
# Build facts-ca for Plan 9, copy it into nlab, and run the native rc e2e.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NLAB_HOST="${NLAB_HOST:-root@nlab.martinez.io}"
PORT="${PORT:-$((18000 + (RANDOM % 10000)))}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/facts-ca-plan9-e2e.XXXXXX")"
NONCE="$(date +%s)$$$RANDOM"
RUN_ID="fce2e$NONCE"
REMOTE_DIR="/tmp/$RUN_ID"
SERVER_PROC="s$NONCE"
CLI_PROC="c$NONCE"
REMOTE_SERVER="$REMOTE_DIR/$SERVER_PROC"
REMOTE_CLI="$REMOTE_DIR/$CLI_PROC"
REMOTE_SCRIPT="$REMOTE_DIR/e2e.rc"

case "$PORT" in
  ''|*[!0-9]*)
    echo "invalid PORT: $PORT" >&2
    exit 1
    ;;
esac
if ((PORT < 1 || PORT > 65535)); then
  echo "invalid PORT: $PORT" >&2
  exit 1
fi

cleanup() {
  ssh "$NLAB_HOST" "facts-lab ssh plan9 'slay $SERVER_PROC | rc; rm -rf $REMOTE_DIR'" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

server="$TMP/facts-ca-server"
cli="$TMP/facts-ca-cli"
CGO_ENABLED=0 GOOS=plan9 GOARCH=amd64 go build -o "$server" "$ROOT/cmd/facts-ca-server"
CGO_ENABLED=0 GOOS=plan9 GOARCH=amd64 go build -o "$cli" "$ROOT/cmd/facts-ca-cli"

ssh "$NLAB_HOST" "facts-lab ssh plan9 'mkdir -p $REMOTE_DIR'"
ssh "$NLAB_HOST" "facts-lab ssh plan9 'cat > $REMOTE_SERVER'" < "$server"
ssh "$NLAB_HOST" "facts-lab ssh plan9 'cat > $REMOTE_CLI'" < "$cli"
ssh "$NLAB_HOST" "facts-lab ssh plan9 'cat > $REMOTE_SCRIPT'" < "$ROOT/tools/nlab-plan9-e2e.rc"
ssh "$NLAB_HOST" "facts-lab ssh plan9 'chmod +x $REMOTE_SERVER $REMOTE_CLI; server=$REMOTE_SERVER cli=$REMOTE_CLI serverproc=$SERVER_PROC tmp=$REMOTE_DIR/work port=$PORT rc $REMOTE_SCRIPT'"
