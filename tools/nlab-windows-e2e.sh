#!/usr/bin/env bash
# Build facts-ca for Windows, copy it into nlab, and run the native PowerShell e2e.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NLAB_HOST="${NLAB_HOST:-root@nlab.martinez.io}"
PORT="${PORT:-}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/facts-ca-windows-e2e.XXXXXX")"
RUN_ID="facts-ca-e2e-$(date +%s)-$(basename "$TMP")"
REMOTE_DIR="/var/lib/facts-vms/autoinstall/$RUN_ID"
WIN_DIR="C:\\$RUN_ID"

encode_ps() {
  printf "%s" "$1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d "\n"
}

if [ -n "$PORT" ]; then
  case "$PORT" in
    *[!0-9]*)
      echo "invalid PORT: $PORT" >&2
      exit 1
      ;;
  esac
  if ((PORT < 1 || PORT > 65535)); then
    echo "invalid PORT: $PORT" >&2
    exit 1
  fi
fi

cleanup() {
  local ps enc
  ssh "$NLAB_HOST" "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
  ps="\$dir='$WIN_DIR'; Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \$dir"
  enc="$(encode_ps "$ps" 2>/dev/null)" || enc=
  if [ -n "$enc" ]; then
    ssh "$NLAB_HOST" "facts-lab ssh windows 'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc'" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

server="$TMP/facts-ca-server.exe"
cli="$TMP/facts-ca-cli.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$server" "$ROOT/cmd/facts-ca-server"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$cli" "$ROOT/cmd/facts-ca-cli"

ssh "$NLAB_HOST" "mkdir -p '$REMOTE_DIR'"
scp -q "$server" "$NLAB_HOST:$REMOTE_DIR/facts-ca-server.exe"
scp -q "$cli" "$NLAB_HOST:$REMOTE_DIR/facts-ca-cli.exe"
scp -q "$ROOT/tools/nlab-windows-e2e.ps1" "$NLAB_HOST:$REMOTE_DIR/facts-ca-e2e.ps1"

ps="\$ErrorActionPreference='Stop'; \$ProgressPreference='SilentlyContinue'; \$base='http://192.168.122.1/$RUN_ID'; \$dir='$WIN_DIR'; New-Item -ItemType Directory -Force -Path \$dir | Out-Null; Invoke-WebRequest -ErrorAction Stop -Uri \"\$base/facts-ca-server.exe\" -OutFile (Join-Path \$dir 'facts-ca-server.exe'); Invoke-WebRequest -ErrorAction Stop -Uri \"\$base/facts-ca-cli.exe\" -OutFile (Join-Path \$dir 'facts-ca-cli.exe'); Invoke-WebRequest -ErrorAction Stop -Uri \"\$base/facts-ca-e2e.ps1\" -OutFile (Join-Path \$dir 'facts-ca-e2e.ps1')"
enc="$(encode_ps "$ps")"
ssh "$NLAB_HOST" "facts-lab ssh windows 'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc'"
ps="\$ErrorActionPreference='Stop'; "
if [ -n "$PORT" ]; then
  ps="\$ErrorActionPreference='Stop'; \$env:PORT='$PORT'; "
fi
ps="${ps}try { & '$WIN_DIR\\facts-ca-e2e.ps1' } catch { Write-Error \$_; exit 1 }"
enc="$(encode_ps "$ps")"
ssh "$NLAB_HOST" "facts-lab ssh windows 'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc'"
