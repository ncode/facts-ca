#!/usr/bin/env bash
# Run the facts-ca local server<->cli e2e proof on nlab Unix-like guests.
# Windows and Plan 9 need native script runners, so they stay out of this POSIX
# shell path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NLAB_HOST="${NLAB_HOST:-root@nlab.martinez.io}"
PORT="${PORT:-$((18000 + (RANDOM % 10000)))}"
TARGETS="${TARGETS:-ubuntu2404:linux:amd64 debian12:linux:amd64 fedora43:linux:amd64 opensuse-tumbleweed:linux:amd64 oracle9:linux:amd64 rocky9:linux:amd64 alma9:linux:amd64 alpine324:linux:amd64 arch:linux:amd64 nixos:linux:amd64 freebsd:freebsd:amd64 omnios:illumos:amd64 openbsd:openbsd:amd64 netbsd:netbsd:amd64 dragonfly:dragonfly:amd64}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/facts-ca-nlab-e2e.XXXXXX")"
RUN_ID="facts-ca-e2e-$(date +%s)-$$"
CURRENT_GUEST=
CURRENT_REMOTE_DIR=

cleanup() {
  if [ -n "$CURRENT_GUEST" ] && [ -n "$CURRENT_REMOTE_DIR" ]; then
    cleanup_guest "$CURRENT_GUEST" "$CURRENT_REMOTE_DIR"
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

validate_part() {
  local label=$1 value=$2
  if [[ ! $value =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "invalid $label: $value" >&2
    exit 1
  fi
}

copy_to_guest() {
  local guest=$1 src=$2 dst=$3
  ssh "$NLAB_HOST" "facts-lab ssh $guest 'mkdir -p ${dst%/*} && cat > $dst'" < "$src"
}

run_guest() {
  local guest=$1 cmd=$2
  ssh "$NLAB_HOST" "facts-lab ssh $guest '$cmd'"
}

cleanup_guest() {
  local guest=$1 dir=$2
  run_guest "$guest" "rm -rf $dir" >/dev/null 2>&1 || true
}

for target in $TARGETS; do
  IFS=: read -r guest goos goarch <<EOF
$target
EOF
  validate_part guest "$guest"
  validate_part goos "$goos"
  validate_part goarch "$goarch"

  echo "== $guest ($goos/$goarch) =="
  server="$TMP/facts-ca-server-$goos-$goarch"
  cli="$TMP/facts-ca-cli-$goos-$goarch"
  remote_dir="/tmp/$RUN_ID-$guest"
  remote_server="$remote_dir/facts-ca-server"
  remote_cli="$remote_dir/facts-ca-cli"
  remote_script="$remote_dir/e2e.sh"
  CURRENT_GUEST="$guest"
  CURRENT_REMOTE_DIR="$remote_dir"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o "$server" "$ROOT/cmd/facts-ca-server"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o "$cli" "$ROOT/cmd/facts-ca-cli"

  cleanup_guest "$guest" "$remote_dir"
  copy_to_guest "$guest" "$server" "$remote_server"
  copy_to_guest "$guest" "$cli" "$remote_cli"
  copy_to_guest "$guest" "$ROOT/e2e.sh" "$remote_script"
  if ! run_guest "$guest" "chmod +x $remote_server $remote_cli $remote_script && PORT=$PORT FACTS_CA_SERVER=$remote_server FACTS_CA_CLI=$remote_cli sh $remote_script"; then
    cleanup_guest "$guest" "$remote_dir"
    exit 1
  fi
  cleanup_guest "$guest" "$remote_dir"
  CURRENT_GUEST=
  CURRENT_REMOTE_DIR=
done
