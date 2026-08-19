#!/usr/bin/env bash
# Builds the CLI and runs a rehearsal `init` end to end into a fresh root.
#
# Rehearsal only. It generates same-host identities and keys, which are not
# production enrollment and prove nothing about participant independence.
# Never point this at a production ceremony root.
#
# usage: scripts/mpc-demo-init.sh [ROOT] [PARTICIPANTS]
set -euo pipefail
umask 077

ROOT=${1:-/tmp/mpcdemo}
PARTICIPANTS=${2:-3}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

# go build embeds vcs.revision and vcs.modified; `go run` does not, and the
# binary refuses to start without them (internal/mpcceremony/software.go).
export PATH="$HOME/.local/go/bin:$PATH"
command -v go >/dev/null || { echo "go not found on PATH" >&2; exit 1; }

[ -e "$ROOT" ] && { echo "refusing to reuse existing root: $ROOT" >&2; exit 1; }

BIN="$ROOT/bin/mpc-ceremony"
mkdir -p "$ROOT/bin"

echo "==> building CLI"
(cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/mpc-ceremony)

echo "==> generating rehearsal identities and canonical config"
(cd "$REPO_ROOT" && go run ./scripts/mpc-rehearsal-config \
  --out-dir "$ROOT/config-root" \
  --participants "$PARTICIPANTS")

CONFIG="$ROOT/config-root/config"
KEYS="$ROOT/config-root/keys"

# The key id must match participants.json, not an invented name. Read it back
# rather than hardcoding it.
COORDINATOR_KEY_ID=$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["coordinator"]["key_id"])' \
    "$CONFIG/participants.json"
)
echo "==> coordinator key id: $COORDINATOR_KEY_ID"

# Signed claim, so use an observed UTC time rather than a fabricated one.
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "==> init (compiles the K=21 circuit; expect several minutes)"
MPC_CEREMONY_DEBUG=${MPC_CEREMONY_DEBUG:-} "$BIN" --format json init \
  --key-version ownership-destination-v2 \
  --participants "$CONFIG/participants.json" \
  --policy "$CONFIG/policy.json" \
  --coordinator-key-id "$COORDINATOR_KEY_ID" \
  --coordinator-signing-key "$KEYS/coordinator.ed25519.private.hex" \
  --created-at "$CREATED_AT" \
  --mode rehearsal \
  --out-dir "$ROOT/public"

echo
echo "==> artifacts"
find "$ROOT/public" -type f -printf '%10s  %p\n' | sort -k2
