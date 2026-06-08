#!/usr/bin/env bash
# Capability-gated Linux e2e proof for the bubblewrap fallback path.
#
# This is not part of the default quickstart proof. It runs only when the
# caller opts in and the runner has a trusted bubblewrap executable available.
set -euo pipefail

if [ "${AXIS_RUN_BWRAP_E2E:-}" != "1" ]; then
    echo "SKIP: set AXIS_RUN_BWRAP_E2E=1 on a runner with bubblewrap installed"
    exit 77
fi

if ! command -v bwrap >/dev/null 2>&1; then
    echo "SKIP: bwrap not found on PATH"
    exit 77
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo is required to run the bubblewrap fallback proof"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: built axis bubblewrap fallback proof requires python3 on PATH"
    exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/axis-bwrap-e2e-XXXXXX)"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
cd "$REPO_ROOT"

cargo build --release -p axis-cli

if python3 - <<'PY'
import ctypes
import sys

SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
sys.exit(0 if ret >= 0 else 1)
PY
then
    echo "SKIP: built axis bwrap fallback requires a runner without Landlock; running crate-level fallback proof"
else
    POLICY_FILE="${TMP_ROOT}/policy.yaml"
    cat >"$POLICY_FILE" <<EOF
version: 1
name: bwrap-fallback-e2e

filesystem:
  read_only:
EOF
    for path in /bin /sbin /usr /lib /lib64 /etc /nix/store; do
        if [ -e "$path" ]; then
            printf '    - %s\n' "$path" >>"$POLICY_FILE"
        fi
    done
    cat >>"$POLICY_FILE" <<EOF
  read_write:
    - "{workspace}"

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0

network:
  mode: block
EOF
    (
        cd "$TMP_ROOT"
        timeout 30 "${REPO_ROOT}/target/release/axis" \
            --socket "/tmp/axis-bwrap-e2e-$$.sock" \
            run --policy "$POLICY_FILE" -- python3 -c 'import pathlib, socket, sys
pathlib.Path("inside.txt").write_text("ok")
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError:
    sys.exit(0)
print("network socket unexpectedly succeeded", file=sys.stderr)
sys.exit(42)'
    )
fi

AXIS_BWRAP_TESTS=1 \
    cargo test -p axis-sandbox \
    gated_bubblewrap_fallback_mounts_workspace_and_blocks_network \
    -- --nocapture
