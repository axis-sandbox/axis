#!/usr/bin/env bash
# Privileged Linux e2e proof for axis-netns-helper launch mode.
#
# This is intentionally an ephemeral-runner harness, not a local developer
# install path. It mutates /usr/libexec/axis only after an explicit opt-in so
# ordinary repo tests never depend on a host setuid helper.
set -euo pipefail

if [ "${AXIS_RUN_PRIVILEGED_E2E:-}" != "1" ]; then
    echo "SKIP: set AXIS_RUN_PRIVILEGED_E2E=1 in an ephemeral CI/container runner"
    exit 77
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: helper launch proof must run cargo test as a non-root user"
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo is required to install the helper inside the ephemeral test runner"
    exit 1
fi

if ! sudo -n true >/dev/null 2>&1; then
    echo "ERROR: passwordless sudo is required in the ephemeral test runner"
    exit 1
fi

for tool in cargo install stat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not found on PATH: $tool"
        exit 1
    fi
done

for tool in ip iptables sysctl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required netns proof tool not found on PATH: $tool"
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

cargo build -p axis-sandbox --bin axis-netns-helper

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="${REPO_ROOT}/${TARGET_DIR}" ;;
esac

HELPER_BUILD="${TARGET_DIR}/debug/axis-netns-helper"
HELPER_INSTALL="/usr/libexec/axis/axis-netns-helper"

if [ ! -x "$HELPER_BUILD" ]; then
    echo "ERROR: helper build output missing: $HELPER_BUILD"
    exit 1
fi

sudo install -d -o root -g root -m 0755 /usr/libexec/axis
sudo install -o root -g root -m 4755 "$HELPER_BUILD" "$HELPER_INSTALL"

owner="$(stat -c '%u:%g %a' "$HELPER_INSTALL")"
if [ "$owner" != "0:0 4755" ]; then
    echo "ERROR: helper install mode mismatch: $owner"
    exit 1
fi

AXIS_TEST_NETNS_HELPER_LAUNCH=1 \
    cargo test -p axis-sandbox \
    gated_netns_helper_launch_starts_proxy_mode_sandbox_as_unprivileged_daemon \
    -- --nocapture
