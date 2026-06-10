#!/usr/bin/env bash
# Default no-dependency security test harness.
#
# This script is intentionally limited to Tier 0 and Tier 1 coverage. It must
# not require privileged host setup, local helper installation, real cloud
# credentials, or optional runtime artifacts.
set -euo pipefail

CARGO_BIN="${CARGO:-cargo}"

echo "=== AXIS Security Tier 0/1 ==="
echo "cargo: ${CARGO_BIN}"
echo ""

echo "--- Shared capability planner ---"
"${CARGO_BIN}" test -p axis-core capability

echo "--- Shared process backend planner ---"
"${CARGO_BIN}" test -p axis-core process_backend

echo "--- Shared container backend planner ---"
"${CARGO_BIN}" test -p axis-core container_backend

echo "--- Shared VM backend planner ---"
"${CARGO_BIN}" test -p axis-core vm_backend

echo "--- MXC fake executor and translation paths ---"
"${CARGO_BIN}" test -p axis-sandbox mxc -- --skip gated_
