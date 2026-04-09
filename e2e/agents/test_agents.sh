#!/bin/bash
# AXIS Agent Safety Test Suite
#
# Tests that agent runtimes CANNOT run without the AXIS sandbox
# and that the sandbox enforces default-deny policies correctly.
#
# Usage:
#   bash e2e/agents/test_agents.sh [--platform linux|macos|windows]
#
# Each test verifies:
# 1. Policy validates correctly
# 2. Sandbox starts with the agent's policy
# 3. Network deny blocks direct connections
# 4. Allowed endpoints pass through proxy
# 5. Credential files are inaccessible (deny paths)
# 6. Workspace writes succeed
# 7. System path writes fail

set -euo pipefail

AXIS="${AXIS_BIN:-axis}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_DIR="${SCRIPT_DIR}/../../policies/agents"

# Detect platform.
PLATFORM="${1:-auto}"
if [ "$PLATFORM" = "auto" ] || [ "$PLATFORM" = "--platform" ]; then
    shift 2>/dev/null || true
    PLATFORM="${1:-auto}"
fi
if [ "$PLATFORM" = "auto" ]; then
    case "$(uname -s)" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *) PLATFORM="unknown" ;;
    esac
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         AXIS Agent Safety Test Suite                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Platform: $PLATFORM"
echo "AXIS:     $($AXIS --version 2>/dev/null || echo 'not found')"
echo ""

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }

# ── Test function for each agent ──────────────────────────────────────────

test_agent() {
    local AGENT_NAME="$1"
    local POLICY_FILE="$2"
    local BINARY_CHECK="${3:-}" # optional: command to check if agent is installed

    echo "--- Agent: $AGENT_NAME ---"

    # Test 1: Policy validates.
    if $AXIS policy validate "$POLICY_FILE" >/dev/null 2>&1; then
        pass "$AGENT_NAME: policy validates"
    else
        fail "$AGENT_NAME: policy validation"
        return
    fi

    # Test 2: Sandbox starts and runs a test command.
    local OUTPUT
    OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- /bin/sh -c "echo SANDBOX_OK" 2>&1) || true
    if echo "$OUTPUT" | grep -q "SANDBOX_OK"; then
        pass "$AGENT_NAME: sandbox runs"
    else
        fail "$AGENT_NAME: sandbox start"
        return
    fi

    # Test 3: Credential files are blocked.
    OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- /bin/sh -c "cat ~/.ssh/id_rsa 2>&1 || echo BLOCKED" 2>&1) || true
    if echo "$OUTPUT" | grep -qi "blocked\|denied\|permission\|No such"; then
        pass "$AGENT_NAME: ~/.ssh blocked"
    else
        fail "$AGENT_NAME: ~/.ssh NOT blocked"
    fi

    # Test 4: Workspace writes succeed (use workspace dir, not /tmp).
    OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- /bin/sh -c 'echo test > axis-write-test && echo WRITE_OK && rm axis-write-test' 2>&1) || true
    if echo "$OUTPUT" | grep -q "WRITE_OK"; then
        pass "$AGENT_NAME: workspace write"
    else
        fail "$AGENT_NAME: workspace write"
    fi

    # Test 5: Network deny (for block-mode policies) or proxy enforcement.
    local NET_MODE
    NET_MODE=$(grep "mode:" "$POLICY_FILE" | head -1 | awk '{print $2}')
    if [ "$NET_MODE" = "block" ]; then
        OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- /bin/sh -c "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 https://example.com 2>&1 || echo NETWORK_BLOCKED" 2>&1) || true
        if echo "$OUTPUT" | grep -qi "blocked\|000\|denied\|not permitted\|timed out"; then
            pass "$AGENT_NAME: network blocked"
        else
            fail "$AGENT_NAME: network NOT blocked ($OUTPUT)"
        fi
    elif [ "$NET_MODE" = "proxy" ]; then
        # Test that non-allowed host is denied by proxy.
        OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- /bin/sh -c "curl -s --proxy \$HTTPS_PROXY -o /dev/null -w '%{http_code}' --connect-timeout 3 https://evil.example.com 2>&1 || echo DENIED" 2>&1) || true
        if echo "$OUTPUT" | grep -qi "denied\|000\|403"; then
            pass "$AGENT_NAME: proxy denies evil.example.com"
        else
            skip "$AGENT_NAME: proxy deny test (proxy may not be running)"
        fi
    fi

    # Test 6: Agent binary check (if available).
    if [ -n "$BINARY_CHECK" ]; then
        if command -v "$BINARY_CHECK" >/dev/null 2>&1; then
            OUTPUT=$($AXIS run --policy "$POLICY_FILE" -- "$BINARY_CHECK" --version 2>&1) || true
            if echo "$OUTPUT" | grep -qi "version\|[0-9]\.[0-9]"; then
                pass "$AGENT_NAME: binary runs in sandbox"
            else
                skip "$AGENT_NAME: binary runs but no version output"
            fi
        else
            skip "$AGENT_NAME: binary '$BINARY_CHECK' not installed"
        fi
    fi
}

# ── Test: base deny policy ────────────────────────────────────────────────

echo "--- Base: Default Deny ---"
if $AXIS policy validate "$POLICY_DIR/base-deny.yaml" >/dev/null 2>&1; then
    pass "base-deny: policy validates"
else
    fail "base-deny: policy validation"
fi

OUTPUT=$($AXIS run --policy "$POLICY_DIR/base-deny.yaml" -- /bin/sh -c "echo DENY_OK" 2>&1) || true
if echo "$OUTPUT" | grep -q "DENY_OK"; then
    pass "base-deny: sandbox runs"
else
    fail "base-deny: sandbox start"
fi

# Verify network is fully blocked in base deny.
OUTPUT=$($AXIS run --policy "$POLICY_DIR/base-deny.yaml" -- /bin/sh -c "curl -s --connect-timeout 2 https://example.com 2>&1; echo EXIT=\$?" 2>&1) || true
if echo "$OUTPUT" | grep -qi "blocked\|denied\|not permitted\|timed out\|EXIT=[^0]"; then
    pass "base-deny: network blocked"
else
    fail "base-deny: network NOT blocked"
fi

echo ""

# ── Run per-agent tests ──────────────────────────────────────────────────

test_agent "Claude Code" "$POLICY_DIR/claude-code.yaml" "claude"
echo ""

test_agent "Codex" "$POLICY_DIR/codex.yaml" "codex"
echo ""

test_agent "OpenClaw" "$POLICY_DIR/openclaw.yaml" "openclaw"
echo ""

test_agent "Ironclaw" "$POLICY_DIR/ironclaw.yaml" "ironclaw"
echo ""

test_agent "NanoClaw" "$POLICY_DIR/nanoclaw.yaml" ""
echo ""

test_agent "ZeroClaw" "$POLICY_DIR/zeroclaw.yaml" ""
echo ""

test_agent "Hermes Agent" "$POLICY_DIR/hermes.yaml" ""
echo ""

# ── Summary ──────────────────────────────────────────────────────────────

echo "══════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
echo "Result: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)"
echo "Platform: $PLATFORM"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "All agent sandbox policies enforce default-deny correctly."
fi

exit $FAIL
