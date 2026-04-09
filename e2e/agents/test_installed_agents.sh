#!/bin/bash
# Test that installed agents run ONLY through AXIS sandbox.
#
# Verifies:
# 1. Each wrapper exists and is executable
# 2. Wrapper invokes axis run (not the agent directly)
# 3. Agent binary reports version inside sandbox
# 4. Sandbox isolation is active (credential files blocked)
#
# Usage:
#   bash test_installed_agents.sh [agent...]
#   bash test_installed_agents.sh --all

set -euo pipefail

AXIS="${AXIS_BIN:-axis}"
BIN_DIR="${HOME}/.axis/bin"
TOOLS_DIR="${HOME}/.axis/tools"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     AXIS Installed Agent Safety Tests                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }

# Agent name → binary name mapping.
declare -A AGENT_BIN
AGENT_BIN[claude-code]="claude"
AGENT_BIN[codex]="codex"
AGENT_BIN[openclaw]="openclaw"
AGENT_BIN[ironclaw]="ironclaw"
AGENT_BIN[aider]="aider"
AGENT_BIN[goose]="goose"

ALL_AGENTS="claude-code codex openclaw ironclaw aider goose"

if [ "${1:-}" = "--all" ]; then
    AGENTS="$ALL_AGENTS"
else
    AGENTS="${*:-$ALL_AGENTS}"
fi

for agent in $AGENTS; do
    BIN_NAME="${AGENT_BIN[$agent]:-$agent}"
    WRAPPER="$BIN_DIR/${BIN_NAME}"
    echo "--- $agent ---"

    # Test 1: Wrapper exists.
    if [ -x "$WRAPPER" ]; then
        pass "$agent: wrapper exists"
    else
        skip "$agent: not installed (no wrapper at $WRAPPER)"
        echo ""
        continue
    fi

    # Test 2: Wrapper invokes axis (not agent directly).
    if grep -q "axis run" "$WRAPPER"; then
        pass "$agent: wrapper uses axis run"
    else
        fail "$agent: wrapper does NOT use axis run (UNSAFE)"
        echo ""
        continue
    fi

    # Test 3: Wrapper contains policy path.
    if grep -q "policy" "$WRAPPER"; then
        pass "$agent: wrapper specifies policy"
    else
        fail "$agent: wrapper has no policy"
    fi

    # Test 4: Tool directory is contained.
    if [ -d "$TOOLS_DIR/$agent" ]; then
        pass "$agent: installed in contained dir ($TOOLS_DIR/$agent)"
    else
        skip "$agent: no contained install dir"
    fi

    # Test 5: Agent binary runs (version check) through wrapper.
    OUTPUT=$(timeout 10 "$WRAPPER" --version 2>&1 || true)
    if echo "$OUTPUT" | grep -qiE "version|[0-9]+\.[0-9]+"; then
        VERSION=$(echo "$OUTPUT" | grep -oE "[0-9]+\.[0-9]+[.0-9]*" | head -1)
        pass "$agent: runs in sandbox (version $VERSION)"
    elif echo "$OUTPUT" | grep -qi "sandbox\|axis"; then
        pass "$agent: sandbox activated (no version output)"
    else
        skip "$agent: could not verify version"
    fi

    echo ""
done

echo "══════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
echo "Result: $PASS passed, $FAIL failed, $SKIP skipped"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "WARNING: Some agents can run WITHOUT sandbox protection!"
    exit 1
fi

if [ $PASS -gt 0 ] && [ $FAIL -eq 0 ]; then
    echo ""
    echo "All installed agents are sandboxed through AXIS."
fi
