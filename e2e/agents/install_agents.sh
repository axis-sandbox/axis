#!/bin/bash
# AXIS Agent Installer
#
# Installs agent runtimes into a contained ~/.axis/tools/ directory.
# Each agent gets its own isolated install — no global pollution.
#
# Usage:
#   bash install_agents.sh [agent...]
#   bash install_agents.sh --all
#   bash install_agents.sh --list
#   bash install_agents.sh claude-code codex aider
#
# Agents are installed to ~/.axis/tools/<agent>/ and wrapper scripts
# are created in ~/.axis/bin/ that run the agent through AXIS sandbox.

set -euo pipefail

AXIS_ROOT="${HOME}/.axis"
TOOLS_DIR="${AXIS_ROOT}/tools"
BIN_DIR="${AXIS_ROOT}/bin"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /tmp)"
# Find policies: relative to script, or install bundled copies.
if [ -d "${SCRIPT_DIR}/../../policies/agents" ]; then
    POLICY_DIR="$(cd "${SCRIPT_DIR}/../../policies/agents" && pwd)"
else
    # Policies not found — use ~/.axis/policies/agents.
    POLICY_DIR="${AXIS_ROOT}/policies/agents"
    mkdir -p "$POLICY_DIR"
fi

# Detect platform.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

mkdir -p "$TOOLS_DIR" "$BIN_DIR"

# ── Agent definitions ────────────────────────────────────────────────────

declare -A AGENT_BINARY
declare -A AGENT_POLICY
declare -A AGENT_INSTALL

AGENT_BINARY[claude-code]="claude"
AGENT_POLICY[claude-code]="claude-code.yaml"
AGENT_INSTALL[claude-code]="install_claude_code"

AGENT_BINARY[codex]="codex"
AGENT_POLICY[codex]="codex.yaml"
AGENT_INSTALL[codex]="install_codex"

AGENT_BINARY[openclaw]="openclaw"
AGENT_POLICY[openclaw]="openclaw.yaml"
AGENT_INSTALL[openclaw]="install_openclaw"

AGENT_BINARY[ironclaw]="ironclaw"
AGENT_POLICY[ironclaw]="ironclaw.yaml"
AGENT_INSTALL[ironclaw]="install_ironclaw"

AGENT_BINARY[aider]="aider"
AGENT_POLICY[aider]="hermes.yaml"  # aider uses similar permissions to hermes
AGENT_INSTALL[aider]="install_aider"

AGENT_BINARY[goose]="goose"
AGENT_POLICY[goose]="hermes.yaml"
AGENT_INSTALL[goose]="install_goose"

ALL_AGENTS="claude-code codex openclaw ironclaw aider goose"

# ── Install functions ────────────────────────────────────────────────────

install_claude_code() {
    local dir="$TOOLS_DIR/claude-code"
    mkdir -p "$dir"
    if [ "$OS" = "darwin" ] || [ "$OS" = "linux" ]; then
        curl -fsSL https://claude.ai/install.sh | CLAUDE_INSTALL_DIR="$dir" bash 2>&1 || {
            # Fallback: check if already installed globally
            if command -v claude >/dev/null 2>&1; then
                echo "Using system-installed claude"
                ln -sf "$(which claude)" "$dir/claude"
            else
                echo "Install failed"
                return 1
            fi
        }
    fi
    # Find the binary
    local bin=$(find "$dir" -name "claude" -type f 2>/dev/null | head -1)
    if [ -z "$bin" ] && command -v claude >/dev/null 2>&1; then
        bin="$(which claude)"
    fi
    echo "$bin"
}

install_codex() {
    local dir="$TOOLS_DIR/codex"
    mkdir -p "$dir"
    # Install via npm into contained directory
    if command -v npm >/dev/null 2>&1; then
        npm install --prefix "$dir" @openai/codex 2>&1 | tail -3
        echo "$dir/node_modules/.bin/codex"
    elif command -v codex >/dev/null 2>&1; then
        echo "$(which codex)"
    else
        echo "npm not found, cannot install codex" >&2
        return 1
    fi
}

install_openclaw() {
    local dir="$TOOLS_DIR/openclaw"
    mkdir -p "$dir"
    if command -v npm >/dev/null 2>&1; then
        npm install --prefix "$dir" openclaw@latest 2>&1 | tail -3
        echo "$dir/node_modules/.bin/openclaw"
    elif command -v openclaw >/dev/null 2>&1; then
        echo "$(which openclaw)"
    else
        echo "npm not found" >&2
        return 1
    fi
}

install_ironclaw() {
    local dir="$TOOLS_DIR/ironclaw"
    mkdir -p "$dir"
    # Download release binary
    local url="https://github.com/nearai/ironclaw/releases/latest/download/ironclaw-${ARCH}-${OS}"
    if curl -fsSL -o "$dir/ironclaw" "$url" 2>/dev/null; then
        chmod +x "$dir/ironclaw"
        echo "$dir/ironclaw"
    elif command -v ironclaw >/dev/null 2>&1; then
        echo "$(which ironclaw)"
    else
        echo "Download failed" >&2
        return 1
    fi
}

install_aider() {
    local dir="$TOOLS_DIR/aider"
    mkdir -p "$dir"
    if command -v python3 >/dev/null 2>&1; then
        python3 -m venv "$dir/venv" 2>/dev/null
        "$dir/venv/bin/pip" install -q aider-chat 2>&1 | tail -3
        echo "$dir/venv/bin/aider"
    elif command -v aider >/dev/null 2>&1; then
        echo "$(which aider)"
    else
        echo "python3 not found" >&2
        return 1
    fi
}

install_goose() {
    local dir="$TOOLS_DIR/goose"
    mkdir -p "$dir"
    if [ "$OS" = "darwin" ] && command -v brew >/dev/null 2>&1; then
        brew install block-goose-cli 2>&1 | tail -3
        echo "$(which goose)"
    else
        curl -fsSL https://github.com/block/goose/releases/download/stable/download_cli.sh \
            | INSTALL_DIR="$dir" bash 2>&1 || true
        local bin=$(find "$dir" -name "goose" -type f 2>/dev/null | head -1)
        if [ -z "$bin" ] && command -v goose >/dev/null 2>&1; then
            bin="$(which goose)"
        fi
        echo "$bin"
    fi
}

# ── Wrapper script generator ────────────────────────────────────────────

create_wrapper() {
    local agent_name="$1"
    local binary_path="$2"
    local policy_file="$3"
    local binary_name="${AGENT_BINARY[$agent_name]}"

    # Find axis binary.
    local axis_bin
    axis_bin=$(command -v axis 2>/dev/null || echo "")
    if [ -z "$axis_bin" ] || [ ! -x "$axis_bin" ]; then
        for candidate in /usr/local/bin/axis /usr/bin/axis "$HOME/.local/bin/axis" "$HOME/.cargo/bin/axis"; do
            if [ -x "$candidate" ]; then axis_bin="$candidate"; break; fi
        done
    fi
    axis_bin="${axis_bin:-axis}"

    # Create wrapper named as the original binary (e.g., "claude", "codex").
    # When ~/.axis/bin is first in PATH, running "claude" goes through AXIS.
    local wrapper="$BIN_DIR/${binary_name}"

    cat > "$wrapper" << WRAPPER
#!/bin/bash
# AXIS-sandboxed ${binary_name}
#
# This wrapper ensures ${binary_name} ALWAYS runs inside an AXIS sandbox.
# Agent state: ~/.axis/agents/
# Policy:      ${policy_file}
# Real binary: ${binary_path}
#
# Usage: ${binary_name} [args...]       (when ~/.axis/bin is in PATH)
#    or: axis ${binary_name} [args...]  (via axis subcommand extension)

AXIS_BIN="\${AXIS_BIN:-${axis_bin}}"
exec "\$AXIS_BIN" run --policy "${policy_file}" -- "${binary_path}" "\$@"
WRAPPER

    chmod +x "$wrapper"
    echo "  Wrapper: $wrapper  (run as: ${binary_name})"
}

# ── Main ─────────────────────────────────────────────────────────────────

if [ "${1:-}" = "--list" ]; then
    echo "Available agents:"
    for agent in $ALL_AGENTS; do
        local_bin="${TOOLS_DIR}/${agent}"
        if [ -d "$local_bin" ]; then
            echo "  $agent  [installed]"
        else
            echo "  $agent"
        fi
    done
    exit 0
fi

if [ "${1:-}" = "--all" ]; then
    AGENTS="$ALL_AGENTS"
else
    AGENTS="${*:-}"
    if [ -z "$AGENTS" ]; then
        echo "AXIS Agent Installer"
        echo ""
        echo "Usage:"
        echo "  $0 --all                    Install all agents"
        echo "  $0 --list                   List available agents"
        echo "  $0 claude-code codex aider  Install specific agents"
        echo ""
        echo "Available: $ALL_AGENTS"
        echo ""
        echo "Agents are installed to ~/.axis/tools/ and wrapped with"
        echo "AXIS sandbox policies. Add ~/.axis/bin to PATH, then run"
        echo "agents normally: claude, codex, aider, etc."
        echo "Or use: axis claude, axis codex, axis aider"
        exit 0
    fi
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         AXIS Agent Installer                             ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Install dir: $TOOLS_DIR"
echo "Wrappers:    $BIN_DIR"
echo ""

INSTALLED=0
FAILED=0

for agent in $AGENTS; do
    echo "--- Installing: $agent ---"

    install_fn="${AGENT_INSTALL[$agent]:-}"
    if [ -z "$install_fn" ]; then
        echo "  Unknown agent: $agent"
        FAILED=$((FAILED+1))
        continue
    fi

    binary_path=$($install_fn 2>&1 | tail -1)

    if [ -n "$binary_path" ] && [ -x "$binary_path" ] 2>/dev/null; then
        echo "  Binary: $binary_path"

        policy_file="${POLICY_DIR}/${AGENT_POLICY[$agent]}"
        if [ ! -f "$policy_file" ]; then
            echo "  Warning: policy not found at $policy_file, using base-deny"
            policy_file="${POLICY_DIR}/base-deny.yaml"
        fi

        create_wrapper "$agent" "$binary_path" "$policy_file"
        INSTALLED=$((INSTALLED+1))
        echo "  OK"
    else
        echo "  Failed to install (binary not found)"
        FAILED=$((FAILED+1))
    fi
    echo ""
done

echo "══════════════════════════════════════════════════════════"
echo "Installed: $INSTALLED  Failed: $FAILED"
echo ""
if [ $INSTALLED -gt 0 ]; then
    echo "Add to PATH (before system paths):"
    echo ""
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
    echo "Then run agents normally — they go through AXIS automatically:"
    echo ""
    for agent in $AGENTS; do
        local_bin="${AGENT_BINARY[$agent]:-$agent}"
        if [ -x "$BIN_DIR/$local_bin" ]; then
            echo "  $local_bin --version        # runs through AXIS sandbox"
            echo "  axis $local_bin --version   # same thing, explicit"
        fi
    done
fi
