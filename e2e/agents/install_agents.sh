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

USE_SYSTEM=false   # --use-system: wrap existing system binaries instead of installing

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

# ── Agent definitions (bash 3 compatible — no associative arrays) ────────

ALL_AGENTS="claude-code codex openclaw ironclaw aider goose gemini-cli opencode"

agent_binary() {
    case "$1" in
        claude-code) echo "claude" ;;
        codex)       echo "codex" ;;
        openclaw)    echo "openclaw" ;;
        ironclaw)    echo "ironclaw" ;;
        aider)       echo "aider" ;;
        goose)       echo "goose" ;;
        gemini-cli)  echo "gemini" ;;
        opencode)    echo "opencode" ;;
        *)           echo "$1" ;;
    esac
}

agent_default_flags() {
    case "$1" in
        claude-code) echo "--dangerously-skip-permissions" ;;
        codex)       echo "--full-auto" ;;
        *)           echo "" ;;
    esac
}

agent_policy() {
    case "$1" in
        claude-code) echo "claude-code.yaml" ;;
        codex)       echo "codex.yaml" ;;
        openclaw)    echo "openclaw.yaml" ;;
        ironclaw)    echo "ironclaw.yaml" ;;
        aider)       echo "hermes.yaml" ;;
        goose)       echo "hermes.yaml" ;;
        gemini-cli)  echo "gemini-cli.yaml" ;;
        opencode)    echo "opencode.yaml" ;;
        *)           echo "base-deny.yaml" ;;
    esac
}

agent_install_fn() {
    case "$1" in
        claude-code) echo "install_claude_code" ;;
        codex)       echo "install_codex" ;;
        openclaw)    echo "install_openclaw" ;;
        ironclaw)    echo "install_ironclaw" ;;
        aider)       echo "install_aider" ;;
        goose)       echo "install_goose" ;;
        gemini-cli)  echo "install_gemini_cli" ;;
        opencode)    echo "install_opencode" ;;
        *)           echo "" ;;
    esac
}

# ── Helpers ──────────────────────────────────────────────────────────────

# Check if a system binary exists and use it if --use-system is set.
# Returns the path if found, empty string otherwise.
try_system_binary() {
    local bin_name="$1"
    local system_bin
    system_bin=$(command -v "$bin_name" 2>/dev/null || true)

    if [ -n "$system_bin" ]; then
        if [ "$USE_SYSTEM" = true ]; then
            echo "  Using system binary: $system_bin" >&2
            echo "$system_bin"
            return 0
        else
            echo "  Found system binary at $system_bin (use --use-system to wrap it instead)" >&2
        fi
    fi
    return 1
}

# ── Install functions ────────────────────────────────────────────────────

install_claude_code() {
    # Check system binary first.
    local sys_bin
    sys_bin=$(try_system_binary "claude") && { echo "$sys_bin"; return 0; }

    local dir="$TOOLS_DIR/claude-code"
    mkdir -p "$dir"
    if [ "$OS" = "darwin" ] || [ "$OS" = "linux" ]; then
        curl -fsSL https://claude.ai/install.sh | CLAUDE_INSTALL_DIR="$dir" bash 2>&1 || true
    fi
    local bin=$(find "$dir" -name "claude" -type f 2>/dev/null | head -1)
    if [ -z "$bin" ] && command -v claude >/dev/null 2>&1; then
        bin="$(which claude)"
    fi
    echo "$bin"
}

install_codex() {
    local sys_bin
    sys_bin=$(try_system_binary "codex") && { echo "$sys_bin"; return 0; }

    local dir="$TOOLS_DIR/codex"
    mkdir -p "$dir"
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
    local sys_bin
    sys_bin=$(try_system_binary "openclaw") && { echo "$sys_bin"; return 0; }

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
    local sys_bin
    sys_bin=$(try_system_binary "ironclaw") && { echo "$sys_bin"; return 0; }

    local dir="$TOOLS_DIR/ironclaw"
    mkdir -p "$dir"
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
    local sys_bin
    sys_bin=$(try_system_binary "aider") && { echo "$sys_bin"; return 0; }

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
    local sys_bin
    sys_bin=$(try_system_binary "goose") && { echo "$sys_bin"; return 0; }

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

install_gemini_cli() {
    local sys_bin
    sys_bin=$(try_system_binary "gemini") && { echo "$sys_bin"; return 0; }

    local dir="$TOOLS_DIR/gemini-cli"
    mkdir -p "$dir"
    if command -v npm >/dev/null 2>&1; then
        npm install --prefix "$dir" @google/gemini-cli@latest 2>&1 | tail -3
        local bin="$dir/node_modules/.bin/gemini"
        if [ -x "$bin" ]; then echo "$bin"; return 0; fi
    fi
    if command -v gemini >/dev/null 2>&1; then
        echo "$(which gemini)"
    fi
}

install_opencode() {
    local sys_bin
    sys_bin=$(try_system_binary "opencode") && { echo "$sys_bin"; return 0; }

    local dir="$TOOLS_DIR/opencode"
    mkdir -p "$dir"
    if command -v npm >/dev/null 2>&1; then
        npm install --prefix "$dir" opencode-ai@latest 2>&1 | tail -3
        local bin="$dir/node_modules/.bin/opencode"
        if [ -x "$bin" ]; then echo "$bin"; return 0; fi
    fi
    if command -v opencode >/dev/null 2>&1; then
        echo "$(which opencode)"
    fi
}

# ── Wrapper script generator ────────────────────────────────────────────

create_wrapper() {
    local agent_name="$1"
    local binary_path="$2"
    local policy_file="$3"
    local binary_name
    binary_name=$(agent_binary "$agent_name")

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

    local default_flags
    default_flags=$(agent_default_flags "$agent_name")

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
#
# Default flags: ${default_flags:-none}
# Override: AXIS_NO_DEFAULT_FLAGS=1 ${binary_name} [args...]

AXIS_BIN="\${AXIS_BIN:-${axis_bin}}"
if [ -z "\${AXIS_NO_DEFAULT_FLAGS:-}" ]; then
    exec "\$AXIS_BIN" run --policy "${policy_file}" -- "${binary_path}" ${default_flags} "\$@"
else
    exec "\$AXIS_BIN" run --policy "${policy_file}" -- "${binary_path}" "\$@"
fi
WRAPPER

    chmod +x "$wrapper"
    echo "  Wrapper: $wrapper  (run as: ${binary_name})"
}

# ── Main ─────────────────────────────────────────────────────────────────

# Parse flags first.
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --use-system) USE_SYSTEM=true; shift ;;
        --list|--all|--help) POSITIONAL+=("$1"); shift ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]}"

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
        echo "  $0 --use-system             Wrap system-installed binaries (don't download)"
        echo "  $0 claude-code codex aider  Install specific agents"
        echo ""
        echo "Options:"
        echo "  --use-system   Use existing system binaries instead of installing"
        echo "                 new copies. Creates AXIS wrappers around the binaries"
        echo "                 already in your PATH."
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

    install_fn=$(agent_install_fn "$agent")
    if [ -z "$install_fn" ]; then
        echo "  Unknown agent: $agent"
        FAILED=$((FAILED+1))
        continue
    fi

    binary_path=$($install_fn 2>&1 | tail -1)

    if [ -n "$binary_path" ] && [ -x "$binary_path" ] 2>/dev/null; then
        echo "  Binary: $binary_path"

        policy_file="${POLICY_DIR}/$(agent_policy "$agent")"
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
        local_bin=$(agent_binary "$agent")
        if [ -x "$BIN_DIR/$local_bin" ]; then
            echo "  $local_bin --version        # runs through AXIS sandbox"
            echo "  axis $local_bin --version   # same thing, explicit"
        fi
    done
fi
