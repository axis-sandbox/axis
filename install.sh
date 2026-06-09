#!/bin/sh
# AXIS installer — downloads pre-built binaries from GitHub releases.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/axis-sandbox/axis/main/install.sh | sh
#   curl -sSf https://raw.githubusercontent.com/axis-sandbox/axis/main/install.sh | sh -s -- --nightly
#
# Options:
#   --nightly     Install latest nightly build instead of stable release
#   --prefix DIR  Install to DIR (default: ~/.local/bin on Linux/macOS)
#   --version VER Install specific version (e.g., 0.1.0)
#   --with-netns-helper
#                 Linux only: install the optional setuid netns helper for proxy mode
#   --with-cap-net-admin
#                 Linux only: grant CAP_NET_ADMIN to axis/axisd (advanced)

set -e

REPO="axis-sandbox/axis"
INSTALL_DIR="${HOME}/.local/bin"
INSTALL_DIR_EXPLICIT=0
CHANNEL="release"
VERSION=""
INSTALL_NETNS_HELPER=0
ENABLE_CAP_NET_ADMIN=0
HELPER_INSTALL_PATH="/usr/libexec/axis/axis-netns-helper"

# Parse args.
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly) CHANNEL="nightly"; shift ;;
        --prefix)  INSTALL_DIR="$2"; INSTALL_DIR_EXPLICIT=1; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --with-netns-helper) INSTALL_NETNS_HELPER=1; shift ;;
        --with-cap-net-admin) ENABLE_CAP_NET_ADMIN=1; shift ;;
        --help|-h)
            echo "AXIS installer"
            echo ""
            echo "Usage: curl -sSf https://raw.githubusercontent.com/axis-sandbox/axis/main/install.sh | sh"
            echo ""
            echo "Options:"
            echo "  --nightly              Install nightly build"
            echo "  --prefix DIR           Install directory (default: ~/.local/bin)"
            echo "  --version VER          Specific version"
            echo "  --with-netns-helper    Linux only: install optional proxy-mode helper"
            echo "  --with-cap-net-admin   Linux only: grant CAP_NET_ADMIN to axis/axisd"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Detect OS and architecture.
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="macos" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *)
            echo "Error: unsupported OS: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

need_privilege() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Error: this install option requires root or sudo"
        exit 1
    fi
}

require_linux_privilege_options() {
    if [ "$INSTALL_NETNS_HELPER" -eq 1 ] || [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        if [ "$OS" != "linux" ]; then
            echo "Error: privileged network install options are Linux-only"
            exit 1
        fi
    fi

    if [ "$INSTALL_NETNS_HELPER" -eq 1 ] && [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        echo "Error: choose either --with-netns-helper or --with-cap-net-admin, not both"
        exit 1
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ] && [ "$INSTALL_DIR_EXPLICIT" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        case "$INSTALL_DIR" in
            "$HOME"|"$HOME"/*)
                echo "Error: --with-cap-net-admin requires a root-owned install prefix"
                echo "Try: curl ... | sh -s -- --with-cap-net-admin --prefix /usr/local/bin"
                exit 1
                ;;
        esac
    fi
}

find_extracted_binary() {
    find "${TMPDIR}/extracted" -name "$1" -type f | head -1
}

install_user_binary() {
    SRC="$1"
    DEST="$2"
    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        need_privilege install -o root -g root -m 0755 "$SRC" "$DEST"
    else
        cp "$SRC" "$DEST"
        chmod +x "$DEST"
    fi
}

install_netns_helper() {
    HELPER_SRC=$(find_extracted_binary axis-netns-helper)
    if [ -z "$HELPER_SRC" ]; then
        echo "Error: archive does not contain axis-netns-helper"
        echo "Install without --with-netns-helper or use a release that ships the helper."
        exit 1
    fi

    echo "Installing optional netns helper..."
    need_privilege install -d -o root -g root -m 0755 "$(dirname "$HELPER_INSTALL_PATH")"
    need_privilege install -o root -g root -m 4755 "$HELPER_SRC" "$HELPER_INSTALL_PATH"
    echo "  Installed: ${HELPER_INSTALL_PATH} (root-owned, setuid)"
}

enable_cap_net_admin() {
    if command -v setcap >/dev/null 2>&1; then
        SETCAP=$(command -v setcap)
    elif [ -x /usr/sbin/setcap ]; then
        SETCAP=/usr/sbin/setcap
    elif [ -x /sbin/setcap ]; then
        SETCAP=/sbin/setcap
    else
        echo "Error: --with-cap-net-admin requires setcap"
        exit 1
    fi

    echo "Granting CAP_NET_ADMIN to AXIS binaries..."
    need_privilege "$SETCAP" cap_net_admin+ep "${INSTALL_DIR}/axis"
    need_privilege "$SETCAP" cap_net_admin+ep "${INSTALL_DIR}/axisd"
    echo "  CAP_NET_ADMIN: ${INSTALL_DIR}/axis"
    echo "  CAP_NET_ADMIN: ${INSTALL_DIR}/axisd"
}

# Get the download URL for the latest release.
get_download_url() {
    if [ "$CHANNEL" = "nightly" ]; then
        TAG="nightly"
    elif [ -n "$VERSION" ]; then
        TAG="v${VERSION}"
    else
        # Get latest release tag.
        TAG=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
        if [ -z "$TAG" ]; then
            echo "Error: cannot determine latest release"
            exit 1
        fi
    fi

    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
    fi

    URL="https://github.com/${REPO}/releases/download/${TAG}/axis-${PLATFORM}.${EXT}"
}

# Download and install.
install() {
    require_linux_privilege_options

    echo "AXIS installer"
    echo ""
    echo "  Platform: ${PLATFORM}"
    echo "  Channel:  ${CHANNEL}"
    echo "  Install:  ${INSTALL_DIR}"
    if [ "$INSTALL_NETNS_HELPER" -eq 1 ]; then
        echo "  Netns:    helper (${HELPER_INSTALL_PATH})"
    elif [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        echo "  Netns:    CAP_NET_ADMIN on axis/axisd"
    fi
    echo ""

    get_download_url

    echo "  Download: ${URL}"
    echo ""

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    # Download.
    echo "Downloading..."
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "${TMPDIR}/axis-archive" "$URL" || {
            echo ""
            echo "Error: download failed. URL: $URL"
            echo ""
            echo "If this is a new release, binaries may not be uploaded yet."
            echo "Try: --nightly or --version <version>"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${TMPDIR}/axis-archive" "$URL" || {
            echo "Error: download failed"
            exit 1
        }
    else
        echo "Error: curl or wget required"
        exit 1
    fi

    # Extract.
    echo "Extracting..."
    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        need_privilege install -d -o root -g root -m 0755 "${INSTALL_DIR}"
    else
        mkdir -p "${INSTALL_DIR}"
    fi

    mkdir -p "${TMPDIR}/extracted"
    if [ "$OS" = "windows" ]; then
        unzip -q "${TMPDIR}/axis-archive" -d "${TMPDIR}/extracted"
    else
        tar xzf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted" 2>/dev/null || \
        tar xf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted"
    fi

    # Install binaries.
    for bin in axis axisd; do
        if [ "$OS" = "windows" ]; then
            BIN_NAME="${bin}.exe"
        else
            BIN_NAME="${bin}"
        fi

        SRC=$(find_extracted_binary "$BIN_NAME")
        if [ -n "$SRC" ]; then
            install_user_binary "$SRC" "${INSTALL_DIR}/${BIN_NAME}"
            echo "  Installed: ${INSTALL_DIR}/${BIN_NAME}"
        fi
    done

    if [ "$INSTALL_NETNS_HELPER" -eq 1 ]; then
        install_netns_helper
    fi

    if [ "$ENABLE_CAP_NET_ADMIN" -eq 1 ]; then
        enable_cap_net_admin
    fi

    echo ""

    # Check PATH.
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo "Add to your PATH:"
            echo ""
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            SHELL_RC=""
            if [ -f "$HOME/.zshrc" ]; then
                SHELL_RC="$HOME/.zshrc"
            elif [ -f "$HOME/.bashrc" ]; then
                SHELL_RC="$HOME/.bashrc"
            fi
            if [ -n "$SHELL_RC" ]; then
                echo "Or run:"
                echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${SHELL_RC}"
                echo ""
            fi
            ;;
    esac

    echo "AXIS installed successfully!"
    echo ""
    echo "  axis --version"
    echo "  axis run -- echo 'Hello from sandbox'"
}

detect_platform
install
