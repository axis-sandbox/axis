#!/bin/sh
# AXIS installer — downloads pre-built binaries from GitHub releases.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh
#   curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh -s -- --nightly
#
# Options:
#   --nightly     Install latest nightly build instead of stable release
#   --prefix DIR  Install to DIR (default: ~/.local/bin on Linux/macOS)
#   --version VER Install specific version (e.g., 0.1.0)

set -e

REPO="ROCm/axis"
INSTALL_DIR="${HOME}/.local/bin"
CHANNEL="release"
VERSION=""

# Parse args.
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly) CHANNEL="nightly"; shift ;;
        --prefix)  INSTALL_DIR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --help|-h)
            echo "AXIS installer"
            echo ""
            echo "Usage: curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh"
            echo ""
            echo "Options:"
            echo "  --nightly      Install nightly build"
            echo "  --prefix DIR   Install directory (default: ~/.local/bin)"
            echo "  --version VER  Specific version"
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
    echo "AXIS installer"
    echo ""
    echo "  Platform: ${PLATFORM}"
    echo "  Channel:  ${CHANNEL}"
    echo "  Install:  ${INSTALL_DIR}"
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
    mkdir -p "${INSTALL_DIR}"

    if [ "$OS" = "windows" ]; then
        unzip -q "${TMPDIR}/axis-archive" -d "${TMPDIR}/extracted"
    else
        tar xzf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted" 2>/dev/null || \
        tar xf "${TMPDIR}/axis-archive" -C "${TMPDIR}/extracted"
    fi

    # Install binaries.
    for bin in axis axsd; do
        if [ "$OS" = "windows" ]; then
            BIN_NAME="${bin}.exe"
        else
            BIN_NAME="${bin}"
        fi

        SRC=$(find "${TMPDIR}/extracted" -name "$BIN_NAME" -type f | head -1)
        if [ -n "$SRC" ]; then
            cp "$SRC" "${INSTALL_DIR}/${BIN_NAME}"
            chmod +x "${INSTALL_DIR}/${BIN_NAME}"
            echo "  Installed: ${INSTALL_DIR}/${BIN_NAME}"
        fi
    done

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
