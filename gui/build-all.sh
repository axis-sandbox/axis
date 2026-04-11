#!/bin/bash
# Build script for AXIS GUI native apps.
# Builds the shared frontend, then copies dist/ into each platform app.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED_DIR="$SCRIPT_DIR/shared"

echo "=== Building shared frontend ==="
cd "$SHARED_DIR"
npm ci
npm run build
echo "Frontend built: $(du -sh dist/ | cut -f1)"

echo ""
echo "=== Bundling into platform apps ==="

# macOS
MACOS_WEB="$SCRIPT_DIR/macos/AXIS/Resources/web"
mkdir -p "$MACOS_WEB"
cp -r "$SHARED_DIR/dist/"* "$MACOS_WEB/"
echo "macOS: bundled to $MACOS_WEB"

# Linux
LINUX_WEB="$SCRIPT_DIR/linux/data/web"
mkdir -p "$LINUX_WEB"
cp -r "$SHARED_DIR/dist/"* "$LINUX_WEB/"
echo "Linux: bundled to $LINUX_WEB"

# Windows (copies happen via .csproj Content include at build time)
echo "Windows: will be bundled by MSBuild (Content include in .csproj)"

echo ""
echo "=== Done ==="
echo "Next steps:"
echo "  macOS:   cd gui/macos && swift build"
echo "  Linux:   cd gui/linux && cargo build --release"
echo "  Windows: cd gui/windows/AXIS && dotnet build"
