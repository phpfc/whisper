#!/bin/bash
set -e

VERSION="0.1.0"
REPO="phpfc/t-chat"

echo "=== t-chat Release Script v$VERSION ==="
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required. Install with: brew install gh"
    exit 1
fi

# Check if cross is installed (for cross-compilation)
if ! command -v cross &> /dev/null; then
    echo "Installing cross for cross-compilation..."
    cargo install cross
fi

echo "Building release binaries..."
echo ""

# Build for current platform
echo "[1/4] Building for current platform..."
cargo build --release

# Create release directory
mkdir -p target/release/dist

# Detect current platform and create archive
case "$(uname -s)" in
    Darwin)
        PLATFORM="apple-darwin"
        ARCH="$(uname -m)"
        if [ "$ARCH" = "arm64" ]; then
            TARGET="aarch64-apple-darwin"
        else
            TARGET="x86_64-apple-darwin"
        fi
        cp target/release/t-chat target/release/dist/
        cd target/release/dist
        tar -czf "t-chat-$TARGET.tar.gz" t-chat
        rm t-chat
        cd -
        echo "  Created: t-chat-$TARGET.tar.gz"
        ;;
    Linux)
        TARGET="x86_64-unknown-linux-gnu"
        cp target/release/t-chat target/release/dist/
        cd target/release/dist
        tar -czf "t-chat-$TARGET.tar.gz" t-chat
        rm t-chat
        cd -
        echo "  Created: t-chat-$TARGET.tar.gz"
        ;;
esac

# Cross-compile for Windows (requires cross or cargo-xwin)
echo ""
echo "[2/4] Building for Windows (x86_64)..."
if command -v cross &> /dev/null; then
    cross build --release --target x86_64-pc-windows-msvc 2>/dev/null || {
        echo "  Skipping Windows build (cross-compilation not configured)"
    }
    if [ -f "target/x86_64-pc-windows-msvc/release/t-chat.exe" ]; then
        cp target/x86_64-pc-windows-msvc/release/t-chat.exe target/release/dist/
        cd target/release/dist
        zip -q "t-chat-x86_64-pc-windows-msvc.zip" t-chat.exe
        rm t-chat.exe
        cd -
        echo "  Created: t-chat-x86_64-pc-windows-msvc.zip"
    fi
else
    echo "  Skipping (cross not installed)"
fi

# Cross-compile for Linux (if on macOS)
echo ""
echo "[3/4] Building for Linux (x86_64)..."
if [ "$(uname -s)" = "Darwin" ] && command -v cross &> /dev/null; then
    cross build --release --target x86_64-unknown-linux-gnu 2>/dev/null || {
        echo "  Skipping Linux build (cross-compilation not configured)"
    }
    if [ -f "target/x86_64-unknown-linux-gnu/release/t-chat" ]; then
        cp target/x86_64-unknown-linux-gnu/release/t-chat target/release/dist/
        cd target/release/dist
        tar -czf "t-chat-x86_64-unknown-linux-gnu.tar.gz" t-chat
        rm t-chat
        cd -
        echo "  Created: t-chat-x86_64-unknown-linux-gnu.tar.gz"
    fi
else
    echo "  Skipping (already built or cross not available)"
fi

# Generate checksums
echo ""
echo "[4/4] Generating checksums..."
cd target/release/dist
shasum -a 256 * > SHA256SUMS.txt
cat SHA256SUMS.txt
cd -

echo ""
echo "=== Release artifacts ready in target/release/dist/ ==="
echo ""
echo "Next steps:"
echo "  1. Create a GitHub release: gh release create v$VERSION"
echo "  2. Upload artifacts: gh release upload v$VERSION target/release/dist/*"
echo "  3. Update Formula/t-chat.rb with SHA256 from source tarball"
echo "  4. Update chocolatey/tools/chocolateyinstall.ps1 with Windows SHA256"
echo ""
