#!/bin/bash
# VScan-MOHESR CLI Installer
set -e

VERSION="1.0.0"
REPO="haydary1986/vscan-mohesr"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "╔═══════════════════════════════════════╗"
echo "║   VScan-MOHESR CLI Installer v${VERSION}  ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "Detected: ${OS}/${ARCH}"
echo ""

# Check if Docker is available for quick install
if command -v docker &> /dev/null; then
    echo "Docker detected. You can run VScan with:"
    echo ""
    echo "  docker run --rm ghcr.io/haydary1986/vscan-mohesr example.com"
    echo ""
    echo "Or install the binary? [y/N]"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Pulling Docker image..."
        docker pull ghcr.io/haydary1986/vscan-mohesr:latest
        echo ""
        echo "Done! Run: docker run --rm ghcr.io/haydary1986/vscan-mohesr example.com"
        exit 0
    fi
fi

# Download binary
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/vscan-${OS}-${ARCH}"
echo "Downloading from ${DOWNLOAD_URL}..."

if command -v curl &> /dev/null; then
    curl -sL "$DOWNLOAD_URL" -o /tmp/vscan
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O /tmp/vscan
else
    echo "Error: curl or wget required"
    exit 1
fi

chmod +x /tmp/vscan

# Install
INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ]; then
    mv /tmp/vscan "$INSTALL_DIR/vscan"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv /tmp/vscan "$INSTALL_DIR/vscan"
fi

echo ""
echo "VScan installed successfully!"
echo ""
echo "Usage:"
echo "  vscan example.com"
echo "  vscan -url https://example.com -output json"
echo "  vscan -file urls.txt -o results.json"
echo ""
