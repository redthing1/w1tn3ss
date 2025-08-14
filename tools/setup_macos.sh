#!/bin/bash
# setup script for macos development

set -e

CERT_NAME="w1tn3ss-dev"
BUILD_DIR="build-macos"

echo "setting up macos development environment..."

# check if certificate already exists
if security find-certificate -c "$CERT_NAME" >/dev/null 2>&1; then
    echo "certificate '$CERT_NAME' already exists"
else
    echo "generating certificate '$CERT_NAME'..."
    ./tools/macos_signing/genkey.sh "$CERT_NAME"
fi

# check if w1tool exists
if [ -f "$BUILD_DIR/w1tool" ]; then
    echo "signing w1tool..."
    ./tools/macos_signing/sign.sh "$CERT_NAME" "$BUILD_DIR/w1tool"
    echo "w1tool signed successfully"
else
    echo "w1tool not found - build project first with:"
    echo "  cmake -B $BUILD_DIR && cmake --build $BUILD_DIR"
fi

echo "macos setup complete"