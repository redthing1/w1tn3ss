#!/bin/bash
# setup script for macos development

set -euo pipefail

cd "$(dirname "$0")"

CERT_NAME="w1tn3ss-dev"
BUILD_DIR="build-macos"

echo "resigning ida to allow debugging..."

# check if certificate already exists
if security find-certificate -c "$CERT_NAME" >/dev/null 2>&1; then
    echo "certificate '$CERT_NAME' already exists"
else
    echo "generating certificate '$CERT_NAME'..."
    ./macos_signing/genkey.sh "$CERT_NAME"
fi


# find ida installs
for ida in "/Applications/IDA Professional "*".app"; do
    echo "found IDA at $ida"
    dbg_dir="$ida"/Contents/MacOS/dbgsrv
    if [ ! -d "$dbg_dir" ]; then
        echo "$ida doesn't have debug servers?"
        continue;
    fi
    for dbg in "$dbg_dir"/mac_server*; do
        echo "resigning $dbg"
        ./macos_signing/sign.sh "$CERT_NAME" "$dbg"
    done
done
