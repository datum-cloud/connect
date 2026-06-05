#!/bin/bash
set -euo pipefail

# Build script for the datum-connect plugin
# Usage: ./scripts/build.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$CONNECT_DIR"

echo "Building datum-connect plugin..."

if go build -o connect . ; then
    echo "Build successful: $CONNECT_DIR/connect"
else
    echo "Build failed" >&2
    exit 1
fi
