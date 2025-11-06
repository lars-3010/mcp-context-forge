#!/bin/bash
# End-to-end container smoke test

set -euo pipefail

CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"

echo "🔥 Running smoke tests..."

# Detect container runtime
if command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_RUNTIME="docker"
else
    echo "❌ No container runtime found (docker or podman required)"
    exit 1
fi

echo "  Using: $CONTAINER_RUNTIME"

# Build container
echo "  Building container..."
$CONTAINER_RUNTIME build -t mcpgateway:test -f Containerfile .

# Run smoke test
echo "  Running smoke test..."
$CONTAINER_RUNTIME run --rm \
    -e DATABASE_URL=sqlite:///tmp/test.db \
    -e AUTH_REQUIRED=false \
    mcpgateway:test \
    python3 -m pytest tests/e2e/ -v --maxfail=1

echo "✅ Smoke tests passed"
