#!/bin/bash
# Stop and remove container

set -euo pipefail

CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-auto}"
CONTAINER_NAME="${CONTAINER_NAME:-mcpgateway}"

# Auto-detect container runtime
if [ "$CONTAINER_RUNTIME" = "auto" ]; then
    if command -v podman &> /dev/null; then
        CONTAINER_RUNTIME="podman"
    elif command -v docker &> /dev/null; then
        CONTAINER_RUNTIME="docker"
    else
        echo "❌ No container runtime found"
        exit 1
    fi
fi

echo "🛑 Stopping container: $CONTAINER_NAME"

if $CONTAINER_RUNTIME ps -a --format "{{.Names}}" | grep -q "^$CONTAINER_NAME$"; then
    $CONTAINER_RUNTIME stop "$CONTAINER_NAME" || true
    $CONTAINER_RUNTIME rm "$CONTAINER_NAME" || true
    echo "✅ Container stopped and removed"
else
    echo "ℹ️  Container not running"
fi
