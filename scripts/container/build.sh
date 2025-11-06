#!/bin/bash
# Build container image

set -euo pipefail

CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-auto}"
IMAGE_NAME="${IMAGE_NAME:-mcpgateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Auto-detect container runtime
if [ "$CONTAINER_RUNTIME" = "auto" ]; then
    if command -v podman &> /dev/null; then
        CONTAINER_RUNTIME="podman"
    elif command -v docker &> /dev/null; then
        CONTAINER_RUNTIME="docker"
    else
        echo "❌ No container runtime found (docker or podman required)"
        exit 1
    fi
fi

echo "🐳 Building container: $IMAGE_NAME:$IMAGE_TAG"
echo "  Using: $CONTAINER_RUNTIME"

$CONTAINER_RUNTIME build \
    -t "$IMAGE_NAME:$IMAGE_TAG" \
    -f Containerfile \
    .

echo "✅ Container built: $IMAGE_NAME:$IMAGE_TAG"
