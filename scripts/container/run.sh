#!/bin/bash
# Run container with configurable options

set -euo pipefail

CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-auto}"
IMAGE_NAME="${IMAGE_NAME:-mcpgateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-mcpgateway}"
PORT="${PORT:-4444}"
HOST_NETWORK="${HOST_NETWORK:-false}"
TLS_ENABLED="${TLS_ENABLED:-false}"
DETACH="${DETACH:-true}"

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

echo "🚀 Starting container: $IMAGE_NAME:$IMAGE_TAG"
echo "  Runtime: $CONTAINER_RUNTIME"
echo "  Port: $PORT"

# Build run command
RUN_ARGS="run --rm --name $CONTAINER_NAME"

# Detach mode
if [ "$DETACH" = "true" ]; then
    RUN_ARGS="$RUN_ARGS -d"
fi

# Networking
if [ "$HOST_NETWORK" = "true" ]; then
    echo "  Network: host"
    RUN_ARGS="$RUN_ARGS --network=host"
else
    echo "  Network: bridge"
    RUN_ARGS="$RUN_ARGS -p $PORT:$PORT"
fi

# TLS support
if [ "$TLS_ENABLED" = "true" ]; then
    echo "  TLS: enabled"
    if [ ! -d "./certs" ]; then
        echo "❌ ./certs directory not found"
        exit 1
    fi
    RUN_ARGS="$RUN_ARGS -v $(pwd)/certs:/app/certs:ro"
    RUN_ARGS="$RUN_ARGS -e TLS_ENABLED=true"
    RUN_ARGS="$RUN_ARGS -e TLS_CERT_FILE=/app/certs/server-cert.pem"
    RUN_ARGS="$RUN_ARGS -e TLS_KEY_FILE=/app/certs/server-key.pem"
fi

# Database
RUN_ARGS="$RUN_ARGS -e DATABASE_URL=sqlite:////tmp/mcp.db"

# Run container
$CONTAINER_RUNTIME $RUN_ARGS "$IMAGE_NAME:$IMAGE_TAG"

if [ "$DETACH" = "true" ]; then
    echo "✅ Container started: $CONTAINER_NAME"
    echo "💡 View logs: task container-logs"
    echo "💡 Stop: task container-stop"
else
    echo "✅ Container stopped"
fi
