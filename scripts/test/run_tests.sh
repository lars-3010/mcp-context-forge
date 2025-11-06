#!/bin/bash
# Run pytest test suite

set -euo pipefail

TEST_PATTERN="${1:-tests/}"
EXTRA_ARGS="${2:-}"

echo "🧪 Running tests: $TEST_PATTERN"

# Ensure we're in venv
if [ -z "${VIRTUAL_ENV:-}" ]; then
    VENV_DIR="${VENV_DIR:-$HOME/.venv/mcpgateway}"
    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
    else
        echo "❌ Virtual environment not found"
        exit 1
    fi
fi

# Run pytest with coverage
uv run pytest \
    --cov=mcpgateway \
    --cov-report=term-missing \
    --cov-report=html:docs/docs/coverage \
    --cov-report=xml:coverage.xml \
    --cov-report=annotate \
    -v \
    $EXTRA_ARGS \
    "$TEST_PATTERN"

echo "✅ Tests complete"
echo "📊 Coverage report: docs/docs/coverage/index.html"
