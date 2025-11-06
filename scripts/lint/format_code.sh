#!/bin/bash
# Auto-format code with autoflake, isort, and black

set -euo pipefail

TARGET="${1:-mcpgateway tests}"

echo "🔧 Auto-formatting code..."

# Autoflake - Remove unused imports and variables
echo "  Running autoflake..."
uv run autoflake \
    --in-place \
    --remove-all-unused-imports \
    --remove-unused-variables \
    --recursive \
    --exclude=__init__.py \
    $TARGET

# isort - Sort imports
echo "  Running isort..."
uv run isort \
    --profile=black \
    --line-length=200 \
    $TARGET

# Black - Format code
echo "  Running black..."
uv run black \
    --line-length=200 \
    $TARGET

echo "✅ Code formatting complete"
