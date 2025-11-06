#!/bin/bash
# Run mutation testing with mutmut

set -euo pipefail

TARGET="${1:-mcpgateway/}"
WORKERS="${2:-auto}"

echo "🧬 Running mutation testing on $TARGET"

# Ensure mutmut is installed
if ! command -v mutmut &> /dev/null; then
    echo "  Installing mutmut..."
    uv pip install mutmut
fi

# Run mutation testing
mutmut run \
    --paths-to-mutate="$TARGET" \
    --runner="pytest -x --maxfail=1" \
    --tests-dir=tests/ \
    --use-coverage \
    --workers="$WORKERS"

# Generate report
echo ""
echo "📊 Mutation testing results:"
mutmut results

# Generate HTML report
mutmut html
echo "📈 HTML report: html/index.html"

echo "✅ Mutation testing complete"
