#!/bin/bash
# Run all linters and static analysis tools

set -euo pipefail

TARGET="${1:-mcpgateway tests}"
FAIL_FAST="${FAIL_FAST:-1}"

ERRORS=0

run_linter() {
    local name="$1"
    shift
    echo "🔍 Running $name..."
    if "$@"; then
        echo "✅ $name passed"
    else
        echo "❌ $name failed"
        ERRORS=$((ERRORS + 1))
        if [ "$FAIL_FAST" = "1" ]; then
            exit 1
        fi
    fi
    echo ""
}

# Ruff - Fast Python linter
run_linter "ruff" uv run ruff check --select=F,E,W,B,ASYNC $TARGET

# Flake8 - Style guide enforcement
run_linter "flake8" uv run flake8 \
    --max-line-length=200 \
    --extend-ignore=E203,W503 \
    $TARGET

# Pylint - Comprehensive analysis
run_linter "pylint" uv run pylint \
    --rcfile=pyproject.toml \
    --errors-only \
    $TARGET

# Mypy - Type checking
run_linter "mypy" uv run mypy \
    --config-file=pyproject.toml \
    --strict \
    $TARGET

# Bandit - Security issues
run_linter "bandit" uv run bandit \
    -r $TARGET \
    -f json \
    -o bandit-report.json

# Interrogate - Docstring coverage
run_linter "interrogate" uv run interrogate \
    --verbose \
    --fail-under=80 \
    $TARGET

if [ $ERRORS -eq 0 ]; then
    echo "✅ All linters passed"
    exit 0
else
    echo "❌ $ERRORS linter(s) failed"
    exit 1
fi
