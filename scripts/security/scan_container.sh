#!/bin/bash
# Scan container image for vulnerabilities using Trivy and Grype

set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-mcpgateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-true}"

echo "🔒 Scanning container image: $IMAGE_NAME:$IMAGE_TAG"
echo ""

ERRORS=0

# Trivy scan
if command -v trivy &> /dev/null; then
    echo "🔍 Running Trivy scan..."
    if trivy image \
        --severity HIGH,CRITICAL \
        --exit-code 0 \
        --format table \
        "$IMAGE_NAME:$IMAGE_TAG"; then
        echo "✅ Trivy scan complete"
    else
        echo "⚠️  Trivy found vulnerabilities"
        ERRORS=$((ERRORS + 1))
    fi
    echo ""
else
    echo "⚠️  Trivy not installed (skipping)"
    echo "   Install: https://aquasecurity.github.io/trivy/"
    echo ""
fi

# Grype scan
if command -v grype &> /dev/null; then
    echo "🔍 Running Grype scan..."
    if grype \
        "$IMAGE_NAME:$IMAGE_TAG" \
        --fail-on critical; then
        echo "✅ Grype scan complete"
    else
        echo "⚠️  Grype found vulnerabilities"
        ERRORS=$((ERRORS + 1))
    fi
    echo ""
else
    echo "⚠️  Grype not installed (skipping)"
    echo "   Install: https://github.com/anchore/grype"
    echo ""
fi

if [ $ERRORS -gt 0 ] && [ "$FAIL_ON_CRITICAL" = "true" ]; then
    echo "❌ Security scan failed with $ERRORS error(s)"
    exit 1
else
    echo "✅ Security scan complete"
fi
