#!/bin/bash
# Generate all certificates (TLS + JWT + mTLS)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔐 Generating all certificates..."
echo ""

# Generate TLS certificates
"$SCRIPT_DIR/gen_tls_certs.sh"
echo ""

# Generate JWT keys
"$SCRIPT_DIR/gen_jwt_keys.sh"
echo ""

# Generate mTLS client certificate
"$SCRIPT_DIR/gen_mtls_certs.sh"
echo ""

echo "✅ All certificates generated successfully!"
echo "💡 Run 'task configure-tls-env' to update .env file"
