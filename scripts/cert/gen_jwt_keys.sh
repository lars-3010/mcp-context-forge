#!/bin/bash
# Generate JWT signing keys (RSA)

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-./certs}"
BITS="${BITS:-4096}"

echo "🔑 Generating JWT signing keys..."
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Generate private key
echo "  Creating JWT private key..."
openssl genrsa -out jwt-private-key.pem "$BITS"

# Extract public key
echo "  Extracting JWT public key..."
openssl rsa -in jwt-private-key.pem -pubout -out jwt-public-key.pem

# Set permissions
chmod 600 jwt-private-key.pem
chmod 644 jwt-public-key.pem

echo "✅ JWT keys generated in $CERTS_DIR/"
echo "📁 Files created:"
echo "   - jwt-private-key.pem (Private key for signing)"
echo "   - jwt-public-key.pem (Public key for verification)"
