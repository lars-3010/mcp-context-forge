#!/bin/bash
# Generate mTLS client certificates

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-./certs}"
CLIENT_NAME="${CLIENT_NAME:-client}"
DAYS="${DAYS:-825}"

if [ ! -f "$CERTS_DIR/ca-key.pem" ] || [ ! -f "$CERTS_DIR/ca-cert.pem" ]; then
    echo "❌ CA certificates not found. Run 'task gen-tls-certs' first"
    exit 1
fi

echo "🔐 Generating mTLS client certificate for '$CLIENT_NAME'..."
cd "$CERTS_DIR"

# Generate client key
echo "  Creating client private key..."
openssl genrsa -out "$CLIENT_NAME-key.pem" 4096

# Generate client CSR
echo "  Creating client certificate signing request..."
openssl req -new -key "$CLIENT_NAME-key.pem" -out "$CLIENT_NAME.csr" \
    -subj "/C=US/ST=State/L=City/O=Dev/CN=$CLIENT_NAME"

# Sign client cert
echo "  Signing client certificate..."
openssl x509 -req -days "$DAYS" -in "$CLIENT_NAME.csr" \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$CLIENT_NAME-cert.pem"

# Cleanup
rm -f "$CLIENT_NAME.csr"

# Set permissions
chmod 600 "$CLIENT_NAME-key.pem"
chmod 644 "$CLIENT_NAME-cert.pem"

echo "✅ mTLS client certificate generated in $CERTS_DIR/"
echo "📁 Files created:"
echo "   - $CLIENT_NAME-key.pem (Client private key)"
echo "   - $CLIENT_NAME-cert.pem (Client certificate)"
