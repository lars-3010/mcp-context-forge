#!/bin/bash
# Generate TLS certificates with auto-signed CA

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-./certs}"
HOST="${HOST:-localhost}"
DAYS="${DAYS:-825}"

echo "🔐 Generating TLS certificates..."
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Generate CA key
if [ ! -f ca-key.pem ]; then
    echo "  Creating CA private key..."
    openssl genrsa -out ca-key.pem 4096
fi

# Generate CA cert
if [ ! -f ca-cert.pem ]; then
    echo "  Creating CA certificate..."
    openssl req -new -x509 -days "$DAYS" -key ca-key.pem -out ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=Dev/CN=DevCA"
fi

# Generate server key
echo "  Creating server private key..."
openssl genrsa -out server-key.pem 4096

# Generate server CSR
echo "  Creating server certificate signing request..."
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Dev/CN=$HOST"

# Create SAN config
cat > san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HOST
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Sign server cert
echo "  Signing server certificate..."
openssl x509 -req -days "$DAYS" -in server.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem -extensions v3_req -extfile san.cnf

# Cleanup
rm -f server.csr san.cnf

# Set permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem

echo "✅ TLS certificates generated in $CERTS_DIR/"
echo "📁 Files created:"
echo "   - ca-key.pem (CA private key)"
echo "   - ca-cert.pem (CA certificate)"
echo "   - server-key.pem (Server private key)"
echo "   - server-cert.pem (Server certificate)"
