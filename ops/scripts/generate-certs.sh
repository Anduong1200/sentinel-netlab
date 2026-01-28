#!/bin/bash
# =============================================================================
# Sentinel NetLab - Self-Signed Certificate Generator
# For development and testing only. Use proper CA certs in production!
# =============================================================================

set -e

CERT_DIR="${1:-./certs}"
DAYS="${2:-365}"
CN="${3:-sentinel.local}"

mkdir -p "$CERT_DIR"

echo "Generating self-signed certificates..."
echo "  Directory: $CERT_DIR"
echo "  Valid for: $DAYS days"
echo "  Common Name: $CN"
echo ""

# Generate CA key and certificate
openssl genrsa -out "$CERT_DIR/ca.key" 4096

openssl req -x509 -new -nodes \
    -key "$CERT_DIR/ca.key" \
    -sha256 \
    -days "$DAYS" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=Sentinel/OU=NetLab/CN=Sentinel CA"

echo "✓ CA certificate generated"

# Generate server key
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate server CSR
openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=Sentinel/OU=Controller/CN=$CN"

# Create extensions file for SAN
cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $CN
DNS.2 = localhost
DNS.3 = controller
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS" \
    -sha256 \
    -extfile "$CERT_DIR/server.ext"

echo "✓ Server certificate generated"

# Generate client certificate (for mTLS)
openssl genrsa -out "$CERT_DIR/client.key" 2048

openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=State/L=City/O=Sentinel/OU=Sensor/CN=sensor-client"

openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days "$DAYS" \
    -sha256

echo "✓ Client certificate generated (for mTLS)"

# Cleanup CSR and temp files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.ext "$CERT_DIR"/*.srl

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo ""
echo "=== Certificates Generated ==="
ls -la "$CERT_DIR"
echo ""
echo "Files:"
echo "  CA:     $CERT_DIR/ca.crt, $CERT_DIR/ca.key"
echo "  Server: $CERT_DIR/server.crt, $CERT_DIR/server.key"
echo "  Client: $CERT_DIR/client.crt, $CERT_DIR/client.key"
echo ""
echo "To verify: openssl x509 -in $CERT_DIR/server.crt -text -noout"
