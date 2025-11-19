#!/bin/bash
# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Generate SWTPM Manufacturer Root CA and Intermediate CA
# This script creates a complete CA hierarchy for swtpm EK certificates

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_CA_DIR="${SCRIPT_DIR}/RootCA"
INTERMEDIATE_CA_DIR="${SCRIPT_DIR}/IntermediateCA"

echo "====================================================="
echo "Generating SWTPM Manufacturer CA Certificates"
echo "====================================================="
echo ""

# Create directory structure
mkdir -p "${ROOT_CA_DIR}"
mkdir -p "${INTERMEDIATE_CA_DIR}"

# Generate Root CA Private Key
echo "[1/6] Generating Root CA private key..."
openssl genrsa -out "${ROOT_CA_DIR}/swtpm-root-ca-key.pem" 4096
chmod 600 "${ROOT_CA_DIR}/swtpm-root-ca-key.pem"

# Generate Root CA Certificate
echo "[2/6] Generating Root CA certificate..."
openssl req -new -x509 -days 7300 -sha256 \
    -key "${ROOT_CA_DIR}/swtpm-root-ca-key.pem" \
    -out "${ROOT_CA_DIR}/SWTPM Manufacturer Root CA.crt" \
    -subj "/C=US/ST=California/L=San Francisco/O=SWTPM Manufacturer/OU=TPM Division/CN=SWTPM Manufacturer Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

echo "✓ Root CA certificate created"
echo "  Subject: /C=US/ST=California/L=San Francisco/O=SWTPM Manufacturer/OU=TPM Division/CN=SWTPM Manufacturer Root CA"
echo "  Valid for: 20 years"
echo ""

# Generate Intermediate CA Private Key
echo "[3/6] Generating Intermediate CA private key..."
openssl genrsa -out "${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca-key.pem" 2048
chmod 600 "${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca-key.pem"

# Generate Intermediate CA CSR
echo "[4/6] Generating Intermediate CA CSR..."
openssl req -new -sha256 \
    -key "${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca-key.pem" \
    -out "${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca.csr" \
    -subj "/C=US/ST=California/L=San Francisco/O=SWTPM Manufacturer/OU=TPM Division/CN=SWTPM TPM EK Intermediate CA"

# Sign Intermediate CA Certificate with Root CA
echo "[5/6] Signing Intermediate CA certificate with Root CA..."
openssl x509 -req -days 3650 -sha256 \
    -in "${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca.csr" \
    -CA "${ROOT_CA_DIR}/SWTPM Manufacturer Root CA.crt" \
    -CAkey "${ROOT_CA_DIR}/swtpm-root-ca-key.pem" \
    -CAcreateserial \
    -out "${INTERMEDIATE_CA_DIR}/SWTPM TPM EK Intermediate CA.crt" \
    -extfile <(cat <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF
)

echo "✓ Intermediate CA certificate created"
echo "  Subject: /C=US/ST=California/L=San Francisco/O=SWTPM Manufacturer/OU=TPM Division/CN=SWTPM TPM EK Intermediate CA"
echo "  Issuer: SWTPM Manufacturer Root CA"
echo "  Valid for: 10 years"
echo ""

# Create certificate chain file
echo "[6/6] Creating certificate chain..."
cat "${INTERMEDIATE_CA_DIR}/SWTPM TPM EK Intermediate CA.crt" \
    "${ROOT_CA_DIR}/SWTPM Manufacturer Root CA.crt" \
    > "${INTERMEDIATE_CA_DIR}/swtpm-ca-chain.pem"

echo "✓ Certificate chain created"
echo ""

# Display certificate information
echo "====================================================="
echo "Root CA Certificate Information:"
echo "====================================================="
openssl x509 -in "${ROOT_CA_DIR}/SWTPM Manufacturer Root CA.crt" -noout -subject -issuer -dates
echo ""

echo "====================================================="
echo "Intermediate CA Certificate Information:"
echo "====================================================="
openssl x509 -in "${INTERMEDIATE_CA_DIR}/SWTPM TPM EK Intermediate CA.crt" -noout -subject -issuer -dates
echo ""

echo "====================================================="
echo "Certificate Generation Complete!"
echo "====================================================="
echo ""
echo "Files created:"
echo "  Root CA:"
echo "    - ${ROOT_CA_DIR}/SWTPM Manufacturer Root CA.crt"
echo "    - ${ROOT_CA_DIR}/swtpm-root-ca-key.pem (private)"
echo ""
echo "  Intermediate CA:"
echo "    - ${INTERMEDIATE_CA_DIR}/SWTPM TPM EK Intermediate CA.crt"
echo "    - ${INTERMEDIATE_CA_DIR}/swtpm-intermediate-ca-key.pem (private)"
echo "    - ${INTERMEDIATE_CA_DIR}/swtpm-ca-chain.pem (full chain)"
echo ""
echo "These certificates will be used by swtpm to generate EK certificates."
echo ""
