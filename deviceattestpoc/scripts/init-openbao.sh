#!/bin/bash
# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Initialize OpenBao with PKI backend, attestation configuration,
# and role for IPsec VPN certificates with device attestation

set -e

echo "========================================="
echo "OpenBao Initialization for Device Attestation PoC"
echo "========================================="
echo "OpenBao Address: $BAO_ADDR"
echo

# Wait for OpenBao to be ready
echo "Waiting for OpenBao to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
  if curl -s -f "$BAO_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo "✓ OpenBao is ready"
    break
  fi
  attempt=$((attempt + 1))
  echo "  Attempt $attempt/$max_attempts..."
  sleep 1
done

if [ $attempt -eq $max_attempts ]; then
  echo "✗ OpenBao failed to become ready"
  exit 1
fi

echo

# Function to make API request
api_request() {
    local method=$1
    local path=$2
    local data=$3

    echo ">>> $method $path"

    if [ -z "$data" ]; then
        response=$(curl -s -X "$method" \
            -H "X-Vault-Token: $BAO_TOKEN" \
            "$BAO_ADDR/v1/$path")
    else
        response=$(curl -s -X "$method" \
            -H "X-Vault-Token: $BAO_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BAO_ADDR/v1/$path")
    fi

    echo "Response:"
    echo "$response" | jq .
    echo

    # Check for errors
    if echo "$response" | jq -e '.errors' > /dev/null 2>&1; then
        echo "❌ ERROR: Request failed"
        return 1
    fi

    echo "✓ Success"
    echo
}

# Step 1: Enable PKI backend
echo "=== Step 1: Enable PKI Backend ==="
# Unmount first if exists
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki" '{
  "type": "pki",
  "config": {
    "max_lease_ttl": "87600h"
  }
}'

# Step 1b: Configure allowed response headers for ACME
echo "=== Step 1b: Configure Allowed Response Headers for ACME ==="
api_request POST "sys/mounts/pki/tune" '{
  "allowed_response_headers": ["Last-Modified", "Replay-Nonce", "Link", "Location"]
}'

# Step 2: Generate root CA
echo "=== Step 2: Generate Root CA ==="
api_request POST "pki/root/generate/internal" '{
  "common_name": "OpenBao PoC Root CA",
  "issuer_name": "root-ca",
  "ttl": "87600h",
  "key_type": "rsa",
  "key_bits": 2048
}'

# Step 3: Configure global attestation settings
echo "=== Step 3: Configure Global Attestation Settings ==="
api_request POST "pki/config/attestation" '{
  "enabled": true,
  "validate_ek_certificate": true,
  "default_attestation_policies": [],
  "allowed_attestation_formats": ["tpm"]
}'

# Step 4: Read attestation configuration
echo "=== Step 4: Read Attestation Configuration ==="
api_request GET "pki/config/attestation"

# Step 5: Create role for IPsec VPN with device attestation
echo "=== Step 5: Create IPsec VPN Role with Device Attestation ==="
api_request POST "pki/roles/ipsec-vpn" '{
  "allowed_domains": ["example.com"],
  "allow_subdomains": true,
  "allow_glob_domains": true,
  "max_ttl": "72h",
  "allow_ip_sans": true,
  "server_flag": false,
  "client_flag": true,
  "key_type": "rsa",
  "key_bits": 2048,
  "key_usage": [
    "DigitalSignature",
    "KeyEncipherment",
    "KeyAgreement"
  ],
  "ext_key_usage": [
    "ClientAuth"
  ],
  "ext_key_usage_oids": [
    "1.3.6.1.5.5.7.3.5",
    "1.3.6.1.5.5.7.3.6"
  ],
  "allow_device_attestation": true,
  "required_attestation_formats": ["tpm"],
  "validate_ek_certificate": true,
  "attestation_policies": [],
  "allowed_tpm_identifiers": []
}'

# Step 6: Read role configuration
echo "=== Step 6: Read Role Configuration ==="
api_request GET "pki/roles/ipsec-vpn"

# Step 7: Configure cluster URL
echo "=== Step 7: Configure Cluster URL ==="
api_request POST "pki/config/cluster" '{
  "path": "http://openbao:8200/v1/pki",
  "aia_path": "http://openbao:8200/v1/pki"
}'

# Step 8: Configure ACME
echo "=== Step 8: Configure ACME ==="
api_request POST "pki/config/acme" '{
  "enabled": true,
  "allowed_issuers": ["*"],
  "allowed_roles": ["*"],
  "eab_policy": "not-required"
}'

# Step 9: Read ACME configuration
echo "=== Step 9: Read ACME Configuration ==="
api_request GET "pki/config/acme"

echo "========================================="
echo "✓ OpenBao initialization completed successfully!"
echo "========================================="
echo
echo "Summary:"
echo "  ✓ PKI backend enabled at: /pki"
echo "  ✓ Root CA generated: OpenBao PoC Root CA"
echo "  ✓ Global attestation: enabled, EK validation enabled"
echo "  ✓ Role created: ipsec-vpn (with device attestation, EK validation)"
echo "  ✓ ACME enabled: all issuers and roles allowed"
echo
echo "Note: TPM devices must be enrolled via the gRPC server before"
echo "      they can request certificates. The server will:"
echo "      1. Configure the TPM's EK root CA certificate"
echo "      2. Add the TPM's permanent ID to the role allowlist"
echo
