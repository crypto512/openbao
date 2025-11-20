#!/bin/bash

# Initialize OpenBao with dual PKI backend configuration:
# - /pki-ak: AK CA for issuing AIK certificates
# - /pki-vpn: VPN CA for issuing end-entity certificates via ACME

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

# Function to check if PKI mounts are already configured
check_pki_configured() {
    echo "=== Checking if PKI mounts are already configured ==="

    # Check if both PKI mounts exist
    local mounts=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts")
    if ! echo "$mounts" | jq -e '.["pki-ak/"]' > /dev/null 2>&1; then
        echo "PKI-AK mount not found"
        return 1
    fi
    if ! echo "$mounts" | jq -e '.["pki-vpn/"]' > /dev/null 2>&1; then
        echo "PKI-VPN mount not found"
        return 1
    fi
    echo "✓ Both PKI mounts exist"

    # Check if AK CA exists
    local ak_ca=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/issuers?list=true" 2>/dev/null)
    if ! echo "$ak_ca" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
        echo "AK CA not found"
        return 1
    fi
    echo "✓ AK CA exists"

    # Check if VPN CA exists
    local vpn_ca=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/issuers?list=true" 2>/dev/null)
    if ! echo "$vpn_ca" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
        echo "VPN CA not found"
        return 1
    fi
    echo "✓ VPN CA exists"

    # Check if ipsec-vpn role exists with attestation enabled
    local role=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/roles/ipsec-vpn" 2>/dev/null)
    if ! echo "$role" | jq -e '.data.allow_device_attestation == true' > /dev/null 2>&1; then
        echo "Role ipsec-vpn not found or attestation not enabled"
        return 1
    fi
    echo "✓ Role ipsec-vpn configured with attestation"

    # Check if ACME is enabled on VPN CA
    local acme=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/config/acme" 2>/dev/null)
    if ! echo "$acme" | jq -e '.data.enabled == true' > /dev/null 2>&1; then
        echo "ACME not enabled"
        return 1
    fi
    echo "✓ ACME enabled"

    echo "=== PKI is fully configured, skipping initialization ==="
    return 0
}

# Check if PKI is already configured (idempotency check)
if check_pki_configured; then
    echo ""
    echo "========================================="
    echo "✓ PKI already configured - skipping initialization"
    echo "========================================="
    echo ""
    echo "This preserves existing ACME accounts and configuration."
    echo "To reconfigure from scratch, run: make clean"
    echo ""
    exit 0
fi

echo ""
echo "PKI not configured or incomplete - performing full initialization"
echo ""

# ================================================
# PART 1: Setup AK CA (for AIK certificates)
# ================================================

echo "========================================"
echo "PART 1: Setup AK CA (/pki-ak)"
echo "========================================"
echo

# Step 1: Enable AK CA PKI backend
echo "=== Step 1: Enable AK CA PKI Backend ==="
# Unmount first if exists
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-ak" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-ak" '{
  "type": "pki",
  "config": {
    "max_lease_ttl": "87600h"
  }
}'

# Step 2: Generate AK CA root
echo "=== Step 2: Generate AK CA Root Certificate ==="
api_request POST "pki-ak/root/generate/internal" '{
  "common_name": "OpenBao AK CA",
  "issuer_name": "ak-root-ca",
  "ttl": "87600h",
  "key_type": "rsa",
  "key_bits": 2048
}'

# Step 3: Create AIK certificate role
echo "=== Step 3: Create AIK Certificate Role ==="
api_request POST "pki-ak/roles/aik-device" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "allowed_serial_numbers": ["*"],
  "max_ttl": "8760h",
  "key_type": "any",
  "key_bits": 2048,
  "use_csr_common_name": true,
  "use_csr_sans": true,
  "allow_ip_sans": false,
  "server_flag": false,
  "client_flag": false,
  "code_signing_flag": false,
  "email_protection_flag": false,
  "key_usage": [
    "DigitalSignature"
  ],
  "ext_key_usage_oids": ["2.23.133.8.3"]
}'

# ================================================
# PART 2: Setup VPN CA (for ACME with attestation)
# ================================================

echo ""
echo "========================================"
echo "PART 2: Setup VPN CA (/pki-vpn)"
echo "========================================"
echo

# Step 4: Enable VPN CA PKI backend
echo "=== Step 4: Enable VPN CA PKI Backend ==="
# Unmount first if exists
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-vpn" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-vpn" '{
  "type": "pki",
  "config": {
    "max_lease_ttl": "87600h"
  }
}'

# Step 4b: Configure allowed response headers for ACME
echo "=== Step 4b: Configure Allowed Response Headers for ACME ==="
api_request POST "sys/mounts/pki-vpn/tune" '{
  "allowed_response_headers": ["Last-Modified", "Replay-Nonce", "Link", "Location"]
}'

# Step 5: Generate VPN CA root
echo "=== Step 5: Generate VPN CA Root Certificate ==="
api_request POST "pki-vpn/root/generate/internal" '{
  "common_name": "OpenBao VPN CA",
  "issuer_name": "vpn-root-ca",
  "ttl": "87600h",
  "key_type": "rsa",
  "key_bits": 2048
}'

# Step 6: Export AK CA root certificate and configure VPN CA to trust it
echo "=== Step 6: Configure VPN CA to Trust AK CA ==="
echo "Exporting AK CA root certificate..."
ak_ca_cert_json=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/cert/ca")
ak_ca_cert=$(echo "$ak_ca_cert_json" | jq -r '.data.certificate')
echo "AK CA Root Certificate:"
echo "$ak_ca_cert" | head -3
echo "..."

# Add AK CA root to VPN CA trusted roots
api_request POST "pki-vpn/config/acme/ak-ca-roots/openbao-ak" "{
  \"name\": \"openbao-ak\",
  \"certificate\": $(echo "$ak_ca_cert" | jq -Rs .)
}"

# Step 7: Configure global attestation settings
echo "=== Step 7: Configure Global Attestation Settings ==="
api_request POST "pki-vpn/config/attestation" '{
  "enabled": true,
  "validate_ek_certificate": true,
  "default_attestation_policies": [],
  "allowed_attestation_formats": ["tpm"]
}'

# Step 8: Read attestation configuration
echo "=== Step 8: Read Attestation Configuration ==="
api_request GET "pki-vpn/config/attestation"

# Step 9: Create role for IPsec VPN with device attestation
echo "=== Step 9: Create IPsec VPN Role with Device Attestation ==="
api_request POST "pki-vpn/roles/ipsec-vpn" '{
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
  "attestation_policies": []
}'

# Step 10: Read role configuration
echo "=== Step 10: Read Role Configuration ==="
api_request GET "pki-vpn/roles/ipsec-vpn"

# Step 11: Configure cluster URL
echo "=== Step 11: Configure Cluster URL ==="
api_request POST "pki-vpn/config/cluster" '{
  "path": "http://openbao:8200/v1/pki-vpn",
  "aia_path": "http://openbao:8200/v1/pki-vpn"
}'

# Step 12: Configure ACME
echo "=== Step 12: Configure ACME ==="
api_request POST "pki-vpn/config/acme" '{
  "enabled": true,
  "allowed_issuers": ["*"],
  "allowed_roles": ["*"],
  "eab_policy": "not-required"
}'

# Step 13: Read ACME configuration
echo "=== Step 13: Read ACME Configuration ==="
api_request GET "pki-vpn/config/acme"

echo "========================================="
echo "✓ OpenBao initialization completed successfully!"
echo "========================================="
echo
echo "Summary:"
echo "  ✓ AK CA enabled at: /pki-ak"
echo "  ✓ AK CA root generated: OpenBao AK CA"
echo "  ✓ AIK role created: aik-device"
echo ""
echo "  ✓ VPN CA enabled at: /pki-vpn"
echo "  ✓ VPN CA root generated: OpenBao VPN CA"
echo "  ✓ VPN CA trusts AK CA: openbao-ak"
echo "  ✓ Global attestation: enabled, AIK validation enabled"
echo "  ✓ Role created: ipsec-vpn (with device attestation)"
echo "  ✓ ACME enabled: all issuers and roles allowed"
echo
echo "Architecture:"
echo "  Phase 1: Devices request AIK certs from /pki-ak (via server module)"
echo "  Phase 2: Devices use AIK certs for ACME enrollment on /pki-vpn"
echo "  Trust chain: VPN Cert ← /pki-vpn ← (trusts) /pki-ak ← AIK ← TPM"
echo
echo "Note: Device authorization (allow/blocklist) is handled by the server module"
echo "      during AIK certificate issuance, not by OpenBao PKI backend."
echo
