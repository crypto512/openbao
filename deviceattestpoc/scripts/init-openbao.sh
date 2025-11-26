#!/bin/bash

set -e

echo "Initializing OpenBao for Device Attestation"
echo "OpenBao: $BAO_ADDR"

max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
  if curl -s -f "$BAO_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo "OpenBao is ready"
    break
  fi
  attempt=$((attempt + 1))
  echo "Waiting for OpenBao... ($attempt/$max_attempts)"
  sleep 1
done

if [ $attempt -eq $max_attempts ]; then
  echo "OpenBao failed to become ready"
  exit 1
fi

api_request() {
    local method=$1
    local path=$2
    local data=$3

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

    if echo "$response" | jq -e '.errors' > /dev/null 2>&1; then
        echo "ERROR: $path: $response"
        return 1
    fi
    echo "OK: $path"
}

check_pki_configured() {
    local mounts=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts")
    if ! echo "$mounts" | jq -e '.["pki-ak/"]' > /dev/null 2>&1; then
        return 1
    fi
    if ! echo "$mounts" | jq -e '.["pki-vpn/"]' > /dev/null 2>&1; then
        return 1
    fi

    local ak_ca=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/issuers?list=true" 2>/dev/null)
    if ! echo "$ak_ca" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
        return 1
    fi

    local vpn_ca=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/issuers?list=true" 2>/dev/null)
    if ! echo "$vpn_ca" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
        return 1
    fi

    local role=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/roles/ipsec-vpn" 2>/dev/null)
    if ! echo "$role" | jq -e '.data.allow_device_attestation == true' > /dev/null 2>&1; then
        return 1
    fi

    local acme=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-vpn/config/acme" 2>/dev/null)
    if ! echo "$acme" | jq -e '.data.enabled == true' > /dev/null 2>&1; then
        return 1
    fi

    return 0
}

if check_pki_configured; then
    echo "PKI already configured - skipping"
    exit 0
fi

echo "Setting up PKI..."

# AK CA
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-ak" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-ak" '{"type": "pki", "config": {"max_lease_ttl": "87600h"}}'
api_request POST "pki-ak/root/generate/internal" '{"common_name": "OpenBao AK CA", "issuer_name": "ak-root-ca", "ttl": "87600h"}'

# LAK device role (Privacy CA issued AK certificate per LAK.md)
# Per TCG spec:
# - Key Usage: digitalSignature only (Critical)
# - Extended Key Usage: tcg-kp-AttestationKey (2.23.133.8.3)
# - Basic Constraints: CA:FALSE (Critical)
# - Subject: empty or pseudonymous
# - SAN: URI with EK hash (urn:ek:sha256:...)
#
# allow_unsigned_csr: required because AK is a restricted signing key
# and cannot sign CSRs - server builds CSR from AK public key
api_request POST "pki-ak/roles/lak-device" '{
  "require_cn": false,
  "allow_any_name": true,
  "enforce_hostnames": false,
  "allowed_uri_sans": ["urn:ek:sha256:*"],
  "max_ttl": "8760h",
  "key_type": "any",
  "key_usage": ["DigitalSignature"],
  "ext_key_usage_oids": ["2.23.133.8.3"],
  "basic_constraints_valid_for_non_ca": true,
  "allow_unsigned_csr": true,
  "no_store": true
}'

# VPN CA
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-vpn" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-vpn" '{"type": "pki", "config": {"max_lease_ttl": "87600h"}}'
api_request POST "sys/mounts/pki-vpn/tune" '{"allowed_response_headers": ["Last-Modified", "Replay-Nonce", "Link", "Location"]}'
api_request POST "pki-vpn/root/generate/internal" '{"common_name": "OpenBao VPN CA", "issuer_name": "vpn-root-ca", "ttl": "87600h"}'

# Trust AK CA
ak_ca_cert=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/cert/ca" | jq -r '.data.certificate')
api_request POST "pki-vpn/config/acme/ak-ca-roots/openbao-ak" "{
  \"name\": \"openbao-ak\",
  \"certificate\": $(echo "$ak_ca_cert" | jq -Rs .)
}"

# Attestation config
api_request POST "pki-vpn/config/attestation" '{
  "enabled": true,
  "validate_ek_certificate": true,
  "allowed_attestation_formats": ["tpm"]
}'

# VPN role
# For device attestation, CN is based on permanent identifier (EK hash)
# so we need allow_any_name to permit non-DNS common names
api_request POST "pki-vpn/roles/ipsec-vpn" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "72h",
  "allow_ip_sans": true,
  "server_flag": false,
  "client_flag": true,
  "key_usage": ["DigitalSignature", "KeyEncipherment", "KeyAgreement"],
  "ext_key_usage": ["ClientAuth"],
  "ext_key_usage_oids": ["1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6"],
  "allow_device_attestation": true,
  "required_attestation_formats": ["tpm"],
  "validate_ek_certificate": true
}'

# Cluster URL and ACME
api_request POST "pki-vpn/config/cluster" '{"path": "http://openbao:8200/v1/pki-vpn", "aia_path": "http://openbao:8200/v1/pki-vpn"}'
api_request POST "pki-vpn/config/acme" '{"enabled": true, "allowed_issuers": ["*"], "allowed_roles": ["*"], "eab_policy": "not-required"}'

# Configure VPN PKI to trust the AK CA for attestation validation
# Get the AK CA root certificate
AK_CA_CERT=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/ca/pem" 2>/dev/null)
if [ -n "$AK_CA_CERT" ] && [ "$AK_CA_CERT" != "null" ]; then
    echo "Configuring VPN PKI to trust AK CA for attestation..."
    # Escape the certificate for JSON
    AK_CA_CERT_ESCAPED=$(echo "$AK_CA_CERT" | jq -Rs .)
    api_request POST "pki-vpn/config/acme/ak-ca-roots/ak-ca" "{\"certificate\": $AK_CA_CERT_ESCAPED}"
fi

echo ""
echo "OpenBao initialized:"
echo "  AK CA: /pki-ak (role: lak-device)"
echo "  VPN CA: /pki-vpn (role: ipsec-vpn)"
echo "  ACME: enabled"
echo "  VPN PKI trusts AK CA for attestation"
