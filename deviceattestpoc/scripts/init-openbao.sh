#!/bin/bash

set -e

echo "Initializing OpenBao for Device Attestation"
echo "OpenBao: $BAO_ADDR"

KEYS_FILE="/data/openbao-keys.json"

# Wait for OpenBao to be reachable (may be sealed or uninitialized)
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
  health=$(curl -s "$BAO_ADDR/v1/sys/health?standbyok=true&sealedok=true&uninitok=true" 2>/dev/null || echo "")
  if [ -n "$health" ]; then
    echo "OpenBao is reachable"
    break
  fi
  attempt=$((attempt + 1))
  echo "Waiting for OpenBao... ($attempt/$max_attempts)"
  sleep 1
done

if [ $attempt -eq $max_attempts ]; then
  echo "OpenBao failed to become reachable"
  exit 1
fi

# Check initialization status
init_status=$(curl -s "$BAO_ADDR/v1/sys/init")
initialized=$(echo "$init_status" | jq -r '.initialized')

if [ "$initialized" = "false" ]; then
  echo "OpenBao not initialized, initializing..."
  init_response=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}' \
    "$BAO_ADDR/v1/sys/init")

  # Save keys to file
  echo "$init_response" > "$KEYS_FILE"
  chmod 600 "$KEYS_FILE"
  echo "Initialization complete, keys saved to $KEYS_FILE"
fi

# Load keys from file
if [ ! -f "$KEYS_FILE" ]; then
  echo "ERROR: Keys file not found: $KEYS_FILE"
  exit 1
fi

UNSEAL_KEY=$(jq -r '.keys[0]' "$KEYS_FILE")
export BAO_TOKEN=$(jq -r '.root_token' "$KEYS_FILE")

# Check seal status and unseal if needed
seal_status=$(curl -s "$BAO_ADDR/v1/sys/seal-status")
sealed=$(echo "$seal_status" | jq -r '.sealed')

if [ "$sealed" = "true" ]; then
  echo "OpenBao is sealed, unsealing..."
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"key\": \"$UNSEAL_KEY\"}" \
    "$BAO_ADDR/v1/sys/unseal" > /dev/null
  echo "Unsealed"
fi

# Wait for OpenBao to be ready (unsealed)
attempt=0
while [ $attempt -lt $max_attempts ]; do
  if curl -s -f "$BAO_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo "OpenBao is ready"
    break
  fi
  attempt=$((attempt + 1))
  echo "Waiting for OpenBao to be ready... ($attempt/$max_attempts)"
  sleep 1
done

if [ $attempt -eq $max_attempts ]; then
  echo "OpenBao failed to become ready after unseal"
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

    # Check all required PKI mounts
    for mount in "pki-ak/" "pki-grpc/" "pki-agent/" "pki-usage/"; do
        if ! echo "$mounts" | jq -e ".\"$mount\"" > /dev/null 2>&1; then
            return 1
        fi
    done

    # Check CAs are generated
    for pki in "pki-ak" "pki-grpc" "pki-agent" "pki-usage"; do
        local ca=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/$pki/issuers?list=true" 2>/dev/null)
        if ! echo "$ca" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
            return 1
        fi
    done

    # Check agent ACME is enabled
    local acme=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-agent/config/acme" 2>/dev/null)
    if ! echo "$acme" | jq -e '.data.enabled == true' > /dev/null 2>&1; then
        return 1
    fi

    # Check CA exports exist
    if [ ! -f "/data/grpc-ca.pem" ] || [ ! -f "/data/agent-ca.pem" ]; then
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

# Get AK CA for agent attestation validation
AK_CA_CERT=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-ak/ca/pem" 2>/dev/null)
AK_CA_CERT_ESCAPED=$(echo "$AK_CA_CERT" | jq -Rs .)

# gRPC Server TLS CA
echo ""
echo "Setting up gRPC TLS CA..."
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-grpc" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-grpc" '{"type": "pki", "config": {"max_lease_ttl": "87600h"}}'
api_request POST "pki-grpc/root/generate/internal" '{"common_name": "OpenBao gRPC CA", "issuer_name": "grpc-root-ca", "ttl": "87600h"}'

# gRPC server role - for server TLS certificates
api_request POST "pki-grpc/roles/server" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "720h",
  "key_usage": ["DigitalSignature", "KeyEncipherment"],
  "ext_key_usage": ["ServerAuth"]
}'

# Agent CA (ACME with device attestation)
echo ""
echo "Setting up Agent CA..."
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-agent" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-agent" '{"type": "pki", "config": {"max_lease_ttl": "87600h"}}'
api_request POST "sys/mounts/pki-agent/tune" '{"allowed_response_headers": ["Last-Modified", "Replay-Nonce", "Link", "Location"]}'
api_request POST "pki-agent/root/generate/internal" '{"common_name": "OpenBao Agent CA", "issuer_name": "agent-root-ca", "ttl": "87600h"}'

# Trust AK CA for agent attestation validation
api_request POST "pki-agent/config/acme/ak-ca-roots/openbao-ak" "{
  \"name\": \"openbao-ak\",
  \"certificate\": $AK_CA_CERT_ESCAPED
}"

# Agent attestation config
api_request POST "pki-agent/config/attestation" '{
  "enabled": true,
  "validate_ek_certificate": true,
  "allowed_attestation_formats": ["tpm"]
}'

# Agent role - hardware-bound agent identity certificates (1 month validity)
api_request POST "pki-agent/roles/agent" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "720h",
  "key_usage": ["DigitalSignature"],
  "ext_key_usage": ["ClientAuth"],
  "allow_device_attestation": true,
  "required_attestation_formats": ["tpm"],
  "validate_ek_certificate": true
}'

# Agent ACME config
api_request POST "pki-agent/config/cluster" '{"path": "http://openbao:8200/v1/pki-agent", "aia_path": "http://openbao:8200/v1/pki-agent"}'
api_request POST "pki-agent/config/acme" '{"enabled": true, "allowed_issuers": ["*"], "allowed_roles": ["*"], "eab_policy": "not-required"}'

# Usage CA (sign-verbatim via mTLS, no ACME)
echo ""
echo "Setting up Usage CA..."
curl -s -X DELETE -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts/pki-usage" > /dev/null 2>&1 || true
api_request POST "sys/mounts/pki-usage" '{"type": "pki", "config": {"max_lease_ttl": "87600h"}}'
api_request POST "pki-usage/root/generate/internal" '{"common_name": "OpenBao Usage CA", "issuer_name": "usage-root-ca", "ttl": "87600h"}'

# Usage roles - issued via sign-verbatim with mTLS authentication (1 day validity)
api_request POST "pki-usage/roles/vpn" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "24h",
  "key_usage": ["DigitalSignature", "KeyEncipherment", "KeyAgreement"],
  "ext_key_usage": ["ClientAuth"],
  "ext_key_usage_oids": ["1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6"]
}'

api_request POST "pki-usage/roles/wifi" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "24h",
  "key_usage": ["DigitalSignature"],
  "ext_key_usage": ["ClientAuth"]
}'

api_request POST "pki-usage/roles/tls" '{
  "allow_any_name": true,
  "enforce_hostnames": false,
  "max_ttl": "24h",
  "key_usage": ["DigitalSignature"],
  "ext_key_usage": ["ClientAuth"]
}'

# Export CA certificates for client/server mounting
echo ""
echo "Exporting CA certificates..."

# gRPC CA - for client TLS verification
GRPC_CA_CERT=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-grpc/ca/pem" 2>/dev/null)
echo "$GRPC_CA_CERT" > /data/grpc-ca.pem
chmod 644 /data/grpc-ca.pem
echo "OK: Exported gRPC CA to /data/grpc-ca.pem"

# Agent CA - for server mTLS validation
AGENT_CA_CERT=$(curl -s -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/pki-agent/ca/pem" 2>/dev/null)
echo "$AGENT_CA_CERT" > /data/agent-ca.pem
chmod 644 /data/agent-ca.pem
echo "OK: Exported Agent CA to /data/agent-ca.pem"

echo ""
echo "OpenBao initialized:"
echo "  AK CA: /pki-ak (role: lak-device)"
echo "  gRPC CA: /pki-grpc (role: server)"
echo "  Agent CA: /pki-agent (role: agent, ACME enabled)"
echo "  Usage CA: /pki-usage (roles: vpn, wifi, tls)"
echo "  CA exports: /data/grpc-ca.pem, /data/agent-ca.pem"
