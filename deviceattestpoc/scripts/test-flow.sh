#!/bin/bash
# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# End-to-end test script for ACME device attestation PoC

set -e

echo "========================================="
echo "ACME Device Attestation E2E Test"
echo "========================================="
echo

# Check if Docker Compose environment is running
if ! docker-compose ps | grep -q "Up"; then
    echo "Starting Docker Compose environment..."
    docker-compose up -d
    sleep 10
fi

echo "=== Test 1: Verify OpenBao is running ==="
if curl -s -f http://localhost:8200/v1/sys/health > /dev/null; then
    echo "✓ OpenBao is healthy"
else
    echo "✗ OpenBao is not responding"
    exit 1
fi
echo

echo "=== Test 2: Verify PKI backend is enabled ==="
response=$(curl -s -H "X-Vault-Token: root" http://localhost:8200/v1/sys/mounts)
if echo "$response" | jq -e '.["pki/"]' > /dev/null 2>&1; then
    echo "✓ PKI backend is mounted"
else
    echo "✗ PKI backend not found"
    exit 1
fi
echo

echo "=== Test 3: Verify attestation configuration ==="
response=$(curl -s -H "X-Vault-Token: root" http://localhost:8200/v1/pki/config/attestation)
if echo "$response" | jq -e '.data.enabled == true' > /dev/null 2>&1; then
    echo "✓ Attestation is enabled"
    echo "  Allowed formats: $(echo "$response" | jq -r '.data.allowed_attestation_formats | join(", ")')"
else
    echo "✗ Attestation not properly configured"
    exit 1
fi
echo

echo "=== Test 4: Verify EK root certificate ==="
response=$(curl -s -X LIST -H "X-Vault-Token: root" http://localhost:8200/v1/pki/config/acme/ek-roots)
if echo "$response" | jq -e '.data.keys | length > 0' > /dev/null 2>&1; then
    echo "✓ EK root certificates registered"
    echo "  Roots: $(echo "$response" | jq -r '.data.keys | join(", ")')"
else
    echo "✗ No EK root certificates found"
    exit 1
fi
echo

echo "=== Test 5: Verify IPsec VPN role ==="
response=$(curl -s -H "X-Vault-Token: root" http://localhost:8200/v1/pki/roles/ipsec-vpn)
if echo "$response" | jq -e '.data.allow_device_attestation == true' > /dev/null 2>&1; then
    echo "✓ IPsec VPN role configured with device attestation"
    echo "  Required formats: $(echo "$response" | jq -r '.data.required_attestation_formats | join(", ")')"
else
    echo "✗ Role not properly configured"
    exit 1
fi
echo

echo "=== Test 6: Verify ACME is enabled ==="
response=$(curl -s http://localhost:8200/v1/pki/acme/directory)
if echo "$response" | jq -e '.newAccount' > /dev/null 2>&1; then
    echo "✓ ACME directory is accessible"
    echo "  New Account: $(echo "$response" | jq -r '.newAccount')"
    echo "  New Order: $(echo "$response" | jq -r '.newOrder')"
else
    echo "✗ ACME not properly configured"
    exit 1
fi
echo

echo "=== Test 7: Verify client is ready ==="
if docker-compose ps client | grep -q "Up\|Exit 0"; then
    echo "✓ Client container is available"
else
    echo "✗ Client container not found"
    exit 1
fi
echo

echo "=== Test 8: Verify gRPC server is running ==="
if docker-compose ps server | grep -q "Up"; then
    echo "✓ gRPC server is running"
else
    echo "✗ gRPC server is not running"
    exit 1
fi
echo

echo "=== Test 9: Run client certificate request ==="
echo "Executing client..."
docker-compose run --rm client /client > /tmp/client-output.txt 2>&1

if grep -q "ACME Device Attestation Flow Completed" /tmp/client-output.txt; then
    echo "✓ Client completed successfully"
    echo
    echo "Client output:"
    cat /tmp/client-output.txt
else
    echo "✗ Client failed"
    echo
    echo "Client output:"
    cat /tmp/client-output.txt
    exit 1
fi
echo

echo "========================================="
echo "✓ All E2E tests passed!"
echo "========================================="
echo
echo "Summary:"
echo "  ✓ OpenBao running with PKI and ACME"
echo "  ✓ Attestation configuration valid"
echo "  ✓ IPsec VPN role configured"
echo "  ✓ gRPC server running"
echo "  ✓ Client successfully completed attestation flow"
echo "  ✓ Certificate issued and bound to TPM device"
echo
echo "The ACME device attestation PoC is fully operational!"
echo
