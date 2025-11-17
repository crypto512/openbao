#!/bin/bash
# Debug script to check AK public key consistency
# This helps diagnose signature verification failures in AK mode

echo "=== AK Public Key Diagnostic ==="
echo ""

AK_HANDLE=0x81010001

# Check if AK exists
if ! sudo tpm2_readpublic -c $AK_HANDLE > /dev/null 2>&1; then
    echo "❌ No AK found at handle $AK_HANDLE"
    echo "   Run 'make run-client-hw-ak' to create one"
    exit 1
fi

echo "✓ AK exists at handle $AK_HANDLE"
echo ""

# Read AK public key and save to file
echo "Reading AK public key from TPM..."
sudo tpm2_readpublic -c $AK_HANDLE -o /tmp/ak_pub.pem -f pem 2>/dev/null

if [ -f /tmp/ak_pub.pem ]; then
    echo "✓ AK public key exported to /tmp/ak_pub.pem"
    echo ""
    echo "Public key details:"
    openssl rsa -pubin -in /tmp/ak_pub.pem -text -noout 2>/dev/null | head -20
else
    echo "❌ Failed to export AK public key"
fi

echo ""
echo "To compare with IAK certificate, check the modulus (N) values."
echo "They should match if the IAK cert was issued for this AK."
