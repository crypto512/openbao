#!/bin/bash
# SWTPM Entrypoint Script with Manufacturer CA Integration
# This script initializes swtpm with proper EK certificates signed by manufacturer CA

set -e

echo "=============================================="
echo "SWTPM - Software TPM 2.0 Initialization"
echo "=============================================="
echo ""

# Create TPM state directory
TPM_STATE_DIR="/tmp/swtpm-state"
mkdir -p "${TPM_STATE_DIR}"

echo "[1/3] Setting up manufacturer CA..."
# Copy manufacturer CA files from mounted volumes to swtpm-localca state directory
# swtpm_localca looks for these specific filenames in its statedir
SWTPM_LOCALCA_DIR="/app/var/lib/swtpm-localca"
mkdir -p "${SWTPM_LOCALCA_DIR}"

if [ -d "/app/ca/intermediate" ] && [ -d "/app/ca/root" ]; then
    echo "Copying manufacturer CA files to swtpm-localca state directory..."

    # Copy intermediate CA private key as signing key
    cp "/app/ca/intermediate/swtpm-intermediate-ca-key.pem" "${SWTPM_LOCALCA_DIR}/signkey.pem"
    chmod 600 "${SWTPM_LOCALCA_DIR}/signkey.pem"

    # Copy intermediate CA certificate as issuer cert
    cp "/app/ca/intermediate/SWTPM TPM EK Intermediate CA.crt" "${SWTPM_LOCALCA_DIR}/issuercert.pem"

    # Copy root CA certificate
    cp "/app/ca/root/SWTPM Manufacturer Root CA.crt" "${SWTPM_LOCALCA_DIR}/swtpm-localca-rootca-cert.pem"

    # Initialize certificate serial number
    echo "02" > "${SWTPM_LOCALCA_DIR}/certserial"

    echo "✓ Manufacturer CA configured"
    echo "  Root CA: SWTPM Manufacturer Root CA"
    echo "  Intermediate CA: SWTPM TPM EK Intermediate CA (signing key)"
    echo "  Serial number initialized"
else
    echo "⚠ Warning: Manufacturer CA files not found in /app/ca"
fi
echo ""

echo "[2/3] Creating swtpm configuration..."
# Create config files and ensure our options file is used
swtpm_setup --tpm2 --create-config-files skip-if-exist,root
echo "✓ Configuration created"
echo ""

# Initialize the TPM with EK certificate (only if not already initialized)
if [ -f "${TPM_STATE_DIR}/tpm2-00.permall" ]; then
    echo "[3/3] TPM state already exists - preserving existing TPM..."
    echo "✓ TPM state preserved (persistent handles and keys intact)"
    echo ""
else
    echo "[3/3] Initializing TPM and generating EK certificate..."
    echo "Using manufacturer CA for EK certificate signing..."
    swtpm_setup --tpm2 \
        --tpm-state "${TPM_STATE_DIR}" \
        --create-ek-cert \
        --create-platform-cert \
        --write-ek-cert-files "${TPM_STATE_DIR}" \
        --vmid "swtpm-device-001"

    if [ -f "${TPM_STATE_DIR}/ek-rsa2048.crt" ]; then
        echo "✓ TPM initialized with EK certificate"
        echo ""
    else
        echo "✗ EK certificate generation failed"
        exit 1
    fi
fi

# Display EK certificate information
echo "EK Certificate Details:"
echo "---------------------------------------------"
openssl x509 -in "${TPM_STATE_DIR}/ek-rsa2048.crt" -noout -subject -issuer
echo "---------------------------------------------"
echo ""

# Launch swtpm socket server
echo "Starting SWTPM server..."
echo "  Command port: 2321 (TCP)"
echo "  Control port: 2322 (TCP)"
echo ""

swtpm socket \
    --tpmstate dir="${TPM_STATE_DIR}" \
    --tpm2 \
    --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
    --server type=tcp,port=2321,bindaddr=0.0.0.0 \
    --flags not-need-init &

SWTPM_PID=$!

# Wait for swtpm to be ready
sleep 2

# Configure TPM2TOOLS_TCTI to use local swtpm
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

# Execute TPM2_Startup
echo "Executing TPM2_Startup..."
if tpm2_startup -c 2>/dev/null; then
    echo "✓ TPM2_Startup successful"
else
    echo "⚠ TPM2_Startup returned non-zero (may be already started)"
fi
echo ""

# Display TPM capabilities
echo "=============================================="
echo "TPM Information"
echo "=============================================="
echo ""
echo "Manufacturer Information:"
tpm2_getcap properties-fixed | grep -E "(TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING)" || true
echo ""
echo "Persistent Handles:"
tpm2_getcap handles-persistent || echo "  (none yet)"
echo ""

echo "=============================================="
echo "SWTPM Ready"
echo "=============================================="
echo ""
echo "Connect using:"
echo "  TPM2TOOLS_TCTI=swtpm:host=tpm1,port=2321"
echo ""
echo "Or from client container:"
echo "  TPM2TOOLS_TCTI=swtpm:host=tpm1,port=2321 tpm2_getrandom 8"
echo ""

# Keep container running
wait $SWTPM_PID
