#!/bin/sh

# Client Entrypoint - Sets up socat proxy for swtpm TCP connection

set -e

echo "========================================"
echo "ACME Client (Rust) - TPM Setup"
echo "========================================"
echo ""

# Check if we should use swtpm over TCP
if [ -n "$TPM_SWTPM_HOST" ] && [ -n "$TPM_SWTPM_PORT" ]; then
    echo "Setting up socat proxy to swtpm at $TPM_SWTPM_HOST:$TPM_SWTPM_PORT..."

    # Create directory for TPM device
    mkdir -p /dev

    # Create a Unix socket that forwards to swtpm TCP port
    # This allows tss-esapi to use it as a device file
    socat UNIX-LISTEN:/tmp/swtpm-sock,fork,mode=666 TCP:$TPM_SWTPM_HOST:$TPM_SWTPM_PORT &
    SOCAT_PID=$!

    # Wait for socket to be ready
    for i in 1 2 3 4 5; do
        if [ -S /tmp/swtpm-sock ]; then
            echo "✓ socat proxy ready at /tmp/swtpm-sock"
            break
        fi
        sleep 1
    done

    # Create symlink so tss-esapi auto-detection finds the TPM
    ln -sf /tmp/swtpm-sock /dev/tpmrm0
    echo "✓ Created /dev/tpmrm0 symlink to Unix socket"

    # Export environment variable for tpm2-tools commands if needed
    export TPM2TOOLS_TCTI="swtpm:host=$TPM_SWTPM_HOST,port=$TPM_SWTPM_PORT"

    # Clean up socat on exit
    trap "kill $SOCAT_PID 2>/dev/null || true" EXIT
fi

echo ""
echo "Starting client..."
echo ""

# Execute the client
exec "$@"
