#!/bin/bash
# Clear the existing AK so it can be recreated with correct attributes
# This is useful when AK attributes change and you need to recreate the key
#
# WARNING: If you have an IAK certificate issued for this AK, it will become
# invalid after clearing the AK, since a new AK will have different keys.
# You will need to request a new IAK certificate from OpenBao.

echo "⚠️  WARNING: Clearing the AK will invalidate any existing IAK certificates!"
echo "   A new IAK certificate will need to be requested from OpenBao."
echo ""
echo "Clearing persistent AK at handle 0x81010001..."
sudo tpm2_evictcontrol -C o -c 0x81010001 2>/dev/null && echo "✓ Cleared old AK at 0x81010001" || echo "No AK to clear (this is fine)"

echo ""
echo "Clearing persistent certificate key at handle 0x81010002..."
sudo tpm2_evictcontrol -C o -c 0x81010002 2>/dev/null && echo "✓ Cleared old certificate key at 0x81010002" || echo "No certificate key to clear (this is fine)"

echo ""
echo "You can now run 'make run-client-hw-ak' to create new TPM-protected keys and request a new IAK certificate."
