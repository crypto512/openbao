# Hardware TPM Support

This PoC now supports both **hardware TPM 2.0** devices and **simulated TPM** with automatic fallback.

## Features

### Hardware TPM Mode
When a hardware TPM is detected:
- ✅ Real EK certificates extracted from TPM NVRAM
- ✅ Manufacturer root CA identified (Intel, AMD, Infineon, etc.)
- ✅ Permanent ID extracted from EK certificate
- ✅ Real TPM Quote for hardware-backed attestation signatures
- ✅ AIK certificate uses real AK public key from TPM

### Simulation Mode
When no hardware TPM is available:
- ✅ Simulated EK root CA generation
- ✅ Hash-based permanent ID
- ✅ Software-simulated attestation signatures
- ✅ Full ACME flow for development/testing

## Unified Workflow (Simulation and Hardware TPM)

The same `tpm-acme-client` binary works for both modes with command-line flags.

### Step 1: Build Client Binary

```bash
make build-client
```

This cross-compiles the client for your host OS (macOS, Linux, etc.).

### Step 2: Start Server Infrastructure

```bash
# In terminal 1
make run-server
```

This starts OpenBao and the gRPC server.

### Step 3: Run Client (Choose Mode)

**Simulation Mode** (works on any OS):
```bash
# In terminal 2
./bin/tpm-acme-client -simulate
```

Or use the make target:
```bash
make run-client-sim
```

**Hardware TPM Mode** (Linux only, requires `/dev/tpm`):
```bash
# In terminal 2
sudo ./bin/tpm-acme-client
```

Or use the make target:
```bash
make run-client-hw
```

**Note:** `sudo` is required for TPM device access (`/dev/tpmrm0` or `/dev/tpm0`).

### Command-Line Options

View all available options:
```bash
./bin/tpm-acme-client -help
```

Available flags:
- `-simulate` - Force simulation mode (no hardware TPM)
- `-server <addr>` - Server address (default: localhost:50051)
- `-tpm <device>` - TPM device path (default: /dev/tpmrm0)
- `-cn <name>` - Certificate common name
- `-help` - Show help message

Examples:
```bash
# Simulation mode with custom server
./bin/tpm-acme-client -simulate -server server.example.com:50051

# Hardware TPM with custom device
sudo ./bin/tpm-acme-client -tpm /dev/tpm0

# Custom certificate common name
./bin/tpm-acme-client -simulate -cn device-001.example.com
```

## Alternative: Docker Workflow

For quick testing without building binaries:

```bash
# Full PoC in Docker (simulation mode only)
docker-compose up --build

# View client logs
docker-compose logs client
```

## TPM Detection Logic

The client attempts hardware TPM initialization:
1. Tries to open TPM via go-attestation (`/dev/tpmrm0`, `/dev/tpm0`, Windows TPM)
2. If successful, retrieves EK certificates from NVRAM
3. Extracts manufacturer CA and permanent ID
4. If any step fails, falls back to simulation mode

## Log Output Examples

### Hardware TPM Mode
```
✓ Hardware TPM detected and opened successfully
Found 1 EK(s) from hardware TPM
✓ EK certificate found in TPM NVRAM
✓ Manufacturer root CA extracted: intel
✓ Permanent ID extracted from EK certificate Subject: TPM-12345678
✓ Using hardware TPM for attestation
✓ Hardware TPM Quote successful
```

### Simulation Mode
```
No hardware TPM detected (TPM device not available)
Using simulated attestation mode (not suitable for production)
Simulated Permanent ID: SIM-TPM-6D56397D02096A72
Generating simulated EK root CA for PoC...
Using simulated TPM attestation
```

## Supported TPM Manufacturers

The implementation recognizes:
- Intel
- AMD
- Infineon
- Nuvoton
- STMicroelectronics

Unknown manufacturers will be labeled as `unknown-<organization>`.

## ACME Draft Compliance

This implementation follows [draft-acme-device-attest-07](https://www.ietf.org/archive/id/draft-acme-device-attest-07.txt):

✅ Challenge type: `device-attest-01`
✅ WebAuthn-style attestation object format
✅ Permanent-identifier extension (RFC 4043)
✅ TPM attestation format with proper validation
✅ Key authorization in attToBeSigned

## Production Considerations

See [SECURITY.md](SECURITY.md) for critical production deployment requirements:
- Admin-only TPM enrollment
- Out-of-band EK certificate validation
- Manufacturer root CA trust store configuration
- Physical device verification procedures
