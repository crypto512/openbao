# ACME Device Attestation with TPM 2.0 - Proof of Concept

Real-world demonstration of ACME device attestation using TPM 2.0 hardware-backed cryptography for secure certificate issuance.

## Overview

This PoC demonstrates hardware-backed device attestation where certificate private keys are generated **inside the TPM** and proven non-exportable through cryptographic attestation. This ensures that private keys never exist in software memory and cannot be extracted from the device.

### Key Features

- **TPM-Protected Certificate Keys**: Private keys generated inside TPM using `CreatePrimary`, never exported
- **Cryptographic Proof**: TPM2_Certify proves keys are non-exportable with FixedTPM and SensitiveDataOrigin attributes
- **Two Attestation Modes**:
  - IAK Mode: Uses manufacturer-provisioned IAK certificates from TPM NVRAM
  - AK Mode: Creates persistent Attestation Key, receives IAK certificate from OpenBao
- **ACME Integration**: Full ACME flow with `device-attest-01` challenge type
- **SWTPM Support**: Software TPM 2.0 emulator with manufacturer CA integration for testing

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         TPM Hardware                               │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────┐│
│  │ EK (RSA)     │  │ IAK/AK (RSA) │  │ Certificate Key (RSA)      ││
│  │ Decrypt Only │  │ Sign         │  │ Sign (TPM-Protected)       ││
│  │              │  │ Attestation  │  │ Non-Exportable             ││
│  └──────────────┘  └──────────────┘  └────────────────────────────┘│
│                                                                    │
│  Persistent Handles:                                               │
│  • 0x81010001: Endorsement Key (EK)                                │
│  • 0x81010002: Attestation Key (AK, AK mode only)                  │
│  • 0x81010003: Certificate Key (both modes)                        │
│  • 0x81010012: IAK Handle (IAK mode, vendor-specific)              │
└────────────────────────────────────────────────────────────────────┘
```

### Component Flow

```
┌─────────────┐       gRPC         ┌─────────────┐      ACME       ┌──────────────┐
│   Client    │◄──────────────────►│   Server    │◄───────────────►│   OpenBao    │
│             │  Enrollment        │             │   Orders/       │              │
│ - TPM Init  │  Cert Request      │ - gRPC API  │   Challenges    │ - PKI        │
│ - CSR (TPM) │  Attestation       │ - ACME      │   Validation    │ - ACME       │
│ - Certify   │                    │   Proxy     │                 │ - TPM Verify │
└─────────────┘                    └─────────────┘                 └──────────────┘
```

## TPM-Protected Certificate Keys

### What Makes This Secure?

Traditional certificate issuance generates private keys in software memory, which can be:
- Extracted and copied
- Stolen by malware
- Exported to other devices

This PoC generates certificate keys **inside the TPM** with these guarantees:

| Property | Meaning | Proof Method |
|----------|---------|--------------|
| **FixedTPM** | Key bound to this specific TPM, cannot be exported | TPM2_Certify attestation |
| **FixedParent** | Key cannot be moved to different parent | TPM2_Certify attestation |
| **SensitiveDataOrigin** | Key was generated inside TPM (not imported) | TPM2_Certify attestation |
| **Persistent Storage** | Keys survive reboot at handle 0x81010002 | TPM persistent memory |
| **CSR Signing** | All signing operations performed inside TPM | TPM2_Sign operations |

### TPM2_Certify Operation

The PoC uses **TPM2_Certify** (not TPM2_Quote):

- **TPM2_Quote**: Attests to PCR values (boot measurements)
- **TPM2_Certify**: Attests to key attributes (our use case)

TPM2_Certify generates a `TPM_ST_ATTEST_CERTIFY` (0x8017) attestation that:
1. Cryptographically proves the certificate key's attributes
2. Binds the certificate key to the IAK/AK
3. Includes the key authorization hash from ACME challenge
4. Follows WebAuthn TPM attestation format

## Attestation Modes

### IAK Mode (Manufacturer-Provisioned)

**Use When**: TPM has manufacturer-provisioned IAK certificate in NVRAM

```
make run-client-hw-iak    # Requires --attest-mode=iak
```

**Process**:
1. Read IAK certificate from TPM NVRAM (0x01C00012)
2. Load IAK key handle (vendor-specific, e.g., 0x81010012)
3. Create TPM-protected certificate key at 0x81010002
4. Use TPM2_Certify with IAK to prove key attributes
5. IAK certificate chains to manufacturer root CA

**Advantages**:
- ✅ IAK provisioned at factory in secure environment
- ✅ Certificate chains to well-known manufacturer CA
- ✅ No additional provisioning step needed

**Requirements**:
- ❌ Not all TPMs have manufacturer IAK
- ❌ Certificate validity set by manufacturer (years)

### AK Mode (Locally Created)

**Use When**: No manufacturer IAK available (most common)

```
make run-client-hw-ak     # Default, or --attest-mode=ak
```

**Process**:
1. Create persistent AK at handle 0x81010002 using `CreatePrimary`
2. Create TPM-protected certificate key at 0x81010003
3. Send AK public key during enrollment
4. Receive IAK certificate from OpenBao (365-day validity)
5. Use TPM2_Certify with AK to prove key attributes
6. IAK certificate chains to OpenBao PKI root

**Advantages**:
- ✅ Works with any TPM that has EK certificate
- ✅ IAK certificate validity controlled by OpenBao
- ✅ AK persisted at handle 0x81010002 (survives reboot)
- ✅ Automatic mode if manufacturer IAK not present

**Requirements**:
- ❌ Requires EK enrollment with OpenBao first
- ❌ Adds OpenBao PKI root to trust anchors

### SWTPM Mode (Software TPM)

**Use When**: Testing without physical hardware TPM

```bash
docker compose up --build    # Includes swtpm container
```

**How It Works**:
- SWTPM is a software TPM 2.0 emulator (libtpms + swtpm)
- **Acts exactly like a real hardware TPM** with full TPM 2.0 command support
- Includes manufacturer CA integration:
  - Root CA: `SWTPM Manufacturer Root CA`
  - Intermediate CA: `SWTPM TPM EK Intermediate CA`
  - EK certificate signed by intermediate CA (just like real TPMs)
- Client connects via TCP using socat proxy that creates `/dev/tpmrm0` symlink
- Persistent storage in `/tmp/swtpm-state` (survives container restarts)

**Architecture**:
```
┌─────────────┐    socat     ┌─────────────┐
│   Client    │   TCP proxy  │   SWTPM     │
│ Container   │◄────────────►│  Container  │
│             │   port 2321  │             │
│/dev/tpmrm0  │              │ TPM 2.0     │
│  symlink    │              │ Emulator    │
└─────────────┘              └─────────────┘
                                    ▲
                                    │
                                    │ Manufacturer CA
                             ┌──────┴──────┐
                             │ ca/swtpm-   │
                             │ manufacturer│
                             └─────────────┘
```

**Manufacturer CA Files** (mounted in swtpm container):
- `ca/swtpm-manufacturer/RootCA/SWTPM Manufacturer Root CA.crt`
- `ca/swtpm-manufacturer/IntermediateCA/SWTPM TPM EK Intermediate CA.crt`
- Private keys (unencrypted) used by swtpm_localca to sign EK certificates

**Advantages**:
- ✅ Full TPM 2.0 command support (not simulation)
- ✅ Manufacturer CA hierarchy like real hardware TPMs
- ✅ EK certificate chains to known manufacturer root
- ✅ Persistent handles survive container restarts
- ✅ Works in Docker/containers
- ✅ Perfect for testing, CI/CD, and development

**Limitations**:
- ⚠️ No hardware security - keys in container memory
- ⚠️ Not physically bound to device
- ⚠️ For testing and development only

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- For hardware TPM: Linux with `/dev/tpmrm0` or `/dev/tpm0`

### Step 1: Generate Manufacturer CAs

```bash
cd deviceattestpoc

# Generate SWTPM manufacturer CA (for software TPM)
cd ca/swtpm-manufacturer
./generate-ca.sh
cd ../..

# Optional: Generate STMicro CA (for hardware TPM testing)
cd ca/stmicro
./generate-ca.sh
cd ../..
```

### Step 2: Build Containers (One-Time Setup)

```bash
make build
```

All containers use Docker layer caching for fast incremental builds. This optimization reduces build times significantly:
- OpenBao: 1GB+ build context reduced to ~50MB via `.dockerignore`
- Client/Server: Proto generation, dependencies, and source code in separate cached layers

### Step 3: Run End-to-End Test

**Automated Test with SWTPM**:
```bash
make run-test-swtpm-ak
```

This runs the complete flow and displays the result.

### Step 4: Interactive Testing

**Start Server Infrastructure**:
```bash
make run-server
# Starts OpenBao + gRPC server + SWTPM (Ctrl+C to stop)
```

**Run Clients** (in separate terminal):

**SWTPM - IAK Mode**:
```bash
make run-client-swtpm-iak
```

**SWTPM - AK Mode** (recommended):
```bash
make run-client-swtpm-ak
```

**Hardware TPM - IAK Mode** (requires manufacturer IAK):
```bash
make run-client-hw-iak
```

**Hardware TPM - AK Mode** (works with any TPM):
```bash
make run-client-hw-ak
```

### Expected Output

```
═══════════════════════════════════════════════
Initializing TPM...
═══════════════════════════════════════════════
✓ TPM detected and opened successfully
✓ Persistent AK created successfully (handle: 0x81010002)
✓ Certificate key persisted (handle: 0x81010003)
  Attributes: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Sign
  Security: Private key NEVER leaves TPM, cannot be exported

═══════════════════════════════════════════════
Generating Certificate Signing Request...
═══════════════════════════════════════════════
✓ CSR signed by TPM (private key never exported)

═══════════════════════════════════════════════
Connecting to gRPC server...
═══════════════════════════════════════════════
✓ Connected to server: localhost:50051

═══════════════════════════════════════════════
Enrolling TPM with OpenBao...
═══════════════════════════════════════════════
✓ TPM enrolled successfully
  Permanent ID: TPM-1234567890ABCDEF
  EK Root CA: intel
✓ IAK certificate provisioned (AK mode)

═══════════════════════════════════════════════
Requesting certificate...
═══════════════════════════════════════════════
✓ Certificate request initiated
  Challenge type: device-attest-01

═══════════════════════════════════════════════
Generating TPM attestation...
═══════════════════════════════════════════════
✓ TPM2_Certify successful (WebAuthn TPM attestation format)
✓ Attestation proves: FixedTPM, SensitiveDataOrigin, non-exportable

═══════════════════════════════════════════════
Submitting attestation...
═══════════════════════════════════════════════
✓ Attestation validated by OpenBao

═══════════════════════════════════════════════
Retrieving certificate...
═══════════════════════════════════════════════
✓ Certificate issued successfully!
  Saved to: ./vpn-client.pem
```

## Detailed Flow

### Phase 1: TPM Initialization

1. **Client opens TPM** (hardware or SWTPM)
   - Hardware: `/dev/tpmrm0` or `/dev/tpm0`
   - SWTPM: `/dev/tpmrm0` symlink via socat TCP proxy

2. **Read/Create IAK**:
   - **IAK Mode**: Read IAK certificate from NVRAM 0x01C00012
   - **AK Mode**: Create persistent AK at handle 0x81010002

3. **Create TPM-Protected Certificate Key**:
   - Generate key INSIDE TPM using `CreatePrimary`
   - Parent: Owner hierarchy
   - Attributes: FixedTPM, FixedParent, SensitiveDataOrigin, Sign
   - Persist at handle 0x81010003
   - Private key **never leaves TPM**

### Phase 2: TPM Enrollment

4. **Client sends enrollment request** to server via gRPC:
   - Permanent ID (from EK certificate)
   - EK root CA certificate
   - AK public key (AK mode only)

5. **Server configures OpenBao**:
   - Add EK root CA to trusted roots
   - Store permanent ID enrollment
   - Issue IAK certificate for AK public key (AK mode only)

### Phase 3: Certificate Request

6. **Generate CSR**:
   - Create CSR for `vpn-client-001.example.com`
   - Sign CSR using TPM2_Sign with certificate key (0x81010003)
   - Private key never exported from TPM

7. **Client sends request** to server:
   - CSR (PEM format)
   - Permanent ID

8. **Server creates ACME order** on OpenBao:
   - Identifier type: `permanent-identifier`
   - Identifier value: TPM permanent ID
   - Receives `device-attest-01` challenge

### Phase 4: Attestation

9. **Client generates attestation**:
   - Compute key authorization: `SHA256(token || '.' || thumbprint)`
   - Execute **TPM2_Certify**:
     - Object to certify: Certificate key (0x81010003)
     - Signing key: IAK or AK
     - Qualifying data: Key authorization hash
   - Generates attestation containing:
     - `certInfo`: TPMS_ATTEST structure (0x8017 CERTIFY)
     - `pubArea`: Certificate key public structure
     - `sig`: Signature by IAK/AK
     - `x5c`: IAK certificate chain

10. **Client submits attestation** to server

11. **Server forwards** to OpenBao ACME challenge URL

### Phase 5: Validation

12. **OpenBao validates attestation**:
    - ✅ Decode CBOR attestation object
    - ✅ Parse WebAuthn TPM format
    - ✅ Verify IAK certificate chains to:
      - Manufacturer root CA (IAK mode), OR
      - OpenBao PKI root (AK mode)
    - ✅ Verify signature over `certInfo` using IAK/AK public key
    - ✅ Verify `certInfo.extraData` matches key authorization hash
    - ✅ Verify `certInfo.name` matches SHA-256 hash of `pubArea`
    - ✅ Verify key attributes: FixedTPM, SensitiveDataOrigin
    - ✅ Confirm key is TPM-protected and non-exportable
    - ✅ Mark challenge as `valid`

### Phase 6: Certificate Issuance

13. **Finalize order** with CSR

14. **OpenBao issues certificate**:
    - Signed by OpenBao PKI CA
    - Valid for 90 days (ACME standard)
    - SAN includes permanent identifier extension

15. **Client downloads certificate**:
    - Saved to `./vpn-client.pem`
    - Ready for use with IPsec, VPN, etc.

## Testing & Verification

### Verify Persistent Handles

```bash
# Check TPM persistent handles (hardware only)
sudo tpm2_getcap handles-persistent
# Should show:
#   0x81010001 (AK, AK mode only)
#   0x81010002 (certificate key, both modes)
```

### Verify Certificate

```bash
# View issued certificate
openssl x509 -in ./vpn-client.pem -text -noout

# Check SAN with permanent identifier
openssl x509 -in ./vpn-client.pem -text | grep -A2 "Subject Alternative Name"
```

### Clear TPM Keys and State

```bash
# Clean all containers and volumes (fresh start)
make clean

# For hardware TPM, manually clear persistent handles if needed:
sudo tpm2_evictcontrol -C o -c 0x81010002  # Clear AK
sudo tpm2_evictcontrol -C o -c 0x81010003  # Clear certificate key
```

## Configuration

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build all containers with layer caching |
| `make clean` | Clean containers and volumes (fresh start) |
| `make run-server` | Start server infrastructure (OpenBao + gRPC + SWTPM) |
| `make run-client-swtpm-iak` | Run client with SWTPM in IAK mode |
| `make run-client-swtpm-ak` | Run client with SWTPM in AK mode (recommended) |
| `make run-client-hw-iak` | Run client with hardware TPM in IAK mode |
| `make run-client-hw-ak` | Run client with hardware TPM in AK mode |
| `make run-test-swtpm-ak` | Automated end-to-end test with SWTPM |

### Architecture Benefits

**Docker Layer Caching** - All containers optimized for fast incremental builds:
- Dependencies cached separately from source code
- Proto generation cached separately
- OpenBao build context reduced from 1GB+ to ~50MB

**Persistent State** - Data survives container restarts:
- **SWTPM**: TPM state persisted in `swtpm-state` volume (AK/keys survive restarts)
- **OpenBao**: PKI configuration and ACME accounts preserved in `openbao-data` volume
- **Multiple enrollments**: Run clients multiple times without reconfiguration

**Hardware TPM Support** - Device passthrough in Docker:
- Uses Docker `devices` and `privileged` mode
- Passes through `/dev/tpm0` and `/dev/tpmrm0`
- Isolated via Docker Compose profiles

### Environment Variables

**Server**:
- `BAO_ADDR`: OpenBao address (default: `http://localhost:8200`)
- `BAO_TOKEN`: OpenBao root token (default: `root`)
- `GRPC_PORT`: gRPC server port (default: `50051`)

**Client**:
- `SERVER_ADDR`: gRPC server address (default: `localhost:50051`)
- `CERT_COMMON_NAME`: Certificate CN
- `TPM_DEVICE`: TPM device path

## Security Considerations

### Hardware TPM Security Properties

When using hardware TPM in IAK or AK mode:

- ✅ **Private key generated inside TPM** - Never exists in software memory
- ✅ **FixedTPM attribute** - Key bound to specific TPM, cannot be exported
- ✅ **FixedParent attribute** - Key cannot be moved to different parent
- ✅ **SensitiveDataOrigin attribute** - Key generated inside TPM (not imported)
- ✅ **TPM2_Certify proof** - IAK/AK cryptographically attests to all key attributes
- ✅ **Persistent storage** - Keys survive reboot at known handles
- ✅ **WebAuthn format** - Industry-standard TPM attestation format
- ✅ **Server validation** - OpenBao validates pubArea hash matches certInfo NAME

### Trust Model

```
Trust Anchor 1: Manufacturer Root CAs
    ├── EK Certificate (validates device authenticity)
    └── IAK Certificate (validates attestation key) [IAK mode only]

Trust Anchor 2: OpenBao PKI Root CA
    └── IAK Certificate (issued for AK) [AK mode only]

All modes:
    └── Certificate Key (0x81010002) certified by IAK/AK via TPM2_Certify
        └── Proves TPM-protected, non-exportable attributes
```

### ⚠️ PoC Limitations

This is a **Proof-of-Concept** for demonstration purposes:

1. **Self-Enrollment Allowed**:
   - PoC allows client-initiated TPM enrollment
   - **Production MUST**: Admin-only enrollment via secure out-of-band channels
   - **Production MUST**: Physical device verification before enrollment

2. **Empty Authorization Values**:
   - PoC uses no passwords for TPM keys
   - **Production MUST**: Implement proper authorization policies

3. **No PCR Binding**:
   - PoC does not bind keys to boot measurements
   - **Production SHOULD**: Bind certificate keys to PCRs for measured boot

4. **No Key Rotation**:
   - PoC has no key rotation policy
   - **Production MUST**: Implement automated key rotation

## Production Recommendations

### 1. Hardware TPM Requirements
- Run on bare metal (not containers) for TPM device access
- Use TPM 2.0 compliant chips (Intel PTT, AMD fTPM, discrete TPMs)
- Ensure kernel TPM drivers loaded (`tpm_tis`, `tpm_crb`)

### 2. Security Hardening
- **Admin-only enrollment**: Require administrator approval for device enrollment
- **Out-of-band verification**: Verify device identity before adding to allowlist
- **EK validation**: Enable `validate_ek_certificate=true` in OpenBao
- **Manufacturer CAs**: Add trusted manufacturer root CAs (Intel, AMD, Infineon, etc.)
- **Authorization policies**: Implement TPM authorization policies for key usage
- **PCR binding**: Bind certificate keys to PCRs for measured boot attestation

### 3. Network Security
- Use mTLS for gRPC communication
- Encrypt all network traffic
- Implement mutual authentication

### 4. Operational Security
- Audit logging for all enrollment and attestation events
- Monitor attestation success/failure rates
- Alert on validation anomalies
- Implement certificate rotation procedures

### 5. Compliance
- FIPS 140-2/3 TPM modules for regulated environments
- Follow TCG guidelines for TPM usage
- Maintain audit trail for compliance reporting

## Standards Compliance

This implementation follows:

1. **TCG TPM 2.0 Keys for Device Identity and Attestation** (2018)
   - Manufacturer-provisioned IAK support
   - TPM-generated attestation keys

2. **TPM 2.0 Library Specification**
   - `TPM2_Certify` operation
   - `TPM_ST_ATTEST_CERTIFY` (0x8017) attestation structure
   - `TPMT_PUBLIC` encoding

3. **WebAuthn Level 2 - TPM Attestation**
   - TPM attestation statement format
   - x5c certificate chain
   - Signature verification
   - NAME hash verification

4. **draft-ietf-acme-device-attest-01**
   - `device-attest-01` challenge type
   - Permanent identifier binding
   - TPM attestation object format

## Troubleshooting

### Hardware TPM Not Detected

**Symptoms**:
```
Failed to open TPM device
```

**Solutions**:
1. Check TPM device exists: `ls -l /dev/tpm*`
2. Load TPM kernel module: `sudo modprobe tpm_tis` or `tpm_crb`
3. Check TPM is not disabled in BIOS
4. Ensure Docker has access to devices (privileged mode enabled in compose)

### Permission Denied on TPM Device

**Error**: `failed to open TPM: permission denied`

**Solution**: Hardware TPM client runs with privileged mode in Docker. If issues persist:
```bash
# Check device permissions
ls -l /dev/tpm0 /dev/tpmrm0

# Ensure devices exist
sudo modprobe tpm_tis
```

### Persistent Handle Already in Use

**Symptoms**: AK or certificate key already exists from previous run

**Solution**: This is **normal behavior** - the implementation reuses existing keys:
```
AK already exists at handle 0x81010002, using existing key
Certificate key already exists at handle 0x81010003, using existing key
```

**To force fresh keys**:
```bash
# Clean all state (SWTPM)
make clean

# Or manually clear hardware TPM handles
sudo tpm2_evictcontrol -C o -c 0x81010002
sudo tpm2_evictcontrol -C o -c 0x81010003
```

### Attestation Validation Fails

**Error**: `TPM signature verification failed`

**Debugging**:
1. Check OpenBao logs: `docker compose logs openbao | grep -i attest`
2. Verify IAK certificate chains correctly
3. Ensure EK root CA is configured in OpenBao
4. Check permanent ID is enrolled

### OpenBao Connection Refused

**Error**: `Failed to connect to server: connection refused`

**Solution**: Ensure server is running:
```bash
make run-server
curl http://localhost:8200/v1/sys/health
```

## References

- [TCG TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/resource/tpm-2-0-keys-for-device-identity-and-attestation/)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [WebAuthn Level 2 - TPM Attestation](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
- [draft-ietf-acme-device-attest-01](https://datatracker.ietf.org/doc/html/draft-ietf-acme-device-attest-01)
- [RFC 8555 - ACME](https://datatracker.ietf.org/doc/html/rfc8555)
- [RFC 4043 - Permanent Identifier](https://datatracker.ietf.org/doc/html/rfc4043)
- [Smallstep Managed Device Attestation](https://smallstep.com/blog/managed-device-attestation/)
- [OpenBao PKI Secrets Engine](https://openbao.org/docs/secrets/pki/)
- [go-attestation](https://github.com/google/go-attestation)
- [go-tpm](https://github.com/google/go-tpm)

## License


