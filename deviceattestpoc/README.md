# ACME Device Attestation Proof-of-Concept

Real-world demonstration of ACME device attestation using TPM 2.0 for IPsec VPN certificate issuance.

## Overview

This PoC demonstrates:
- **TPM 2.0 Device Attestation** using `google/go-attestation` library
- **Hardware or Simulated TPM** auto-detection
- **gRPC API** for certificate requests with attestation
- **OpenBao ACME** integration with `device-attest-01` challenge
- **Permanent Identifier** binding certificates to TPM devices

## Architecture

```
┌─────────────┐       gRPC         ┌─────────────┐      ACME       ┌──────────────┐
│   Client    │◄──────────────────►│   Server    │◄───────────────►│   OpenBao    │
│             │  Cert Request      │             │   Orders/       │              │
│ - TPM Ops   │  Attestation       │ - gRPC      │   Challenges    │ - PKI        │
│ - CSR Gen   │                    │ - ACME API  │                 │ - ACME       │
│ - Attest    │                    │ - Proxy     │                 │ - Validation │
└──────┬──────┘                    └─────────────┘                 └──────────────┘
       │
       │ TPM API (Hardware or Simulated)
       ▼
┌─────────────┐
│   TPM 2.0   │
│             │
│ /dev/tpmrm0 │
│ or built-in │
│  simulation │
└─────────────┘
```

## Components

### 1. Client (`client/`)
- **Language**: Go
- **Dependencies**: go-attestation, gRPC, CBOR
- **Functions**:
  - Initialize TPM using go-attestation
  - Create Attestation Key (AK)
  - Generate CSR for IPsec VPN certificates
  - Generate TPM attestation objects (CBOR format)
  - Submit attestation via gRPC

### 2. Server (`server/`)
- **Language**: Go
- **Dependencies**: gRPC, OpenBao API client
- **Functions**:
  - Receive certificate requests via gRPC
  - Create ACME orders on OpenBao
  - Extract `device-attest-01` challenges
  - Forward attestations to OpenBao
  - Return signed certificates to clients

### 3. OpenBao
- **PKI Backend**: Certificate Authority
- **ACME Support**: RFC 8555 + draft-acme-device-attest
- **Device Attestation**: TPM 2.0 validation
- **Configuration**: Configured with attestation policies and role

## Prerequisites

- Docker and Docker Compose
- OpenBao binary built at `../bin/bao`

## Quick Start

### Option A: Unified Standalone Workflow (Recommended)

This workflow uses the same `tpm-acme-client` binary for both simulation and hardware TPM modes.

#### 1. Build Client Binary

```bash
cd deviceattestpoc
make build-client
```

This cross-compiles the client for your host OS (macOS, Linux, etc.).

#### 2. Start Server Infrastructure

```bash
# In one terminal
make run-server
```

This starts OpenBao and the gRPC server.

#### 3. Run Client (Choose Mode)

**Simulation Mode** (works anywhere):
```bash
# In another terminal
./bin/tpm-acme-client -simulate
```

**Hardware TPM Mode** (Linux only, requires `/dev/tpm`):
```bash
sudo ./bin/tpm-acme-client
```

Or use the make targets:
```bash
make run-client-sim    # Simulation mode
make run-client-hw     # Hardware TPM mode (sudo required)
```

#### 4. View Help

```bash
./bin/tpm-acme-client -help
```

### Option B: Docker Workflow (Simulation Only)

For quick testing without building binaries:

```bash
# Start everything in Docker
docker-compose up --build

# View client logs
docker-compose logs client
```

Expected output:
```
==============================================
ACME Device Attestation Client
==============================================
Server: server:50051
TPM Device: /dev/tpmrm0
Certificate CN: vpn-client-001.example.com

Step 1: Initializing TPM client...
✓ TPM initialized. Permanent ID: SIM-TPM-A1B2C3D4E5F60708

Step 2: Generating Certificate Signing Request...
✓ CSR generated

Step 3: Connecting to gRPC server...
✓ Connected to server

Step 3.5: Enrolling TPM device (PoC demonstration only)...

⚠️  IMPORTANT SECURITY NOTICE:
   In production, TPM enrollment MUST be performed by administrators
   through secure out-of-band channels. This PoC allows client-initiated
   enrollment for demonstration purposes ONLY.

✓ TPM enrolled successfully
  Permanent ID: SIM-TPM-A1B2C3D4E5F60708
  EK Root CA: simulated-tpm

Step 4: Requesting certificate with device attestation...
✓ Certificate request initiated
  Order ID: http://openbao:8200/v1/pki/acme/order/...
  Challenge URL: http://openbao:8200/v1/pki/acme/challenge/...
  Challenge Token: abc123...

Step 5: Generating TPM attestation...
✓ TPM attestation generated (1234 bytes)

Step 6: Submitting attestation to server...
✓ Attestation submitted successfully
  Status: valid

Step 7: Retrieving certificate...
✓ Certificate issued successfully!
Certificate saved to: /certs/vpn-client.pem

==============================================
✓ ACME Device Attestation Flow Completed
==============================================

Summary:
  • TPM Permanent ID: SIM-TPM-A1B2C3D4E5F60708
  • Certificate CN: vpn-client-001.example.com
  • Order ID: http://openbao:8200/v1/pki/acme/order/...
  • Attestation Status: processing

The device attestation challenge was successfully validated!
Certificate has been issued and saved to /certs/vpn-client.pem.
The certificate includes the permanent identifier in the SAN extension.
```

## Detailed Flow

### Phase 1: Initialization (Automatic)

1. **OpenBao Setup** (`scripts/init-openbao.sh`):
   - Enable PKI secrets engine at `/pki`
   - Generate root CA: "OpenBao PoC Root CA"
   - Configure global attestation settings:
     - `enabled=true`
     - `allowed_attestation_formats=["tpm"]`
     - `validate_ek_certificate=true` (now defaults to true for security)
   - Create role `ipsec-vpn`:
     - `allowed_domains=["example.com"]`
     - `allow_device_attestation=true`
     - `key_usage=["DigitalSignature", "KeyEncipherment", "KeyAgreement"]`
     - `ext_key_usage_oids=["1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6"]` (IPsec)
   - Enable ACME at `/pki/acme/`

2. **TPM Setup**:
   - Client auto-detects hardware TPM at `/dev/tpmrm0` or `/dev/tpm0`
   - Falls back to built-in simulation mode if no hardware TPM found
   - Uses `google/go-attestation` library for TPM operations

### Phase 2: TPM Enrollment (PoC Only - Admin Task in Production)

3. **Client Enrollment Request** (⚠️ **PoC ONLY - Admin task in production**):
   - Extract/generate EK root CA certificate (simulated in PoC)
   - Send enrollment request via gRPC `EnrollTPM`:
     ```protobuf
     EnrollTPM({
       permanent_identifier: "TPM-A1B2C3D4E5F60708",
       ek_root_ca_pem: "-----BEGIN CERTIFICATE-----...",
       ek_root_ca_name: "simulated-tpm",
       device_description: "Simulated TPM device..."
     })
     ```

4. **Server Configures OpenBao**:
   - Configure EK root CA: `POST /pki/config/acme/ek-roots/simulated-tpm`
   - Update role to enable EK validation and allowlist TPM:
     - `validate_ek_certificate=true`
     - `allowed_tpm_identifiers=["TPM-A1B2C3D4E5F60708"]`

### Phase 3: Certificate Request (Client-Initiated)

5. **Client Initialization**:
   - Open TPM connection via go-attestation
   - Create Attestation Key (AK) using `tpm.NewAK()`
   - Extract permanent identifier from TPM (serial or derived)
   - Generate RSA-2048 key pair for certificate

6. **CSR Generation**:
   - Create x509 CSR with:
     - CN: `vpn-client-001.example.com`
     - SAN DNS: `vpn-client-001.example.com`
   - Sign CSR with certificate private key

7. **gRPC Certificate Request**:
   ```protobuf
   RequestCertificate({
     common_name: "vpn-client-001.example.com",
     san_dns: ["vpn-client-001.example.com"],
     csr_pem: "-----BEGIN CERTIFICATE REQUEST-----...",
     permanent_identifier: "TPM-A1B2C3D4E5F60708"
   })
   ```

8. **Server Creates ACME Order**:
   - Create ACME account on OpenBao (if needed)
   - POST to `/pki/acme/new-order`:
     ```json
     {
       "identifiers": [
         {
           "type": "permanent-identifier",
           "value": "TPM-A1B2C3D4E5F60708"
         }
       ]
     }
     ```
   - Extract `device-attest-01` challenge from authorization
   - Return challenge details to client

### Phase 4: Attestation (Client Response)

9. **Generate TPM Attestation**:
   - Compute key authorization: `{token}.{account_thumbprint}`
   - Hash key authorization: `SHA256(key_authorization)`
   - Create `pubArea` (TPMT_PUBLIC) for certificate key
   - Create `certInfo` (TPMS_ATTEST) with:
     - `magic`: `0xFF544347` (TPM_GENERATED_VALUE)
     - `type`: `0x8017` (TPM_ST_ATTEST_CERTIFY)
     - `extraData`: SHA256 hash of key authorization
     - `attestedCertify.name`: TPM name of certificate key
   - Sign `certInfo` with AK private key
   - Build attestation statement:
     ```json
     {
       "ver": "2.0",
       "alg": -257,  // RS256
       "x5c": [<AIK certificate DER>],
       "sig": <signature over certInfo>,
       "certInfo": <TPMS_ATTEST bytes>,
       "pubArea": <TPMT_PUBLIC bytes>
     }
     ```
   - Wrap in attestation object:
     ```json
     {
       "fmt": "tpm",
       "attStmt": {...}
     }
     ```
   - Encode to CBOR and base64url

10. **Submit Attestation**:
   ```protobuf
   SubmitAttestation({
     order_id: "http://openbao:8200/v1/pki/acme/order/...",
     challenge_url: "http://openbao:8200/v1/pki/acme/challenge/...",
     attestation_object: "<base64url CBOR>"
   })
   ```

11. **Server Forwards to OpenBao**:
   - POST to challenge URL with JWS:
     ```json
     {
       "attObj": "<base64url CBOR attestation object>"
     }
     ```

### Phase 5: Validation (OpenBao)

12. **OpenBao Validates Attestation**:
    - Decode base64url → CBOR → AttestationObject
    - Verify format is "tpm"
    - Parse TPM attestation statement
    - Verify TPM version is "2.0"
    - Parse AIK certificate from `x5c[0]`
    - Validate EK certificate chain (if enabled)
    - Parse `certInfo` (TPMS_ATTEST):
      - Verify magic value
      - Verify type is TPM_ST_ATTEST_CERTIFY
      - Extract `extraData` (key authorization hash)
    - Compute expected key authorization hash
    - **Verify**: `extraData == SHA256(token + '.' + thumbprint)`
    - Parse `pubArea` (TPMT_PUBLIC)
    - Verify signature over `certInfo` using AIK public key
    - Compute TPM name of certified object
    - **Verify**: `attestedCertify.name == ComputeName(pubArea)`
    - Extract permanent identifier from AIK certificate
    - **Verify**: Permanent identifier is in allowlist (if configured)
    - **Verify**: Permanent identifier is not in blocklist (if configured)
    - Mark challenge as `valid`

13. **Order Status**:
    - All challenges valid → Order status: `ready`
    - Ready for finalization with CSR

### Phase 6: Finalization

14. **Finalize Order**:
    - POST CSR to finalize URL
    - OpenBao issues certificate with:
      - Subject from CSR
      - SAN: Permanent identifier extension (OID 1.3.6.1.5.5.7.8.3)
      - Key Usage: DigitalSignature, KeyEncipherment, KeyAgreement
      - Extended Key Usage: IPsec End System (1.3.6.1.5.5.7.3.5), IPsec Tunnel (1.3.6.1.5.5.7.3.6)
    - Order status: `valid`

15. **Download Certificate**:
    - GET certificate URL
    - Receive PEM-encoded certificate + chain
    - Save to `/certs/vpn-client.pem`

## Configuration

### Environment Variables

**OpenBao** (`openbao` service):
- `BAO_DEV_ROOT_TOKEN_ID`: Root token (default: `root`)
- `BAO_DEV_LISTEN_ADDRESS`: Listen address (default: `0.0.0.0:8200`)

**Server** (`server` service):
- `BAO_ADDR`: OpenBao address (default: `http://openbao:8200`)
- `BAO_TOKEN`: OpenBao token (default: `root`)
- `GRPC_PORT`: gRPC port (default: `50051`)

**Client** (`client` service):
- `SERVER_ADDR`: gRPC server address (default: `server:50051`)
- `CERT_COMMON_NAME`: Certificate CN (default: `vpn-client-001.example.com`)
- `LOG_LEVEL`: Logging level (default: `debug`)

### Re-running the Client

To run the client again (e.g., to test different configurations):

```bash
# Restart the client container to run again
docker-compose restart client

# View the new output
docker-compose logs -f client
```

### Customization

**Change Certificate Name**:
```bash
docker-compose run --rm -e CERT_COMMON_NAME=vpn-client-002.example.com client
```

**Enable EK Certificate Validation**:
Edit `scripts/init-openbao.sh`, change:
```bash
"validate_ek_certificate": true
```

**Add Real EK Root Certificates**:
```bash
docker-compose exec openbao bash
bao write pki/config/acme/ek-roots/intel-root certificate=@/path/to/intel-root.pem
```

## Testing

### Manual Testing

```bash
# View all logs in real-time
docker-compose logs -f

# View OpenBao logs
docker-compose logs -f openbao

# View server logs
docker-compose logs -f server

# View client output
docker-compose logs client

# Run client again with different settings
docker-compose run --rm -e CERT_COMMON_NAME=test.example.com client

# Interactive client shell (for debugging)
docker-compose run --rm client sh
```

### API Testing

```bash
# Test OpenBao ACME directory
curl http://localhost:8200/v1/pki/acme/directory | jq .

# List EK roots
curl -X LIST \
  -H "X-Vault-Token: root" \
  http://localhost:8200/v1/pki/config/acme/ek-roots | jq .

# Get attestation config
curl -H "X-Vault-Token: root" \
  http://localhost:8200/v1/pki/config/attestation | jq .

# Get role config
curl -H "X-Vault-Token: root" \
  http://localhost:8200/v1/pki/roles/ipsec-vpn | jq .
```

### gRPC Testing (with grpcurl)

```bash
# List services
docker run --rm --network deviceattestpoc_attestation-net \
  fullstorydev/grpcurl -plaintext server:50051 list

# Describe service
docker run --rm --network deviceattestpoc_attestation-net \
  fullstorydev/grpcurl -plaintext server:50051 \
  describe certservice.CertificateService
```

## Troubleshooting

### Client Uses Simulated TPM

**Message**: `Using simulated attestation mode (not suitable for production)`

**Explanation**: No hardware TPM detected. Client uses built-in simulation.

**For Production**: Run on bare metal with real TPM hardware at `/dev/tpmrm0`

### Server Can't Reach OpenBao

**Error**: `Failed to create ACME order: connection refused`

**Solution**: Check OpenBao health:
```bash
curl http://localhost:8200/v1/sys/health
docker-compose logs openbao
```

### Attestation Validation Fails

**Error**: `badAttestationStatement` or `extraData mismatch`

**Debugging**:
1. Check key authorization computation in client
2. Verify qualifying data in `certInfo`
3. Review OpenBao logs for validation details:
   ```bash
   docker-compose logs openbao | grep -i attest
   ```

### Certificate Not Issued

**Error**: Order stuck in "ready" status

**Reason**: Finalization not implemented in PoC server

**Workaround**: Manually finalize using OpenBao API

## Production Considerations

This is a **Proof-of-Concept** for demonstration purposes.

⚠️ **CRITICAL SECURITY NOTICE**: See [SECURITY.md](SECURITY.md) for detailed production deployment requirements, especially regarding TPM enrollment which **MUST** be performed by administrators through secure out-of-band channels.

For production:

1. **Use Real TPM Hardware**:
   - Run on bare metal (not containers) for hardware TPM access
   - Client auto-detects `/dev/tpmrm0` or `/dev/tpm0`
   - Ensure kernel TPM drivers loaded
   - Test with actual TPM 2.0 chips (Intel PTT, AMD fTPM, discrete TPMs)

2. **Enable EK Certificate Validation**:
   - Set `validate_ek_certificate=true`
   - Add manufacturer root CAs (Intel, AMD, Infineon, STMicroelectronics)
   - Verify certificate chains to trusted roots

3. **Use mTLS for gRPC**:
   - Generate server/client TLS certificates
   - Enable mutual authentication
   - Encrypt all gRPC communication

4. **Complete Certificate Issuance**:
   - Implement order finalization in server
   - Submit CSR to finalize URL
   - Download and verify certificate
   - Handle certificate renewal

5. **Add Policy Validation**:
   - Define attestation policy OIDs
   - Require specific TPM attributes
   - Validate firmware versions
   - Check for known vulnerabilities

6. **Implement Error Handling**:
   - Retry logic for transient failures
   - Proper error reporting to clients
   - Audit logging for security events

7. **Key Management**:
   - Secure storage for ACME account keys
   - TPM-based key storage
   - Key rotation procedures

8. **Scalability**:
   - Load balancing for gRPC servers
   - OpenBao HA deployment
   - Distributed TPM management

9. **Monitoring**:
   - Metrics for attestation success/failure rates
   - Alerting for validation anomalies
   - Performance monitoring

10. **Compliance**:
    - Meet FIPS 140-2/3 requirements
    - Follow Common Criteria guidelines
    - Comply with industry standards (e.g., TCG, IEEE 802.1AR)

## Architecture Details

### TPM Attestation Format

Based on [draft-acme-device-attest-07](https://datatracker.ietf.org/doc/html/draft-ietf-acme-device-attest) and [WebAuthn TPM Attestation](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation).

**Attestation Object** (CBOR):
```
{
  "fmt": "tpm",
  "attStmt": {
    "ver": "2.0",
    "alg": -257,  // COSE algorithm (RS256)
    "x5c": [<AIK cert DER>, ...],
    "sig": <signature bytes>,
    "certInfo": <TPMS_ATTEST bytes>,
    "pubArea": <TPMT_PUBLIC bytes>
  }
}
```

**TPMS_ATTEST Structure**:
```
struct {
  TPM_GENERATED magic;           // 0xff544347
  TPMI_ST_ATTEST type;           // 0x8017 (certify)
  TPM2B_NAME qualifiedSigner;
  TPM2B_DATA extraData;          // ← Key authorization hash!
  TPMS_CLOCK_INFO clockInfo;
  UINT64 firmwareVersion;
  TPMS_CERTIFY_INFO attested;    // For type=certify
}
```

**TPMS_CERTIFY_INFO**:
```
struct {
  TPM2B_NAME name;               // ← TPM name of certified key
  TPM2B_NAME qualifiedName;
}
```

**TPMT_PUBLIC Structure**:
```
struct {
  TPMI_ALG_PUBLIC type;          // e.g., TPM_ALG_RSA
  TPMI_ALG_HASH nameAlg;         // e.g., TPM_ALG_SHA256
  TPMA_OBJECT objectAttributes;
  TPM2B_DIGEST authPolicy;
  TPMU_PUBLIC_PARMS parameters;  // RSA/ECC params
  TPMU_PUBLIC_ID unique;         // Public key data
}
```

### gRPC Protocol

**Service Definition**:
```protobuf
service CertificateService {
  // PoC-only endpoint - MUST be admin-only in production
  rpc EnrollTPM(TPMEnrollmentRequest) returns (EnrollmentResponse);

  rpc RequestCertificate(CertRequest) returns (CertResponse);
  rpc SubmitAttestation(AttestationSubmit) returns (CertResponse);
  rpc GetCertificate(GetCertRequest) returns (CertResponse);
}
```

**Flow**:
1. **Enrollment (PoC only)**: Client → `EnrollTPM` → Server → Configure OpenBao
2. Client → `RequestCertificate` → Server
3. Server creates ACME order on OpenBao
4. Server ← `CertResponse` (with challenge) ← Server
5. Client generates TPM attestation
6. Client → `SubmitAttestation` → Server
7. Server submits to OpenBao ACME API
8. OpenBao validates attestation (including allowlist/blocklist check)
9. Client → `GetCertificate` → Server
10. Server downloads certificate from OpenBao
11. Client ← `CertResponse` (with certificate) ← Server

## References

- [draft-acme-device-attest-07](https://datatracker.ietf.org/doc/html/draft-ietf-acme-device-attest)
- [RFC 8555 - ACME](https://datatracker.ietf.org/doc/html/rfc8555)
- [RFC 4043 - Permanent Identifier](https://datatracker.ietf.org/doc/html/rfc4043)
- [RFC 4108 - Hardware Module Name](https://datatracker.ietf.org/doc/html/rfc4108)
- [WebAuthn TPM Attestation](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [google/go-attestation](https://github.com/google/go-attestation)

## License

Copyright (c) OpenBao a Series of LF Projects, LLC

SPDX-License-Identifier: MPL-2.0
