# ACME Device Attestation PoC

**Proof of Concept** demonstrating TPM 2.0 device attestation with a three-phase approach:

1. **TCG Credential Activation** - LAK certificate issuance via MakeCredential/ActivateCredential
2. **ACME device-attest-01** - Agent certificate via TPM attestation (hardware-bound identity)
3. **mTLS Certificate Generation** - Usage certificates issued via mTLS with agent cert

## Overview

This PoC implements industry standards for hardware-backed device identity:

| Phase | Standard | Purpose |
|-------|----------|---------|
| **LAK Provisioning** | TCG TPM 2.0 Credential Profiles | Establish device identity via Privacy CA |
| **Agent Certificate** | draft-acme-device-attest-07 | Hardware-bound agent identity via ACME |
| **Usage Certificates** | mTLS with agent cert | Issue VPN/WiFi/TLS certs (short-lived) |

The combination ensures:
- Device authenticity proven via EK certificate chain
- AK-EK binding verified through credential activation
- Agent key proven non-exportable via TPM2_Certify
- Usage certificates require valid agent mTLS authentication

### Key Concepts

| Term | Description |
|------|-------------|
| **EK** | Endorsement Key - Manufacturer-provisioned, decrypt-only, proves TPM authenticity |
| **AK** | Attestation Key - Restricted signing key for TPM2_Certify operations |
| **LAK** | Local Attestation Key certificate - Binds AK to device identity (TCG term) |
| **Agent Key** | TPM-bound signing key for agent certificate (attested via ACME) |
| **Cert Key** | Ephemeral RSA key for usage certificates (generated on demand) |
| **Permanent ID** | Base64(SHA256(EK public key)) - Stable device identifier |

## Architecture

```
+===================================================================+
|                         INFRASTRUCTURE                             |
+===================================================================+
|                                                                    |
|  +---------------+    +---------------+    +-------------------+   |
|  |    SWTPM      |    |    Server     |    |     OpenBao       |   |
|  |  (TPM 2.0)    |    |  (gRPC+mTLS)  |    |   (PKI + ACME)    |   |
|  +-------+-------+    +-------+-------+    +---------+---------+   |
|          |                    |                      |             |
|     port 2321            port 50051             port 8200          |
+----------+--------------------+----------------------+-------------+
           |                    |                      |
           | TPM2 Commands      | gRPC/TLS/mTLS        | HTTP/ACME
           |                    |                      |
+----------+--------------------+----------------------+-------------+
|          v                    v                      v             |
|  +----------------------------------------------------------------+|
|  |                          CLIENT                                ||
|  |                                                                ||
|  |  +--------------+ +---------+ +--------+ +--------+ +--------+ ||
|  |  |da-fingerprint| | da-init | | da-lak | |da-agent| | da-gen | ||
|  |  | (EK hash)    | | (TOFU)  | | (TCG)  | | (ACME) | | (mTLS) | ||
|  |  +--------------+ +---------+ +--------+ +--------+ +--------+ ||
|  +----------------------------------------------------------------+|
|                              TOOLS                                 |
+====================================================================+


+====================================================================+
|                       TPM KEY HIERARCHY                            |
+====================================================================+
|                                                                    |
|  Endorsement Hierarchy          Storage Hierarchy                  |
|  (Manufacturer)                 (Owner)                            |
|                                                                    |
|  +-------------+                +------------------+               |
|  |     EK      |                |       SRK        |               |
|  | (decrypt)   |                |  (storage root)  |               |
|  +------+------+                +--------+---------+               |
|         |                                |                         |
|         |                       +--------+--------+--------+       |
|         |                       |                 |        |       |
|         |               +-------+------+  +-------+----+ +-+-----+ |
|         |               |      AK      |  | Agent Key  |         |
|         |               | (restricted  |  | (flexible  |         |
|         |               |  signing)    |  |  signing)  |         |
|         |               +-------+------+  +-----+------+         |
|         |                       |               |                  |
|         |  MakeCredential       | TPM2_Certify  |                  |
|         +--------+--------------+               |                  |
|                  |                              |                  |
|                  v                              v                  |
|         +--------+--------+            +--------+---+              |
|         | LAK Certificate |            |Agent Cert  |  Usage Cert  |
|         | (pki-ak CA)     |            |(pki-agent) |  (pki-usage) |
|         +-----------------+            +------------+  [ephemeral] |
|                                                                    |
|  Phase 1: TCG Credential   Phase 2: ACME      Phase 3: mTLS       |
+====================================================================+
```

## Protocol Flows

### Phase 1: TCG Credential Activation (da-lak)

Per TCG TPM 2.0 Keys for Device Identity and Attestation:

```
    CLIENT                         SERVER                      OPENBAO
      |                               |                           |
      |  1. EnrollTPM(EK cert)        |                           |
      |------------------------------>|                           |
      |                               | Validate EK cert          |
      |                               | against manufacturer CAs  |
      |<-- enrolled ------------------|                           |
      |                               |                           |
      |  2. ProvisionLAK              |                           |
      |     (AK public, EK public)    |                           |
      |------------------------------>|                           |
      |                               |                           |
      |                               | 3. MakeCredential         |
      |                               |    - Generate secret      |
      |                               |    - Encrypt to EK        |
      |                               |    - Bind to AK name      |
      |                               |                           |
      |<-- encrypted_credential ------|                           |
      |                               |                           |
      | 4. TPM2_ActivateCredential    |                           |
      |    - Proves EK+AK in same TPM |                           |
      |    - Decrypts secret          |                           |
      |                               |                           |
      |  5. ActivateCredential        |                           |
      |     (decrypted secret)        |                           |
      |------------------------------>|                           |
      |                               | Verify secret matches     |
      |                               |                           |
      |                               | 6. Sign LAK certificate   |
      |                               |-------------------------->|
      |                               | POST /pki-ak/sign-verbatim|
      |                               |      /lak-device          |
      |                               |<--------------------------|
      |                               |                           |
      |<-- LAK certificate -----------|                           |
      |                               |                           |
      | Store LAK cert in da.json     |                           |
      |                               |                           |
```

### Phase 2: ACME Device Attestation (da-agent)

Per draft-acme-device-attest-07:

```
    CLIENT                         SERVER                      OPENBAO
      |                               |                           |
      | Load LAK cert from da.json    |                           |
      |                               |                           |
      |  1. RequestCertificate        |                           |
      |     (usage=agent, permanent_id)|                          |
      |------------------------------>|                           |
      |                               | 2. POST /pki-agent/roles/ |
      |                               |    agent/acme/new-order   |
      |                               |    identifier: permanent-id
      |                               |-------------------------->|
      |                               |<--------------------------|
      |                               |    device-attest-01       |
      |<-- challenge_token -----------|                           |
      |                               |                           |
      | 3. Create Agent Key (TPM)     |                           |
      |    - Flexible signing scheme  |                           |
      |    - FixedTPM, FixedParent    |                           |
      |                               |                           |
      | 4. TPM2_Certify(AgentKey, AK) |                           |
      |    - Proves key attributes    |                           |
      |    - extraData = SHA256(      |                           |
      |        token.thumbprint)      |                           |
      |                               |                           |
      | 5. Build attestation object   |                           |
      |    (WebAuthn TPM format)      |                           |
      |    - fmt: "tpm"               |                           |
      |    - certInfo: TPMS_ATTEST    |                           |
      |    - pubArea: TPMT_PUBLIC     |                           |
      |    - sig: AK signature        |                           |
      |    - x5c: [LAK cert]          |                           |
      |                               |                           |
      |  6. SubmitAttestation         |                           |
      |------------------------------>|                           |
      |                               | 7. POST challenge response|
      |                               |-------------------------->|
      |                               |    Validate:              |
      |                               |    - LAK cert chain       |
      |                               |    - TPM2_Certify sig     |
      |                               |    - Key attributes       |
      |                               |    - extraData matches    |
      |                               |<--------------------------|
      |<-- valid ----------------------|                           |
      |                               |                           |
      | 8. Sign CSR with Agent Key    |                           |
      |    (TPM2_Sign)                |                           |
      |                               |                           |
      |  9. FinalizeOrder(CSR)        |                           |
      |------------------------------>|                           |
      |                               | 10. POST /acme/finalize   |
      |                               |-------------------------->|
      |                               |<--------------------------|
      |<-- agent certificate ---------|                           |
      |                               |                           |
      | Save agent cert + key blobs   |                           |
      |                               |                           |
```

### Phase 3: mTLS Certificate Generation (da-gen)

Usage certificates are issued via mTLS authentication with the agent certificate.
The usage key is a standard RSA key (not TPM-bound) - ephemeral and regenerated on demand:

```
    CLIENT                         SERVER                      OPENBAO
      |                               |                           |
      | Load agent cert + key blobs   |                           |
      |                               |                           |
      | Generate RSA key (standard)   |                           |
      | Sign CSR with RSA key         |                           |
      |                               |                           |
      |  1. IssueCertificate (mTLS)   |                           |
      |     TLS client cert: agent    |                           |
      |     (usage, CSR)              |                           |
      |=============================>|                           |
      |     mTLS handshake uses       |                           |
      |     TPM-backed agent key      |                           |
      |                               |                           |
      |                               | 2. Validate mTLS client   |
      |                               |    cert is from pki-agent |
      |                               |                           |
      |                               | 3. POST /pki-usage/issue/ |
      |                               |    <role> (CSR)           |
      |                               |-------------------------->|
      |                               |<--------------------------|
      |                               |                           |
      |<-- certificate + chain -------|                           |
      |                               |                           |
      | Output: key.pem + cert.pem    |                           |
      |                               |                           |
```

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- Make

### Build

```bash
cd deviceattestpoc
make build
```

### Run

#### Administrator: Device Provisioning (before shipping)

**1. Get Device Fingerprint**
```bash
make da-fingerprint
```
Output: `A3B2C1D4E5F6...` (Base64 SHA256 of EK public key)

Register this fingerprint on the server to allow the device to enroll.

#### End User: Device Initialization

**2. Initialize Device (Bootstraps Trust)**
```bash
# Development/testing mode (skips SPKI verification):
make da-init

# Production mode with SPKI pin verification (TOFU):
docker compose run --rm client /bin/da-init server:50051 sha256//...
```
This bootstraps device trust by:
1. Connecting to the server (with SPKI pin verification in production mode)
2. Persisting the server address and CA chain to `/etc/da/da.json`
3. Provisioning LAK certificate (via da-lak)
4. Provisioning agent certificate (via da-agent)

The server displays its SPKI pin on startup in the logs:
```
═══════════════════════════════════════════════════════════
Server SPKI Pin: sha256//yp/DAVVj1vR8tPqQ/KFq0kvXUKzJHMg6y58STUXM2vA=
═══════════════════════════════════════════════════════════
```

**3. Generate Usage Certificate (mTLS)**
```bash
make da-gen USAGE=vpn
# Or with custom output directory:
make da-gen USAGE=vpn OUTPUT=/path/to/certs
```
Output files (in `./certs/` by default):
- `vpn-key.pem` - Private key in standard PEM format
- `vpn-cert.pem` - Signed certificate with full CA chain

Note: da-gen auto-refreshes expired LAK/agent certificates if needed (self-healing).

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build all containers with Docker Buildx |
| `make bin` | Extract binaries (`da-*`) to `./bin/` |
| `make clean` | Remove containers, volumes, and images |
| `make clean-client` | Clean client state (LAK, agent, certificates) |
| `make clean-pki` | Clean OpenBao PKI (requires clean-client) |
| `make clean-swtpm` | Clean SWTPM state (new EK on restart) |
| `make run-server` | Start infrastructure (OpenBao + Server + SWTPM) |
| `make da-fingerprint` | Display permanent identifier (admin provisioning) |
| `make da-init` | Bootstrap device trust (--force mode for dev/testing) |
| `make da-lak` | Provision LAK certificate (TCG credential activation) |
| `make da-agent` | Provision agent certificate (ACME device-attest-01) |
| `make da-gen USAGE=<name> [OUTPUT=<dir>]` | Generate usage certificate (mTLS, self-healing) |

## Components

### Client Tools

| Tool | Standard | Purpose |
|------|----------|---------|
| `da-fingerprint` | - | Compute and display permanent ID from EK (admin provisioning) |
| `da-init` | TOFU | Bootstrap device trust, chain to da-lak and da-agent |
| `da-lak` | TCG Credential Profiles | Provision LAK via credential activation |
| `da-agent` | draft-acme-device-attest-07 | Provision agent cert via TPM attestation |
| `da-gen` | mTLS | Generate usage certificates with agent cert (self-healing) |

### Server (gRPC)

- Validates EK certificates against manufacturer CAs (loaded from `/ca`)
- Implements MakeCredential for LAK provisioning
- Proxies ACME requests to OpenBao for agent certificates
- Issues usage certificates via mTLS (validates agent cert from pki-agent CA)
- TLS for LAK/agent provisioning, mTLS for certificate generation

### OpenBao PKI Configuration

| Mount | Role | Purpose | Validity |
|-------|------|---------|----------|
| `/pki-ak` | `lak-device` | Privacy CA for LAK certificates | 1 year |
| `/pki-grpc` | `server` | gRPC server TLS certificates | 30 days |
| `/pki-agent` | `agent` | Agent identity via ACME device-attest-01 | 1 month |
| `/pki-usage` | `vpn`, `wifi`, `tls` | Usage certificates via mTLS | 1 day |

**LAK Certificate Properties** (per TCG spec):
- Key Usage: `digitalSignature` only
- Extended Key Usage: `tcg-kp-AttestationKey` (2.23.133.8.3)
- SAN URI: `urn:permanent-identifier:<EK-hash>`

**Usage Mappings**:
```
vpn  -> pki-usage/roles/vpn   (VPN client certificates)
wifi -> pki-usage/roles/wifi  (WiFi/802.1X certificates)
tls  -> pki-usage/roles/tls   (Generic TLS client certificates)
```

### SWTPM

Software TPM 2.0 emulator (libtpms + swtpm):
- Manufacturer CA hierarchy for EK certificates
- Persistent state across restarts
- TCP interface on port 2321

## Security Properties

| Property | Verification Method |
|----------|---------------------|
| **TPM Authenticity** | EK certificate chain to manufacturer CA |
| **AK-EK Binding** | TPM2_ActivateCredential (MakeCredential challenge) |
| **Agent Key Non-Exportability** | TPM2_Certify proves FixedTPM, SensitiveDataOrigin |
| **Key-to-Device Binding** | extraData in TPMS_ATTEST contains challenge hash |
| **Usage Cert Authorization** | mTLS with pki-agent issued certificate required |

## Standards

| Standard | Usage in PoC |
|----------|--------------|
| [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/resource/tpm-2-0-keys-for-device-identity-and-attestation/) | LAK provisioning via credential activation |
| [draft-acme-device-attest-07](https://www.ietf.org/archive/id/draft-acme-device-attest-07.txt) | ACME device-attest-01 challenge |
| [WebAuthn TPM Attestation](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation) | Attestation object format |
| [TCG TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) | TPM2_Certify, TPM2_ActivateCredential |
| [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) | ACME Protocol base |

## Limitations (PoC)

- No device allowlist enforcement (all enrolled devices accepted)
- Empty authorization values for TPM keys
- No PCR binding for measured boot
- SWTPM keys are in container memory (use hardware TPM for production)
