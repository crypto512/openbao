# ACME Device Attestation PoC

**Proof of Concept** demonstrating TPM 2.0 device attestation with a two-phase approach:

1. **TCG Credential Activation** - LAK certificate issuance via MakeCredential/ActivateCredential
2. **ACME device-attest-01** - TPM-bound certificate generation per draft-acme-device-attest-07

## Overview

This PoC implements industry standards for hardware-backed device identity:

| Phase | Standard | Purpose |
|-------|----------|---------|
| **LAK Provisioning** | TCG TPM 2.0 Credential Profiles | Establish device identity via Privacy CA |
| **Certificate Issuance** | draft-acme-device-attest-07 | Issue TPM-bound certificates via ACME |

The combination ensures:
- Device authenticity proven via EK certificate chain
- AK-EK binding verified through credential activation
- Application keys proven non-exportable via TPM2_Certify

### Key Concepts

| Term | Description |
|------|-------------|
| **EK** | Endorsement Key - Manufacturer-provisioned, decrypt-only, proves TPM authenticity |
| **AK** | Attestation Key - Restricted signing key for TPM2_Certify operations |
| **LAK** | Local Attestation Key certificate - Binds AK to device identity (TCG term) |
| **Cert Key** | Non-restricted signing key for CSRs, certified by AK |
| **Permanent ID** | Base64(SHA256(EK public key)) - Stable device identifier |

## Architecture

```
+===================================================================+
|                         INFRASTRUCTURE                             |
+===================================================================+
|                                                                    |
|  +---------------+    +---------------+    +-------------------+   |
|  |    SWTPM      |    |    Server     |    |     OpenBao       |   |
|  |  (TPM 2.0)    |    |    (gRPC)     |    |   (PKI + ACME)    |   |
|  +-------+-------+    +-------+-------+    +---------+---------+   |
|          |                    |                      |             |
|     port 2321            port 50051             port 8200          |
+----------+--------------------+----------------------+-------------+
           |                    |                      |
           | TPM2 Commands      | gRPC Protocol        | HTTP/ACME
           |                    |                      |
+----------+--------------------+----------------------+-------------+
|          v                    v                      v             |
|  +----------------------------------------------------------------+|
|  |                          CLIENT                                ||
|  |                                                                ||
|  |  +-----------------+  +-----------------+  +-----------------+ ||
|  |  | da-fingerprint  |  |     da-lak      |  |     da-gen      | ||
|  |  |  (display EK    |  | (TCG credential |  | (ACME device-   | ||
|  |  |   hash)         |  |  activation)    |  |  attest-01)     | ||
|  |  +-----------------+  +-----------------+  +-----------------+ ||
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
|         |                       +--------+---------+               |
|         |                       |                  |               |
|         |               +-------+------+   +-------+-------+       |
|         |               |      AK      |   |   Cert Key    |       |
|         |               | (restricted  |   | (unrestricted |       |
|         |               |  signing)    |   |  signing)     |       |
|         |               +-------+------+   +-------+-------+       |
|         |                       |                  |               |
|         |  MakeCredential       |  TPM2_Certify    |               |
|         +--------+--------------+                  |               |
|                  |                                 |               |
|                  v                                 v               |
|         +--------+--------+               +-------+-------+        |
|         | LAK Certificate |               | App Certificate|       |
|         | (pki-ak CA)     |               | (pki-vpn CA)   |       |
|         +-----------------+               +----------------+       |
|                                                                    |
|  Phase 1: TCG Credential          Phase 2: ACME device-attest-01   |
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

### Phase 2: ACME Device Attestation (da-gen)

Per draft-acme-device-attest-07:

```
    CLIENT                         SERVER                      OPENBAO
      |                               |                           |
      | Load LAK cert from da.json    |                           |
      |                               |                           |
      |  1. RequestCertificate        |                           |
      |     (usage, permanent_id)     |                           |
      |------------------------------>|                           |
      |                               | 2. POST /pki-vpn/roles/   |
      |                               |    ipsec-vpn/acme/new-order
      |                               |    identifier: permanent-id
      |                               |-------------------------->|
      |                               |<--------------------------|
      |                               |    device-attest-01       |
      |<-- challenge_token -----------|                           |
      |                               |                           |
      | 3. Create Cert Key (TPM)      |                           |
      |    - Non-restricted signing   |                           |
      |    - FixedTPM, FixedParent    |                           |
      |                               |                           |
      | 4. TPM2_Certify(CertKey, AK)  |                           |
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
      | 8. Sign CSR with Cert Key     |                           |
      |    (TPM2_Sign)                |                           |
      |                               |                           |
      |  9. FinalizeOrder(CSR)        |                           |
      |------------------------------>|                           |
      |                               | 10. POST /acme/finalize   |
      |                               |-------------------------->|
      |                               |<--------------------------|
      |<-- certificate ----------------|                           |
      |                               |                           |
      | Save cert + key blobs         |                           |
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

**1. Get Device Fingerprint**
```bash
make da-fingerprint
```
Output: `A3B2C1D4E5F6...` (Base64 SHA256 of EK public key)

**2. Provision LAK Certificate (TCG Credential Activation)**
```bash
make da-lak
```
Performs MakeCredential/ActivateCredential, stores LAK cert in `/etc/da/da.json`

**3. Generate Attested Certificate (ACME device-attest-01)**
```bash
make da-gen USAGE=ipsec-vpn
```
Output files:
- `ipsec-vpn-key.blob` - TPM-encrypted key blobs (non-exportable)
- `ipsec-vpn-cert.pem` - Signed certificate with full chain

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build all containers with Docker Buildx |
| `make bin` | Extract binaries (`da-*`) to `./bin/` |
| `make clean` | Remove containers, volumes, and images |
| `make clean-client` | Clean client state (LAK, certificates) |
| `make clean-pki` | Clean OpenBao PKI (requires clean-client) |
| `make clean-swtpm` | Clean SWTPM state (new EK on restart) |
| `make run-server` | Start infrastructure (OpenBao + Server + SWTPM) |
| `make da-fingerprint` | Display permanent identifier |
| `make da-lak` | Provision LAK certificate (TCG) |
| `make da-gen USAGE=<name>` | Generate attested certificate (ACME) |

## Components

### Client Tools

| Tool | Standard | Purpose |
|------|----------|---------|
| `da-fingerprint` | - | Compute and display permanent ID from EK |
| `da-lak` | TCG Credential Profiles | Provision LAK via credential activation |
| `da-gen` | draft-acme-device-attest-07 | Generate TPM-attested certificates |

### Server (gRPC)

- Validates EK certificates against manufacturer CAs (loaded from `/ca`)
- Implements MakeCredential for LAK provisioning
- Proxies ACME requests to OpenBao
- Issues LAK certificates via OpenBao `/pki-ak/sign-verbatim/lak-device`

### OpenBao PKI Configuration

| Mount | Role | Purpose |
|-------|------|---------|
| `/pki-ak` | `lak-device` | Privacy CA for LAK certificates |
| `/pki-vpn` | `ipsec-vpn` | VPN certificates via ACME device-attest-01 |

**LAK Certificate Properties** (per TCG spec):
- Key Usage: `digitalSignature` only
- Extended Key Usage: `tcg-kp-AttestationKey` (2.23.133.8.3)
- SAN URI: `urn:permanent-identifier:<EK-hash>`

**Usage Mappings** (extensible):
```
ipsec-vpn, vpn -> pki-vpn/roles/ipsec-vpn
wifi           -> pki-wifi/roles/wifi-client
tls            -> pki-tls/roles/tls-client
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
| **Key Non-Exportability** | TPM2_Certify proves FixedTPM, SensitiveDataOrigin |
| **Key-to-Device Binding** | extraData in TPMS_ATTEST contains challenge hash |

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
