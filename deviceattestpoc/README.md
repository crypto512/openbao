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
|  |  (TPM 2.0)    |    | (gRPC+Web+DB) |    |   (PKI + ACME)    |   |
|  +-------+-------+    +-------+-------+    +---------+---------+   |
|          |                    |                      |             |
|     port 2321         port 50051/8443           port 8200          |
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
      |<-- provisioned --------------|                           |
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
make da-init SPKI=sha256//yp/DAVVj1vR8tPqQ/KFq0kvXUKzJHMg6y58STUXM2vA=
```

The server displays its SPKI pin on startup in the logs:
```
═══════════════════════════════════════════════════════════
Server SPKI Pin: sha256//yp/DAVVj1vR8tPqQ/KFq0kvXUKzJHMg6y58STUXM2vA=
═══════════════════════════════════════════════════════════
```

#### da-init Sequence

The `da-init` command performs Trust-On-First-Use (TOFU) bootstrap:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          da-init Sequence                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. TOFU Setup                                                          │
│     ├─ Connect to server (with SPKI pin verification if provided)       │
│     ├─ Capture server CA chain during TLS handshake                     │
│     └─ Persist to /etc/da/da.json: server address, CA, SPKI pin         │
│                                                                         │
│  2. TPM Enrollment (via da-lak)                                         │
│     ├─ Send EK certificate to server                                    │
│     ├─ Server validates EK against manufacturer CAs                     │
│     └─ Check device approval status (see below)                         │
│         │                                                               │
│         ├─ [Pre-registered by admin] → Auto-approve, continue           │
│         ├─ [Auto-approve enabled]    → Auto-approve, continue           │
│         └─ [Auto-approve disabled]   → Exit with "PENDING APPROVAL"     │
│                                                                         │
│  3. LAK Provisioning (if approved)                                      │
│     ├─ Generate AK in TPM                                               │
│     ├─ MakeCredential/ActivateCredential challenge                      │
│     └─ Receive LAK certificate                                          │
│                                                                         │
│  4. Agent Certificate (via da-agent)                                    │
│     ├─ Create agent key in TPM                                          │
│     ├─ ACME device-attest-01 challenge                                  │
│     └─ Receive agent certificate                                        │
│                                                                         │
│  ✓ Device fully initialized                                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Device Approval Workflow

The server supports two enrollment modes controlled via the web UI:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Auto-approve enabled** (default) | New devices are automatically approved | Development, testing |
| **Auto-approve disabled** | New devices require admin approval | Production |

**Pre-registered devices** (added via web UI) go directly to "provisioned" state, bypassing approval. When the device connects, it can immediately proceed with LAK provisioning.

When auto-approve is disabled and a new device connects:

```
════════════════════════════════════════════════════════════
  DEVICE PENDING APPROVAL
════════════════════════════════════════════════════════════

  This device has been registered but requires admin approval
  before it can proceed with provisioning.

  Permanent ID: A3B2C1D4E5F6...

  Next steps:
  1. Ask your administrator to approve this device
  2. Run 'da-init' again after approval

════════════════════════════════════════════════════════════
```

The admin can then approve the device via the web UI, and the user re-runs `make da-init`.

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (check logs) |
| 2 | Pending approval (not an error, device registered but awaiting admin) |

> **Note:** When pending approval, no TPM attestation key is created. This prevents TPM dictionary attack lockout from repeated attempts while waiting for admin approval.

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

### Build Targets

| Target | Description |
|--------|-------------|
| `make build` | Build all containers (Go + Rust clients) |
| `make build-client` | Build Go client container only |
| `make build-client-rust` | Build Rust client container only |
| `make bin` | Extract Go binaries (Linux) to `./bin/` |
| `make bin-windows` | Extract Go binaries (Windows) to `./bin/windows/` |
| `make bin-rust` | Extract Rust binaries (Linux) to `./bin/` |
| `make clean` | Remove containers, volumes, and images |
| `make clean-client` | Clean client state (LAK, agent, certificates) |
| `make clean-pki` | Clean OpenBao PKI (requires clean-client) |
| `make clean-swtpm` | Clean SWTPM state and container (new EK, clears DA lockout) |

### Go Client Tools (da-*)

| Target | Description |
|--------|-------------|
| `make run-server` | Start infrastructure (OpenBao + Server + SWTPM) |
| `make da-fingerprint` | Display permanent identifier (admin provisioning) |
| `make da-init` | Bootstrap device trust (--force mode for dev/testing) |
| `make da-init SPKI=<pin>` | Bootstrap with SPKI pin verification (TOFU mode) |
| `make da-lak` | Provision LAK certificate (TCG credential activation) |
| `make da-agent` | Provision agent certificate (ACME device-attest-01) |
| `make da-gen USAGE=<name> [OUTPUT=<dir>]` | Generate usage certificate (mTLS, self-healing) |

### Rust Client Tools (dar-*)

| Target | Description |
|--------|-------------|
| `make dar-fingerprint` | Display permanent identifier (Rust client) |
| `make dar-init` | Bootstrap device trust (Rust client) |
| `make dar-init SPKI=<pin>` | Bootstrap with SPKI pin verification (Rust client) |
| `make dar-lak` | Provision LAK certificate (Rust client) |
| `make dar-agent` | Provision agent certificate (Rust client) |
| `make dar-gen USAGE=<name> [OUTPUT=<dir>]` | Generate usage certificate (Rust client) |

## Components

### Client Tools

Two client implementations are provided with identical functionality:

| Go Tool | Rust Tool | Standard | Purpose |
|---------|-----------|----------|---------|
| `da-fingerprint` | `dar-fingerprint` | - | Compute and display permanent ID from EK |
| `da-init` | `dar-init` | TOFU | Bootstrap device trust |
| `da-lak` | `dar-lak` | TCG Credential Profiles | Provision LAK via credential activation |
| `da-agent` | `dar-agent` | draft-acme-device-attest-07 | Provision agent cert via TPM attestation |
| `da-gen` | `dar-gen` | mTLS | Generate usage certificates (self-healing) |

### Server (gRPC + Web)

- Validates EK certificates against manufacturer CAs (loaded from `/ca`)
- Implements MakeCredential for LAK provisioning
- Proxies ACME requests to OpenBao for agent certificates
- Issues usage certificates via mTLS (validates agent cert from pki-agent CA)
- TLS for LAK/agent provisioning, mTLS for certificate generation
- **Web Interface** on port 8443 (same TLS certificate as gRPC)

#### Web Interface (https://localhost:8443)

The server provides an HTMX-based web interface for device management:

| Feature | Description |
|---------|-------------|
| **Dashboard** | SPKI pin display, device counts, certificate status, activity metrics |
| **Device List** | View all devices with status, LAK/Agent cert validity icons |
| **Add Device** | Enroll devices by fingerprint (manual pre-approval) |
| **Auto-Approve** | Toggle automatic enrollment of new devices (default: enabled) |
| **Audit Log** | Full history of enrollment and certificate operations |
| **Real-time Updates** | SSE-based live updates when device state changes |

Device status progression:
- `registered` → Device self-enrolled, awaiting admin approval
- `provisioned` → Device approved (ready for LAK enrollment)
- `enrolled` → LAK certificate issued (device identity established)
- `trusted` → Agent certificate issued (fully trusted, can request usage certificates)

Certificate validity icons:
- 🟢 Green: Valid (>7 days remaining)
- 🟡 Yellow: Expiring soon (<7 days)
- 🔴 Red: Expired
- ⚫ None: Not issued

#### Data Persistence

All server state is persisted in SQLite (`/data/db/devices.db`):
- Device enrollment and certificate status
- ACME orders and activation sessions
- Audit log of all operations
- Server settings (auto-approve, SPKI)
- Server TLS certificate (cached until expiry)

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

## Platform Support

### Go Client (da-*)

| Platform | Status | TPM Access |
|----------|--------|------------|
| **Linux** | ✅ Fully supported | `/dev/tpmrm0` device |
| **Windows** | ✅ Fully supported | Windows TBS API |

Both Linux and Windows binaries are cross-compiled from the same Docker build.

**Build:**
```bash
make bin          # Linux binaries → ./bin/
make bin-windows  # Windows binaries → ./bin/windows/
```

**Windows Configuration:**
- Config path: `%PROGRAMDATA%\DeviceAttest\da.json`
- TPM access: Automatic via Windows TBS API (no device path needed)
- Requires TPM 2.0 hardware or Hyper-V vTPM

### Rust Client (dar-*)

| Platform | Status | TPM Access |
|----------|--------|------------|
| **Linux** | ✅ Fully supported | tpm2-tss via tss-esapi |

The Rust client provides identical functionality to the Go client using the `tss-esapi` crate for TPM 2.0 access.

**Build:**
```bash
make bin-rust     # Linux binaries → ./bin/
```

## Limitations (PoC)

- Empty authorization values for TPM keys
- No PCR binding for measured boot
- SWTPM keys are in container memory (use hardware TPM for production)
- Web interface has no authentication (relies on network isolation)
