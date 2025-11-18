# ACME Device Attestation in OpenBao PKI

This document describes the ACME device attestation functionality added to OpenBao's PKI secrets engine, implementing [draft-acme-device-attest-07](https://www.ietf.org/archive/id/draft-acme-device-attest-07.txt).

## Overview

ACME Device Attestation extends the standard ACME protocol to enable certificate issuance to hardware-backed devices based on cryptographic attestation rather than traditional domain ownership validation. Devices equipped with Trusted Platform Modules (TPMs), Secure Enclaves, or similar secure cryptoprocessors can prove their identity and request certificates automatically.

### Use Cases

- **IoT Device Provisioning**: Automatically provision certificates to IoT devices with hardware security modules
- **Enterprise Device Management**: Issue certificates to corporate laptops and workstations with TPM chips
- **Zero-Touch Provisioning**: Enable devices to obtain certificates without manual intervention or pre-shared secrets
- **Hardware-Bound Certificates**: Ensure private keys are generated in and never leave secure hardware

### Key Differences from Standard ACME

| Aspect | Standard ACME | ACME Device Attestation |
|--------|---------------|-------------------------|
| **Validation Method** | Domain ownership (HTTP-01, DNS-01, TLS-ALPN-01) | Hardware attestation (device-attest-01) |
| **Identifier Types** | `dns`, `ip` | `permanent-identifier`, `hardware-module` |
| **Challenge Response** | Empty JSON object `{}` | WebAuthn attestation object (CBOR-encoded) |
| **Certificate Binding** | Domain names | Device hardware identifiers |
| **Trust Anchor** | CA validates domain control | CA validates manufacturer certificate chain |

## Protocol Flow

```
┌─────────────┐                                           ┌─────────────┐
│   Device    │                                           │  OpenBao    │
│  with TPM   │                                           │ ACME Server │
└──────┬──────┘                                           └──────┬──────┘
       │                                                         │
       │  1. Create ACME Account                                 │
       ├────────────────────────────────────────────────────────>│
       │     POST /acme/{role}/new-account                       │
       │<────────────────────────────────────────────────────────┤
       │     201 Created (account URL)                           │
       │                                                         │
       │  2. Submit Order with permanent-identifier              │
       ├────────────────────────────────────────────────────────>│
       │     POST /acme/{role}/new-order                         │
       │     {                                                   │
       │       "identifiers": [                                  │
       │         {                                               │
       │           "type": "permanent-identifier",               │
       │           "value": "PID:device-12345"                   │
       │         }                                               │
       │       ]                                                 │
       │     }                                                   │
       │<────────────────────────────────────────────────────────┤
       │     201 Created (order with device-attest-01 challenge) │
       │                                                         │
       │  3. Fetch Authorization                                 │
       ├────────────────────────────────────────────────────────>│
       │     POST-as-GET /acme/{role}/authz/{authz-id}           │
       │<────────────────────────────────────────────────────────┤
       │     200 OK (challenge type: device-attest-01)           │
       │                                                         │
       │  4. Generate TPM Attestation                            │
       ├──┐                                                      │
       │  │ • Construct key authorization                        │
       │  │ • Hash with SHA-256                                  │
       │  │ • Call TPM2_Certify with hash                        │
       │  │ • Build attestation object (CBOR)                    │
       │<─┘                                                      │
       │                                                         │
       │  5. Respond to Challenge                                │
       ├────────────────────────────────────────────────────────>│
       │     POST /acme/{role}/challenge/{challenge-id}          │
       │     { "attObj": "<base64url-encoded-cbor>" }            │
       │<────────────────────────────────────────────────────────┤
       │     200 OK (challenge valid)                            │
       │                                                         │
       │                      ┌──────────────────────┐           │
       │                      │ OpenBao validates:   │           │
       │                      │ • AIK cert chain     │           │
       │                      │ • TPM signature      │           │
       │                      │ • Key authorization  │           │
       │                      │ • Permanent ID       │           │
       │                      └──────────────────────┘           │
       │                                                         │
       │  6. Finalize Order with CSR                             │
       ├────────────────────────────────────────────────────────>│
       │     POST /acme/{role}/order/{order-id}/finalize         │
       │     { "csr": "<base64url-pkcs10>" }                     │
       │<────────────────────────────────────────────────────────┤
       │     200 OK (certificate ready)                          │
       │                                                         │
       │  7. Download Certificate                                │
       ├────────────────────────────────────────────────────────>│
       │     POST-as-GET /acme/{role}/certificate/{cert-id}      │
       │<────────────────────────────────────────────────────────┤
       │     200 OK (PEM certificate with permanent-identifier)  │
       │                                                         │
```

### TPM Attestation Validation

```
┌──────────────────────────────────────────────────────────────────┐
│              Attestation Object (CBOR, Base64URL)                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │   "fmt": "tpm",                                            │  │
│  │   "attStmt": {                                             │  │
│  │     "ver": "2.0",                                          │  │
│  │     "alg": -257,     // RS256                              │  │
│  │     "x5c": [<AIK-cert>, <intermediate-CAs>...],            │  │
│  │     "sig": <tpm-signature>,                                │  │
│  │     "certInfo": <TPMS_ATTEST>,                             │  │
│  │     "pubArea": <TPMT_PUBLIC>                               │  │
│  │   }                                                        │  │
│  │ }                                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                OpenBao Validation Pipeline                     │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 1. Decode CBOR and Parse Structures                      │  │
│  │    • Verify CBOR format                                  │  │
│  │    • Extract attestation statement                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 2. Validate AIK Certificate Chain                        │  │
│  │    • x5c[0]: AIK certificate                             │  │
│  │    • x5c[1..n]: Intermediate CAs                         │  │
│  │    • Chain to configured EK root CA                      │  │
│  │    • Check expiration and revocation                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 3. Verify TPM Structures                                 │  │
│  │    • TPMS_ATTEST magic = 0xff544347                      │  │
│  │    • Type = TPM_ST_ATTEST_CERTIFY (0x8017)               │  │
│  │    • Extract extraData (key auth hash)                   │  │
│  │    • Extract attested key from TPMT_PUBLIC               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 4. Verify Cryptographic Signature                        │  │
│  │    • Compute hash of certInfo                            │  │
│  │    • Verify signature using AIK public key               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 5. Validate Key Authorization                            │  │
│  │    • Construct: token + "." + thumbprint                 │  │
│  │    • SHA-256 hash                                        │  │
│  │    • Compare with extraData (constant-time)              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 6. Extract Permanent Identifier                          │  │
│  │    • Parse AIK certificate SAN extension                 │  │
│  │    • OID 1.3.6.1.5.5.7.8.3 (permanentIdentifier)         │  │
│  │    • OID 1.3.6.1.5.5.7.8.4 (hardwareModuleName)          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 7. Policy Enforcement                                    │  │
│  │    • Check allowed/blocked identifier lists              │  │
│  │    • Verify attestation policy OIDs                      │  │
│  │    • Validate against role settings                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌────────────────────────────────────────────────────────────┐│
│  │         ✓ Attestation Valid - Store for Issuance           ││
│  └────────────────────────────────────────────────────────────┘│
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Configuration API

### Global Attestation Configuration

Configure device attestation settings at the PKI mount level.

**Endpoint**: `POST /v1/pki/config/attestation`

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | `false` | Enable device attestation globally |
| `validate_ek_certificate` | bool | `true` | Validate TPM EK certificate chains |
| `default_attestation_policies` | []string | `[]` | Default policy OIDs required in certificates |
| `allowed_attestation_formats` | []string | `["tpm"]` | Allowed attestation formats |

**Request Example**:

```bash
curl -X POST https://bao.example.com/v1/pki/config/attestation \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "enabled": true,
    "validate_ek_certificate": true,
    "allowed_attestation_formats": ["tpm"]
  }'
```

**Response**: `204 No Content`

**Read Configuration**:

```bash
curl https://bao.example.com/v1/pki/config/attestation \
  -H "X-Vault-Token: $TOKEN"
```

**Response Example**:
```json
{
  "data": {
    "enabled": true,
    "validate_ek_certificate": true,
    "default_attestation_policies": [],
    "allowed_attestation_formats": ["tpm"]
  }
}
```

### EK Root Certificate Management

Manage trusted TPM manufacturer root CA certificates.

#### List EK Roots

**Endpoint**: `LIST /v1/pki/config/acme/ek-roots`

```bash
curl -X LIST https://bao.example.com/v1/pki/config/acme/ek-roots \
  -H "X-Vault-Token: $TOKEN"
```

**Response**:
```json
{
  "data": {
    "keys": ["intel-tpm-root", "infineon-ecc", "infineon-rsa", "stm"]
  }
}
```

#### Add EK Root Certificate

**Endpoint**: `POST /v1/pki/config/acme/ek-roots/{name}`

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Identifier for this root CA |
| `certificate` | string | Yes | PEM-encoded X.509 root CA certificate |

```bash
curl -X POST https://bao.example.com/v1/pki/config/acme/ek-roots/intel-tpm-root \
  -H "X-Vault-Token: $TOKEN" \
  -d @- <<EOF
{
  "name": "intel-tpm-root",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIEnjCCA4agAwIBAgIUGQ...\n-----END CERTIFICATE-----"
}
EOF
```

**Response**:
```json
{
  "data": {
    "name": "intel-tpm-root"
  }
}
```

#### Read EK Root Certificate

**Endpoint**: `GET /v1/pki/config/acme/ek-roots/{name}`

```bash
curl https://bao.example.com/v1/pki/config/acme/ek-roots/intel-tpm-root \
  -H "X-Vault-Token: $TOKEN"
```

**Response**:
```json
{
  "data": {
    "name": "intel-tpm-root",
    "certificate": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

#### Delete EK Root Certificate

**Endpoint**: `DELETE /v1/pki/config/acme/ek-roots/{name}`

```bash
curl -X DELETE https://bao.example.com/v1/pki/config/acme/ek-roots/intel-tpm-root \
  -H "X-Vault-Token: $TOKEN"
```

**Response**: `204 No Content`

### Role Configuration

Configure PKI roles to support device attestation.

**Endpoint**: `POST /v1/pki/roles/{role-name}`

**Device Attestation Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_device_attestation` | bool | `false` | Enable device attestation for this role |
| `validate_ek_certificate` | bool | inherited | Override global EK validation setting |
| `required_attestation_formats` | []string | inherited | Required attestation formats (e.g., `["tpm"]`) |
| `attestation_policies` | []string | `[]` | Required certificate policy OIDs |
| `allowed_tpm_identifiers` | []string | `[]` | Whitelist of permanent identifiers (empty = allow all) |
| `blocked_tpm_identifiers` | []string | `[]` | Blacklist of permanent identifiers |
| `allow_permanent_identifier_sans` | bool | `false` | Include permanent identifier in certificate SAN |
| `allow_hardware_module_name_sans` | bool | `false` | Include hardware module name in certificate SAN |

**Request Example**:

```bash
curl -X POST https://bao.example.com/v1/pki/roles/ipsec-vpn \
  -H "X-Vault-Token: $TOKEN" \
  -d @- <<EOF
{
  "allow_device_attestation": true,
  "required_attestation_formats": ["tpm"],
  "validate_ek_certificate": true,
  "attestation_policies": ["2.23.133.8.1"],
  "allow_permanent_identifier_sans": true,
  "allowed_domains": ["vpn.example.com"],
  "allow_subdomains": true,
  "ttl": "8760h",
  "max_ttl": "8760h"
}
EOF
```

## ACME API Reference

### ACME Directory

Standard ACME directory endpoint.

**Endpoint**: `GET /v1/pki/acme/{role}/directory`

```bash
curl https://bao.example.com/v1/pki/acme/ipsec-vpn/directory
```

**Response**:
```json
{
  "newNonce": "https://bao.example.com/v1/pki/acme/ipsec-vpn/new-nonce",
  "newAccount": "https://bao.example.com/v1/pki/acme/ipsec-vpn/new-account",
  "newOrder": "https://bao.example.com/v1/pki/acme/ipsec-vpn/new-order",
  "revokeCert": "https://bao.example.com/v1/pki/acme/ipsec-vpn/revoke-cert",
  "keyChange": "https://bao.example.com/v1/pki/acme/ipsec-vpn/key-change"
}
```

### Create Order with Device Identifier

**Endpoint**: `POST /v1/pki/acme/{role}/new-order`

**Identifier Types**:

- `permanent-identifier`: Device-specific permanent identifier from TPM
- `hardware-module`: Hardware security module identifier

**Request Example**:

```bash
curl -X POST https://bao.example.com/v1/pki/acme/ipsec-vpn/new-order \
  -H "Content-Type: application/jose+json" \
  -d '{
    "protected": "<base64url-jws-header>",
    "payload": "<base64url-payload>",
    "signature": "<base64url-signature>"
  }'
```

**Decoded Payload**:
```json
{
  "identifiers": [
    {
      "type": "permanent-identifier",
      "value": "PID:device-12345"
    }
  ]
}
```

**Response** (201 Created):
```json
{
  "status": "pending",
  "expires": "2025-01-25T10:00:00Z",
  "identifiers": [
    {
      "type": "permanent-identifier",
      "value": "PID:device-12345"
    }
  ],
  "authorizations": [
    "https://bao.example.com/v1/pki/acme/ipsec-vpn/authz/abc123"
  ],
  "finalize": "https://bao.example.com/v1/pki/acme/ipsec-vpn/order/xyz789/finalize"
}
```

### Fetch Authorization

**Endpoint**: `POST /v1/pki/acme/{role}/authz/{authz-id}` (POST-as-GET)

**Response**:
```json
{
  "status": "pending",
  "expires": "2025-01-25T10:00:00Z",
  "identifier": {
    "type": "permanent-identifier",
    "value": "PID:device-12345"
  },
  "challenges": [
    {
      "type": "device-attest-01",
      "url": "https://bao.example.com/v1/pki/acme/ipsec-vpn/challenge/challenge-id",
      "token": "a82d5ff8d91c1421c8c8faa8f8e5e5e5",
      "status": "pending"
    }
  ]
}
```

### Respond to device-attest-01 Challenge

**Endpoint**: `POST /v1/pki/acme/{role}/challenge/{challenge-id}`

**Request**:

```bash
curl -X POST https://bao.example.com/v1/pki/acme/ipsec-vpn/challenge/challenge-id \
  -H "Content-Type: application/jose+json" \
  -d '{
    "protected": "<base64url-jws-header>",
    "payload": "<base64url-payload>",
    "signature": "<base64url-signature>"
  }'
```

**Decoded Payload**:
```json
{
  "attObj": "o2NmbXRjdHBtZ2F0dFN0bXSmY3ZlcmMyLjBjYWxnJmR4NWOCWQKgMIICnDCCAYSgAwIBAgIQeD..."
}
```

The `attObj` field contains a base64url-encoded CBOR attestation object:

```
Attestation Object (CBOR):
{
  "fmt": "tpm",
  "attStmt": {
    "ver": "2.0",
    "alg": -257,
    "x5c": [<AIK-cert-DER>, <intermediate-CA-DER>, ...],
    "sig": <signature-bytes>,
    "certInfo": <TPMS_ATTEST-bytes>,
    "pubArea": <TPMT_PUBLIC-bytes>
  }
}
```

**Response** (200 OK):
```json
{
  "type": "device-attest-01",
  "url": "https://bao.example.com/v1/pki/acme/ipsec-vpn/challenge/challenge-id",
  "token": "a82d5ff8d91c1421c8c8faa8f8e5e5e5",
  "status": "valid",
  "validated": "2025-01-18T15:30:00Z"
}
```

### Finalize Order

**Endpoint**: `POST /v1/pki/acme/{role}/order/{order-id}/finalize`

**Decoded Payload**:
```json
{
  "csr": "MIICzDCCAbQCAQAwXzELMAkGA1UEBhMCVVMx..."
}
```

**Response** (200 OK):
```json
{
  "status": "valid",
  "expires": "2025-01-25T10:00:00Z",
  "identifiers": [...],
  "authorizations": [...],
  "finalize": "...",
  "certificate": "https://bao.example.com/v1/pki/acme/ipsec-vpn/certificate/cert-id"
}
```

### Download Certificate

**Endpoint**: `POST /v1/pki/acme/{role}/certificate/{cert-id}` (POST-as-GET)

**Response** (200 OK):
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIUFEzU9z7F7N3J3k7vX...
-----END CERTIFICATE-----
```

## TPM Attestation Format

### Attestation Statement Structure

| Field | Type | Description |
|-------|------|-------------|
| `ver` | string | TPM version ("2.0") |
| `alg` | int | COSE algorithm identifier (-257 for RS256) |
| `x5c` | [][]byte | AIK certificate chain (DER-encoded) |
| `sig` | []byte | TPM signature over certInfo |
| `certInfo` | []byte | TPMS_ATTEST structure |
| `pubArea` | []byte | TPMT_PUBLIC structure |

### COSE Algorithm Identifiers

| Algorithm | COSE ID | Description |
|-----------|---------|-------------|
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 |

### TPMS_ATTEST Structure

The `certInfo` field contains a TPM 2.0 attestation structure:

| Field | Value | Description |
|-------|-------|-------------|
| `magic` | `0xff544347` | TPM_GENERATED_VALUE |
| `type` | `0x8017` | TPM_ST_ATTEST_CERTIFY |
| `qualifiedSigner` | TPM2B_NAME | AIK name |
| `extraData` | TPM2B_DATA | SHA-256(token + "." + thumbprint) |
| `clockInfo` | TPMS_CLOCK_INFO | TPM clock counters |
| `firmwareVersion` | uint64 | TPM firmware version |
| `attested` | TPMS_CERTIFY_INFO | Attested key information |

The `extraData` field **must** contain the SHA-256 hash of the ACME key authorization string.

## Certificate Extensions

When device attestation is used and enabled in the role, issued certificates include special SAN extensions.

### Permanent Identifier Extension

**OID**: `1.3.6.1.5.5.7.8.3` (id-on-permanentIdentifier)

Appears in certificate Subject Alternative Name as:

```
X509v3 Subject Alternative Name:
    DNS:device.vpn.example.com
    othername: 1.3.6.1.5.5.7.8.3 :: UTF8String: PID:device-12345
```

### Hardware Module Name Extension

**OID**: `1.3.6.1.5.5.7.8.4` (id-on-hardwareModuleName)

Appears in certificate Subject Alternative Name as:

```
X509v3 Subject Alternative Name:
    DNS:device.vpn.example.com
    othername: 1.3.6.1.5.5.7.8.4 ::
        hwType: 2.23.133.2.1
        hwSerialNum: OCTET STRING 'TPM:manufacturer=IFX,model=SLB9665'
```

## TPM Manufacturer Root CAs

Configure trusted manufacturer root CA certificates for validating TPM endorsement key certificates.

### Microsoft provide a package with all TPM manufacturer CA

https://go.microsoft.com/fwlink/?linkid=2097925

## Security Model

### Trust Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Hierarchy                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  TPM Manufacturer Root CA (trusted by OpenBao)              │
│              │                                              │
│              ├─ Intermediate CA                             │
│              │        │                                     │
│              │        └─ AIK Certificate                    │
│              │                  │                           │
│              │                  │ certifies                 │
│              │                  ▼                           │
│              │           Device Key                         │
│              │           (in TPM, non-exportable)           │
│              │                                              │
│  Endorsement Key (EK)                                       │
│  • Factory-provisioned by manufacturer                      │
│  • Identifies specific TPM hardware                         │
│  • Used to validate AIK authenticity                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Validation Requirements

OpenBao performs comprehensive validation:

1. **Certificate Chain Validation**
   - AIK certificate must chain to a configured manufacturer root CA
   - All certificates must be within validity period
   - Certificate key usage must be appropriate

2. **Cryptographic Verification**
   - TPM signature must verify using AIK public key
   - Key authorization hash must match extraData in attestation
   - TPMS_ATTEST magic value must be correct (0xff544347)

3. **Policy Enforcement**
   - Permanent identifier allowlist/blocklist checks
   - Certificate policy OID validation
   - Attestation format restrictions per role

4. **Replay Prevention**
   - Each challenge has a unique token
   - Key authorization binds challenge to specific ACME account
   - Attestation validated only once per challenge

### Security Best Practices

#### 1. Configure EK Root Certificates

Only trust manufacturer CAs from official sources:

```bash
# Verify certificate fingerprints
openssl x509 -in Intel_TPM_RootCA.pem -noout -fingerprint -sha256

# Compare with published fingerprints before installing
bao write pki/config/acme/ek-roots/intel \
  name=intel \
  certificate=@Intel_TPM_RootCA.pem
```

#### 2. Use Identifier Allowlists

Restrict which devices can obtain certificates:

```bash
bao write pki/roles/ipsec-vpn \
  allow_device_attestation=true \
  allowed_tpm_identifiers="PID:laptop-001,PID:laptop-002,PID:laptop-003"
```

#### 3. Enable EK Certificate Validation

Always validate in production:

```bash
bao write pki/config/attestation \
  validate_ek_certificate=true
```

#### 4. Require Attestation Policies

Enforce enterprise TPM policies:

```bash
bao write pki/roles/ipsec-vpn \
  attestation_policies="2.23.133.8.1,2.23.133.8.3"
```

Common TCG policy OIDs:
- `2.23.133.8.1` - TCG TPM Attestation
- `2.23.133.8.3` - TCG TPM Endorsement

#### 5. Limit Certificate Validity

Use short TTLs and enable rotation:

```bash
bao write pki/roles/ipsec-vpn \
  ttl=720h \      # 30 days
  max_ttl=8760h   # 1 year
```

#### 6. Block Compromised Devices

Maintain a blocklist:

```bash
bao write pki/roles/ipsec-vpn \
  blocked_tpm_identifiers="PID:compromised-device-123"
```

### Threat Model

**Protected Against:**

- ✅ Unauthorized certificate issuance (requires TPM attestation)
- ✅ Software-based key generation (TPM validates key origin)
- ✅ Stolen credentials (no pre-shared secrets)
- ✅ Impersonation attacks (cryptographic proof required)
- ✅ Man-in-the-middle (HTTPS + JWS signatures)

**Not Protected Against:**

- ❌ Physical TPM extraction/cloning (requires physical security)
- ❌ Compromised TPM firmware (trust manufacturer practices)
- ❌ Side-channel attacks on TPM (hardware security responsibility)
- ❌ Authorized device misuse (certificate issuance is legitimate)

## Example Configuration Workflow

### Step 1: Enable Device Attestation

```bash
# Enable globally
bao write pki/config/attestation \
  enabled=true \
  validate_ek_certificate=true \
  allowed_attestation_formats=tpm
```

### Step 2: Configure Manufacturer Root CAs

```bash
# Add Intel TPM root
bao write pki/config/acme/ek-roots/intel \
  name=intel \
  certificate=@intel_tpm_root.pem

# Add Infineon TPM roots
bao write pki/config/acme/ek-roots/infineon-ecc \
  name=infineon-ecc \
  certificate=@infineon_ecc_root.pem

bao write pki/config/acme/ek-roots/infineon-rsa \
  name=infineon-rsa \
  certificate=@infineon_rsa_root.pem
```

### Step 3: Create Role for Device Certificates

```bash
bao write pki/roles/ipsec-vpn \
  allow_device_attestation=true \
  required_attestation_formats=tpm \
  validate_ek_certificate=true \
  allow_permanent_identifier_sans=true \
  allowed_domains="vpn.example.com" \
  allow_subdomains=true \
  ttl=720h \
  max_ttl=8760h
```

### Step 4: Verify Configuration

```bash
# Check attestation config
bao read pki/config/attestation

# List EK roots
bao list pki/config/acme/ek-roots

# Verify role
bao read pki/roles/ipsec-vpn
```

### Step 5: Device Enrollment

Devices can now use ACME with device attestation:

1. Create ACME account
2. Submit order with `permanent-identifier`
3. Complete `device-attest-01` challenge with TPM attestation
4. Finalize order with CSR
5. Download certificate

## Troubleshooting

### Configuration Issues

**Problem**: "device attestation not enabled"

**Solution**: Enable globally and in role:
```bash
bao write pki/config/attestation enabled=true
bao write pki/roles/ipsec-vpn allow_device_attestation=true
```

---

**Problem**: "no validator registered for attestation format: tpm"

**Solution**: Ensure TPM format is allowed:
```bash
bao write pki/config/attestation allowed_attestation_formats=tpm
bao write pki/roles/ipsec-vpn required_attestation_formats=tpm
```

### Certificate Validation Issues

**Problem**: "failed to verify AIK certificate chain"

**Solution**: Add manufacturer root CA:
```bash
bao write pki/config/acme/ek-roots/manufacturer \
  name=manufacturer \
  certificate=@manufacturer_root.pem
```

---

**Problem**: "permanent identifier not found in AIK certificate"

**Solution**: AIK certificate must include SAN with OID 1.3.6.1.5.5.7.8.3

### Attestation Validation Issues

**Problem**: "key authorization verification failed"

**Solution**: Client must:
1. Construct key authorization: `token + "." + thumbprint`
2. Compute SHA-256 hash
3. Use hash as qualifying data in TPM2_Certify

---

**Problem**: "TPM permanent identifier is blocked"

**Solution**: Remove from blocklist:
```bash
bao write pki/roles/ipsec-vpn \
  blocked_tpm_identifiers=""
```

### Policy Issues

**Problem**: "attestation format 'tpm' is not allowed by server policy"

**Solution**: Update role configuration:
```bash
bao write pki/roles/ipsec-vpn \
  required_attestation_formats=tpm
```

---

**Problem**: "role does not allow device attestation"

**Solution**: Enable in role:
```bash
bao write pki/roles/ipsec-vpn \
  allow_device_attestation=true
```

## References

- [draft-acme-device-attest-07](https://www.ietf.org/archive/id/draft-acme-device-attest-07.txt) - ACME Device Attestation
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html) - ACME Protocol
- [WebAuthn](https://www.w3.org/TR/webauthn-2/) - Web Authentication (attestation format)
- [TCG TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/) - TPM Specification
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) - X.509 Certificate Profile

---

**Document Version**: 1.0
**OpenBao Branch**: deviceattest
**Last Updated**: 2025-01-18
