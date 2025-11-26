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
| **Trust Anchor** | CA validates domain control | CA validates AIK certificate chain |

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
       │  │ • Call TPM2_Certify with hash as extraData           │
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
│  │    • Chain to configured AK CA root                      │  │
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
│  │ 6. Verify Attested Public Key Name                       │  │
│  │    • Compute TPM Name = nameAlg || Hash(pubArea)         │  │
│  │    • Compare with TPMS_CERTIFY_INFO.Name                 │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 7. Extract Permanent Identifier                          │  │
│  │    • Parse AIK certificate SAN extension                 │  │
│  │    • OID 1.3.6.1.5.5.7.8.3 (permanentIdentifier)         │  │
│  │    • Or URI SAN with urn:permanent-identifier: prefix    │  │
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
| `validate_ek_certificate` | bool | `true` | Validate AIK certificate chains against configured AK CA roots |
| `default_attestation_policies` | []string | `[]` | Default policy OIDs required in certificates |
| `allowed_attestation_formats` | []string | `["tpm"]` | Allowed attestation formats: `tpm`, `android-key`, `apple`, `chromeos` |

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

### AK CA Root Certificate Management

Manage trusted Attestation Key (AK) CA root certificates. These certificates are used to validate AIK certificate chains in TPM attestation statements.

**Note**: In a typical deployment, a Privacy CA issues AIK/LAK certificates to devices. The Privacy CA's root certificate must be configured here for OpenBao to validate device attestations.

#### List AK CA Roots

**Endpoint**: `LIST /v1/pki/config/acme/ak-ca-roots`

```bash
curl -X LIST https://bao.example.com/v1/pki/config/acme/ak-ca-roots \
  -H "X-Vault-Token: $TOKEN"
```

**Response**:
```json
{
  "data": {
    "keys": ["privacy-ca", "openbao-ak", "enterprise-ca"]
  }
}
```

#### Add AK CA Root Certificate

**Endpoint**: `POST /v1/pki/config/acme/ak-ca-roots/{name}`

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Identifier for this root CA |
| `certificate` | string | Yes | PEM-encoded X.509 CA certificate |

```bash
curl -X POST https://bao.example.com/v1/pki/config/acme/ak-ca-roots/privacy-ca \
  -H "X-Vault-Token: $TOKEN" \
  -d @- <<EOF
{
  "name": "privacy-ca",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIEnjCCA4agAwIBAgIUGQ...\n-----END CERTIFICATE-----"
}
EOF
```

**Response**:
```json
{
  "data": {
    "name": "privacy-ca"
  }
}
```

#### Read AK CA Root Certificate

**Endpoint**: `GET /v1/pki/config/acme/ak-ca-roots/{name}`

```bash
curl https://bao.example.com/v1/pki/config/acme/ak-ca-roots/privacy-ca \
  -H "X-Vault-Token: $TOKEN"
```

**Response**:
```json
{
  "data": {
    "name": "privacy-ca",
    "certificate": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

#### Delete AK CA Root Certificate

**Endpoint**: `DELETE /v1/pki/config/acme/ak-ca-roots/{name}`

```bash
curl -X DELETE https://bao.example.com/v1/pki/config/acme/ak-ca-roots/privacy-ca \
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
| `validate_ek_certificate` | bool | `true` | Validate AIK certificate chain (override global setting) |
| `required_attestation_formats` | []string | `[]` | Required attestation formats (empty = inherit from global) |
| `attestation_policies` | []string | `[]` | Required certificate policy OIDs |

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

- `permanent-identifier`: Device-specific permanent identifier extracted from AIK certificate
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

Per draft-acme-device-attest-07 Section 5, the server verifies that the CSR contains the public key attested in the attestation statement (from `pubArea`).

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
| `sig` | []byte | TPM signature over certInfo (TPMT_SIGNATURE) |
| `certInfo` | []byte | TPMS_ATTEST structure |
| `pubArea` | []byte | TPMT_PUBLIC structure |

### COSE Algorithm Identifiers

| Algorithm | COSE ID | Description |
|-----------|---------|-------------|
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 |

### TPMS_ATTEST Structure

The `certInfo` field contains a TPM 2.0 attestation structure (TPM 2.0 Part 2, Section 10.12.8):

| Field | Value | Description |
|-------|-------|-------------|
| `magic` | `0xff544347` | TPM_GENERATED_VALUE |
| `type` | `0x8017` | TPM_ST_ATTEST_CERTIFY |
| `qualifiedSigner` | TPM2B_NAME | AIK name |
| `extraData` | TPM2B_DATA | SHA-256(token + "." + thumbprint) |
| `clockInfo` | TPMS_CLOCK_INFO | TPM clock counters |
| `firmwareVersion` | uint64 | TPM firmware version |
| `attested` | TPMS_CERTIFY_INFO | Attested key information |

The `extraData` field **MUST** contain the SHA-256 hash of the ACME key authorization string.

### TPMT_PUBLIC Structure

The `pubArea` field contains the public key structure (TPM 2.0 Part 2, Section 12.2.4):

| Field | Description |
|-------|-------------|
| `type` | Key algorithm (TPM_ALG_RSA, TPM_ALG_ECDSA) |
| `nameAlg` | Hash algorithm for computing Name (TPM_ALG_SHA256) |
| `objectAttributes` | TPMA_OBJECT flags (FixedTPM, FixedParent, etc.) |
| `authPolicy` | Authorization policy digest |
| `parameters` | Algorithm-specific parameters |
| `unique` | Public key material |

The TPM Name is computed as: `nameAlg || Hash(pubArea)` and must match `TPMS_CERTIFY_INFO.Name`.

### TPMT_SIGNATURE Structure

Per draft-acme-device-attest-07 Section 5.1, the `sig` field contains a TPMT_SIGNATURE:

| Signature Algorithm | Format |
|---------------------|--------|
| RSASSA (0x0014) | hashAlg (2B) + TPM2B_PUBLIC_KEY_RSA |
| RSAPSS (0x0016) | hashAlg (2B) + TPM2B_PUBLIC_KEY_RSA |
| ECDSA (0x0018) | hashAlg (2B) + TPM2B r + TPM2B s |

## Certificate Extensions

When device attestation is used, issued certificates include special SAN extensions.

### Permanent Identifier Extension

**OID**: `1.3.6.1.5.5.7.8.3` (id-on-permanentIdentifier per RFC 4043)

Appears in certificate Subject Alternative Name as:

```
X509v3 Subject Alternative Name:
    DNS:device.vpn.example.com
    othername: 1.3.6.1.5.5.7.8.3 :: UTF8String: PID:device-12345
```

Alternative URI format (used by LAK certificates):
```
X509v3 Subject Alternative Name:
    URI:urn:permanent-identifier:A3B2C1D4E5F6...
```

### Hardware Module Name Extension

**OID**: `1.3.6.1.5.5.7.8.4` (id-on-hardwareModuleName per RFC 4108)

Appears in certificate Subject Alternative Name as:

```
X509v3 Subject Alternative Name:
    DNS:device.vpn.example.com
    othername: 1.3.6.1.5.5.7.8.4 ::
        hwType: 2.23.133.2.1
        hwSerialNum: OCTET STRING 'TPM:manufacturer=IFX,model=SLB9665'
```

## Security Model

### Trust Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Hierarchy                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  AK CA Root (Privacy CA)                                    │
│  • Configured in OpenBao via /config/acme/ak-ca-roots       │
│  • Issues AIK/LAK certificates to devices                   │
│              │                                              │
│              ├─ Intermediate CA (optional)                  │
│              │        │                                     │
│              │        └─ AIK Certificate (LAK)              │
│              │                  │                           │
│              │                  │ certifies via TPM2_Certify│
│              │                  ▼                           │
│              │           Device Key                         │
│              │           (in TPM, non-exportable)           │
│              │                                              │
│  Endorsement Key (EK) - Manufacturer-provisioned            │
│  • Used during LAK provisioning (credential activation)     │
│  • Proves TPM authenticity to Privacy CA                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Validation Requirements

OpenBao performs comprehensive validation:

1. **Certificate Chain Validation**
   - AIK certificate must chain to a configured AK CA root certificate
   - All certificates must be within validity period
   - Certificate key usage must be appropriate

2. **Cryptographic Verification**
   - TPM signature must verify using AIK public key
   - Key authorization hash must match extraData in attestation
   - TPMS_ATTEST magic value must be correct (0xff544347)

3. **Public Key Binding**
   - Computed TPM Name of pubArea must match TPMS_CERTIFY_INFO.Name
   - CSR public key must match attested public key from pubArea

4. **Replay Prevention**
   - Each challenge has a unique token
   - Key authorization binds challenge to specific ACME account
   - Attestation validated only once per challenge

### ACME Error Types

Device attestation defines specific error types per draft-acme-device-attest-07:

| Error Type | HTTP Status | Description |
|------------|-------------|-------------|
| `badAttestationStatement` | 400 | The attestation statement is malformed or invalid |
| `unsupportedAttestationFormat` | 501 | The attestation format is not supported |
| `rejectedAttestationFormat` | 403 | The attestation format is not allowed by policy |
| `attestationVerificationFailed` | 403 | The attestation statement verification failed |

### Security Best Practices

#### 1. Configure AK CA Root Certificates

Only trust Privacy CA certificates from authorized sources:

```bash
# Verify certificate fingerprints
openssl x509 -in privacy-ca-root.pem -noout -fingerprint -sha256

# Configure in OpenBao
bao write pki/config/acme/ak-ca-roots/privacy-ca \
  name=privacy-ca \
  certificate=@privacy-ca-root.pem
```

#### 2. Enable AIK Certificate Validation

Always validate in production:

```bash
bao write pki/config/attestation \
  enabled=true \
  validate_ek_certificate=true
```

#### 3. Require Attestation Policies

Enforce enterprise TPM policies:

```bash
bao write pki/roles/ipsec-vpn \
  attestation_policies="2.23.133.8.1,2.23.133.8.3"
```

Common TCG policy OIDs:
- `2.23.133.8.1` - TCG TPM Attestation
- `2.23.133.8.3` - TCG TPM Endorsement

#### 4. Limit Certificate Validity

Use short TTLs and enable rotation:

```bash
bao write pki/roles/ipsec-vpn \
  ttl=720h \      # 30 days
  max_ttl=8760h   # 1 year
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

### Step 2: Configure AK CA Root Certificates

```bash
# Add Privacy CA root certificate
bao write pki/config/acme/ak-ca-roots/privacy-ca \
  name=privacy-ca \
  certificate=@privacy-ca-root.pem

# For dual PKI setups (Privacy CA is another OpenBao mount)
# Export AK CA root from /pki-ak mount
bao read -field=certificate pki-ak/cert/ca > ak-ca-root.pem

# Configure /pki-vpn to trust the AK CA
bao write pki-vpn/config/acme/ak-ca-roots/openbao-ak \
  name=openbao-ak \
  certificate=@ak-ca-root.pem
```

### Step 3: Create Role for Device Certificates

```bash
bao write pki/roles/ipsec-vpn \
  allow_device_attestation=true \
  required_attestation_formats=tpm \
  validate_ek_certificate=true \
  allowed_domains="vpn.example.com" \
  allow_subdomains=true \
  ttl=720h \
  max_ttl=8760h
```

### Step 4: Enable ACME

```bash
bao write pki/config/cluster \
  path="https://bao.example.com/v1/pki" \
  aia_path="https://bao.example.com/v1/pki"

bao write pki/config/acme \
  enabled=true \
  allowed_issuers="*" \
  allowed_roles="*"
```

### Step 5: Verify Configuration

```bash
# Check attestation config
bao read pki/config/attestation

# List AK CA roots
bao list pki/config/acme/ak-ca-roots

# Verify role
bao read pki/roles/ipsec-vpn
```

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

**Solution**: Add AK CA root certificate:
```bash
bao write pki/config/acme/ak-ca-roots/my-ca \
  name=my-ca \
  certificate=@my-ca-root.pem
```

---

**Problem**: "AIK certificate validation is enabled but no trusted AK CA roots are configured"

**Solution**: Configure at least one AK CA root certificate.

---

**Problem**: "permanent identifier not found in certificate"

**Solution**: AIK certificate must include either:
- SAN with OID 1.3.6.1.5.5.7.8.3 (permanentIdentifier)
- URI SAN with `urn:permanent-identifier:` prefix
- Subject DN serialNumber field

### Attestation Validation Issues

**Problem**: "key authorization verification failed"

**Solution**: Client must:
1. Construct key authorization: `token + "." + thumbprint`
2. Compute SHA-256 hash
3. Use hash as extraData in TPM2_Certify

---

**Problem**: "certified object name mismatch"

**Solution**: Verify that:
1. pubArea contains the correct public key
2. TPM2_Certify was called on the correct key
3. pubArea bytes match what was certified

---

**Problem**: "invalid magic value"

**Solution**: The certInfo must start with TPM_GENERATED_VALUE (0xff544347). Ensure using real TPM-generated attestation, not simulated data.

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

## Implementation Files

The device attestation implementation consists of the following files in `builtin/logical/pki/`:

| File | Description |
|------|-------------|
| `path_config_attestation.go` | Global attestation configuration endpoint |
| `path_acme_ak_ca_roots.go` | AK CA root certificate management |
| `acme_attestation.go` | Core attestation types and validation framework |
| `acme_attestation_tpm.go` | TPM 2.0 attestation validator |
| `acme_attestation_aik.go` | AIK certificate chain validation |
| `tpm_structures.go` | TPM 2.0 structure parsing (TPMS_ATTEST, TPMT_PUBLIC, TPMT_SIGNATURE) |
| `acme_cert_extensions.go` | Permanent identifier and hardware module name extensions |
| `acme_challenges.go` | ValidateDeviceAttest01Challenge function |
| `acme_authorizations.go` | ACMEDeviceAttestChallenge type definition |
| `acme_errors.go` | Device attestation error types |
| `path_roles.go` | Role parameters for device attestation |

## References

- [draft-acme-device-attest-07](https://www.ietf.org/archive/id/draft-acme-device-attest-07.txt) - ACME Device Attestation
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html) - ACME Protocol
- [WebAuthn TPM Attestation](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation) - Attestation format
- [TCG TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) - TPM Specification
- [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/resource/tpm-2-0-keys-for-device-identity-and-attestation/) - LAK provisioning
- [RFC 4043](https://www.rfc-editor.org/rfc/rfc4043.html) - Permanent Identifier
- [RFC 4108](https://www.rfc-editor.org/rfc/rfc4108.html) - Hardware Module Name
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) - X.509 Certificate Profile

## Demonstration

A working demonstration of TPM device attestation is available in the `deviceattestpoc/` directory. See `deviceattestpoc/README.md` for setup and usage instructions.

---

**Document Version**: 2.0
**OpenBao Branch**: deviceattest
**Last Updated**: 2025-01-26
