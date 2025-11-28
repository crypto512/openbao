# ACME Device-Attest-01 Compliance Analysis

This document analyzes the OpenBao device attestation implementation against
[draft-ietf-acme-device-attest-07](https://datatracker.ietf.org/doc/draft-acme-device-attest/)
and related RFCs/standards.

## Draft Specification Summary

### Key Requirements from draft-acme-device-attest-07

| Requirement | Category | Description |
|-------------|----------|-------------|
| Token entropy | MUST | >= 128 bits, base64url, no padding |
| Key export | MUST | Hardware module keys cannot be exported |
| WebAuthn Section 6 verification | MUST | Server performs attestation verification |
| CSR extension | MUST | Hardware module must appear in extensionRequest |
| authData field | SHOULD | Omit from attestation object |
| New error type | MUST | `badAttestationStatement` |
| Identifier types | NEW | `permanent-identifier`, `hardware-module` |

### Identifier Types (Section 4)

The draft defines two new ACME identifier types:

1. **permanent-identifier**: Binds certificate to a specific device via RFC 4043
2. **hardware-module**: Binds certificate to a hardware security module via RFC 4108

### Challenge Type (Section 5)

The `device-attest-01` challenge requires:
- Client submits attestation object with `attObj` field
- Server validates attestation per WebAuthn Section 6 (adapted)
- Key authorization hash in attestation extraData
- Public key in CSR must match attested key

---

## Component Analysis

### 1. OpenBao ACME Implementation

**Location**: `builtin/logical/pki/`

#### Conformant Implementations

| Feature | File | Status |
|---------|------|--------|
| `device-attest-01` challenge type | `acme_authorizations.go:972-980` | PASS |
| `permanent-identifier` identifier type | `path_acme_order.go:1127-1134` | PASS |
| `hardware-module` identifier type | `path_acme_order.go:1136-1144` | PASS |
| TPM attestation format (`tpm`) | `acme_attestation.go:23` | PASS |
| Attestation object CBOR parsing | `acme_attestation.go:115-130` | PASS |
| Key authorization hash verification | `acme_attestation.go:132-137` | PASS |
| TPM 2.0 TPMS_ATTEST parsing | `tpm_structures.go:200-265` | PASS |
| TPMT_PUBLIC parsing | `tpm_structures.go:282-346` | PASS |
| Signature verification (RSA/ECDSA) | `acme_attestation_tpm.go:176-239` | PASS |
| AIK certificate chain validation | `acme_attestation_aik.go:21-73` | PASS |
| Permanent identifier extraction | `acme_cert_extensions.go:204-243` | PASS |
| Hardware module extraction | `acme_cert_extensions.go:314-401` | PASS |
| `badAttestationStatement` error | `acme_errors.go:53` | PASS |
| CSR public key validation | `path_acme_order.go:389-406` | PASS |

#### Gaps and Missing Features

| Gap | Specification Reference | Status | Priority |
|-----|-------------------------|--------|----------|
| `authData` field validation | Section 5: "SHOULD be omitted" | MISSING | HIGH |
| Multiple attestation formats | WebAuthn registry | PARTIAL | MEDIUM |
| `externalAccountBinding` | Section 4: "RECOMMENDED" | OPTIONAL | LOW |
| Device-specific revocation | Section 6 | MISSING | LOW |

---

### 2. gRPC Server Component

**Location**: `deviceattestpoc/server/`

#### Conformant Implementations

| Feature | File | Status |
|---------|------|--------|
| TCG credential activation | `main.go:206-234` | PASS |
| EK certificate validation | `main.go:368-391` | PASS |
| LAK certificate issuance | `main.go:279-300` | PASS |
| ACME order creation | `openbao_client.go:171-200` | PASS |
| Attestation submission | `openbao_client.go:294-321` | PASS |
| Account persistence | `acme_accounts.go` | PASS |

#### Gaps and Missing Features

| Gap | Impact | Priority |
|-----|--------|----------|
| In-memory activation sessions | Sessions lost on restart | MEDIUM |
| No device allowlist persistence | Memory-only device registry | MEDIUM |
| No rate limiting | DoS vulnerability | MEDIUM |
| No audit logging | Compliance gap | LOW |

---

### 3. Client Component

**Location**: `deviceattestpoc/client/`

#### Conformant Implementations

| Feature | File | Status |
|---------|------|--------|
| TPM 2.0 key operations | `tpm_client.go:180-249` | PASS |
| TPM2_Certify for attestation | `tpm_client.go:621-681` | PASS |
| TPMT_PUBLIC construction | `tpm_client.go:683-718` | PASS |
| CBOR attestation object | `tpm_client.go:666-680` | PASS |
| Key authorization hash | `tpm_client.go:632-634` | PASS |
| TPM key persistence | `tpm_blob_storage.go` | PASS |
| Non-restricted signing keys | `tpm_client.go:504-519` | PASS |

#### Gaps and Missing Features

| Gap | Impact | Priority |
|-----|--------|----------|
| `authData` included in attestation | Per spec SHOULD be omitted | HIGH |
| No ECC key support for cert keys | Limited algorithm choice | MEDIUM |
| No key attestation for cert keys | Reduced security | LOW |

---

## Specification Compliance Matrix

| Requirement | OpenBao | Server | Client | Overall |
|-------------|---------|--------|--------|---------|
| permanent-identifier type | PASS | PASS | PASS | PASS |
| hardware-module type | PASS | PARTIAL | PARTIAL | PARTIAL |
| device-attest-01 challenge | PASS | PASS | PASS | PASS |
| Token >= 128 bits entropy | PASS | N/A | N/A | PASS |
| attObj field in response | PASS | PASS | PASS | PASS |
| WebAuthn attestation format | PASS | N/A | PASS | PASS |
| TPM certInfo validation | PASS | N/A | N/A | PASS |
| pubArea name verification | PASS | N/A | N/A | PASS |
| CSR public key binding | PASS | N/A | PASS | PASS |
| authData SHOULD be omitted | MISSING | N/A | FAIL | FAIL |
| badAttestationStatement error | PASS | N/A | N/A | PASS |
| AIK chain validation | PASS | PASS | N/A | PASS |

---

## Proposed Evolutions

### Phase 1: Compliance Fixes (High Priority)

1. **Remove authData from client attestation object**
   - File: `deviceattestpoc/client/tpm_client.go:669`
   - Change: Remove `authData` field from attestation object
   - Rationale: Per Section 5, "authData field is unused and SHOULD be omitted"

2. **Validate authData absence in OpenBao**
   - File: `builtin/logical/pki/acme_attestation.go`
   - Change: Warn or reject attestation objects with non-empty `authData`
   - Rationale: Enforce specification compliance

3. **Complete hardware-module identifier end-to-end**
   - Ensure server and client support hardware-module type
   - Add hardware module extension to issued certificates

### Phase 2: Security Enhancements (Medium Priority)

4. **Add multiple attestation format support**
   - Implement `android-key` validator
   - Implement `apple` attestation validator
   - Add format negotiation in challenge

5. **Implement device registry**
   - Persistent device allowlist/blocklist
   - Device status tracking (enrolled, revoked, suspended)
   - Migration from in-memory to persistent storage

6. **Add rate limiting**
   - Enrollment endpoint rate limits
   - Per-device and global limits

### Phase 3: Enterprise Features (Lower Priority)

7. **External Account Binding support**
   - Require EAB for enterprise deployments
   - Link ACME accounts to device identifiers

8. **Device-specific revocation**
   - Revoke all certificates for a device
   - Support revocation by permanent identifier

9. **Attestation policy engine**
   - Configurable policies (manufacturer allowlist, firmware versions)
   - Policy OID enforcement

### Phase 4: Protocol Evolution

10. **RATS attestation format support**
    - Align with draft-ietf-rats-tpm-based-network-device-attest
    - Support for network device attestation workflows

11. **Pre-authorization support**
    - Device pre-registration before certificate request
    - Background authorization validation

---

## Related Standards

| Standard | Relevance |
|----------|-----------|
| [RFC 4043](https://datatracker.ietf.org/doc/html/rfc4043) | Permanent Identifier format |
| [RFC 4108](https://datatracker.ietf.org/doc/html/rfc4108) | Hardware Module Name |
| [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) | ACME protocol |
| [WebAuthn L2](https://www.w3.org/TR/webauthn-2/) | Attestation statement format |
| [TPM 2.0 Part 2](https://trustedcomputinggroup.org/resource/tpm-library-specification/) | TPM structures |
| [draft-ietf-rats-tpm-based-network-device-attest](https://datatracker.ietf.org/doc/draft-ietf-rats-tpm-based-network-device-attest/) | Network device RIV |

---

## Summary

The implementation provides a solid foundation for ACME device attestation with TPM 2.0 support.
The core flow (order -> challenge -> attestation -> certificate) is fully functional and largely
conformant with draft-acme-device-attest-07.

**Key Strengths:**
- Complete TPM 2.0 attestation validation pipeline
- Proper TPM2_Certify flow with pubArea/certInfo verification
- AIK certificate chain validation
- Public key binding between attestation and CSR

**Priority Fixes Required:**
1. Remove `authData` from client attestation object
2. Validate `authData` absence in server (warning/rejection)
3. Complete hardware-module identifier support end-to-end

---

*Document generated: 2025-01-28*
*Draft version analyzed: draft-ietf-acme-device-attest-07*
