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
| Multiple attestation formats | WebAuthn registry | PARTIAL | MEDIUM |
| `externalAccountBinding` | Section 4: "RECOMMENDED" | OPTIONAL | LOW |
| Device-specific revocation | Section 6 | PARTIAL | LOW |

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
| No rate limiting | DoS vulnerability | MEDIUM |

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
| No ECC key support for cert keys | Limited algorithm choice | LOW |

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
| authData SHOULD be omitted | PASS | N/A | PASS | PASS |
| badAttestationStatement error | PASS | N/A | N/A | PASS |
| AIK chain validation | PASS | PASS | N/A | PASS |

---

## Proposed Evolutions

### Phase 1: Security Enhancements (Medium Priority)

1. **Add multiple attestation format support**
   - Implement `android-key` validator
   - Implement `apple` attestation validator
   - Add format negotiation in challenge

2. **Add rate limiting**
   - Enrollment endpoint rate limits
   - Per-device and global limits

3. **Complete hardware-module identifier end-to-end**
   - Ensure server and client support hardware-module type
   - Add hardware module extension to issued certificates

### Phase 2: Enterprise Features (Lower Priority)

4. **External Account Binding support**
   - Require EAB for enterprise deployments
   - Link ACME accounts to device identifiers

5. **Device-specific revocation**
   - Revoke all certificates for a device
   - Support revocation by permanent identifier

6. **Attestation policy engine**
   - Configurable policies (manufacturer allowlist, firmware versions)
   - Policy OID enforcement

### Phase 3: Protocol Evolution

7. **RATS attestation format support**
    - Align with draft-ietf-rats-tpm-based-network-device-attest
    - Support for network device attestation workflows

8. **Pre-authorization support**
    - Device pre-registration before certificate request
    - Background authorization validation

---

## TCG LAK/IAK Compliance Analysis

This section analyzes compliance with [TCG TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf).

### AK (Attestation Key) Attributes

| Requirement | TCG Spec | Implementation | Status |
|-------------|----------|----------------|--------|
| Key Type | RSA or ECC | RSA 2048-bit | PASS |
| NameAlg | SHA-256 or SHA-384 | SHA-256 | PASS |
| Restricted | MUST be set | `FlagRestricted` | PASS |
| FixedTPM | MUST be set | `FlagFixedTPM` | PASS |
| FixedParent | MUST be set | `FlagFixedParent` | PASS |
| SensitiveDataOrigin | MUST be set | `FlagSensitiveDataOrigin` | PASS |
| Sign | MUST be set | `FlagSignerDefault` | PASS |
| Signing Scheme | RSASSA or RSAPSS | RSASSA (SHA-256) | PASS |

**Implementation**: `client/tpm_client.go:211-226` (akTemplate)

### LAK Certificate Properties

| Requirement | TCG Spec | Implementation | Status |
|-------------|----------|----------------|--------|
| Key Usage | `digitalSignature` only (Critical) | `DigitalSignature` | PASS |
| Extended Key Usage | `tcg-kp-AttestationKey` (2.23.133.8.3) | OID 2.23.133.8.3 | PASS |
| Basic Constraints | CA:FALSE (Critical) | `basic_constraints_valid_for_non_ca: true` | PASS |
| Subject | Empty or pseudonymous | Empty (SAN-only) | PASS |
| SAN URI | Permanent identifier | `urn:permanent-identifier:<EK-hash>` | PASS |

**Implementation**:
- PKI role: `scripts/init-openbao.sh:166-172`
- CSR generation: `server/main.go:394`
- Certificate issuance: `server/openbao_client.go:444-449`

### MakeCredential / ActivateCredential Flow

| Step | TCG Requirement | Implementation | Status |
|------|-----------------|----------------|--------|
| EK Validation | Verify EK cert chain to manufacturer CA | `validateEKCertificate()` | PASS |
| EK Public Key | Extract from cert or TPM | Both supported | PASS |
| AK Public Area | Send TPMT_PUBLIC to server | `GetAKActivationData()` | PASS |
| MakeCredential | Server creates encrypted credential | `MakeCredential()` via go-attestation | PASS |
| ActivateCredential | TPM decrypts using EK | `ActivateCredentialChallenge()` | PASS |
| Secret Verification | Compare decrypted secret | Constant-length comparison | PASS |
| Session Management | Time-limited session | 5-minute TTL | PASS |

**Implementation**: `server/main.go:206-370`, `client/tpm_client.go:419-483`

### Agent Key (Cert Key) Attributes

| Requirement | TCG/WebAuthn | Implementation | Status |
|-------------|--------------|----------------|--------|
| Non-Restricted | MUST NOT be restricted | No `FlagRestricted` | PASS |
| FixedTPM | MUST be set | `FlagFixedTPM` | PASS |
| FixedParent | MUST be set | `FlagFixedParent` | PASS |
| SensitiveDataOrigin | MUST be set | `FlagSensitiveDataOrigin` | PASS |
| Sign | MUST be set | `FlagSign` | PASS |
| Scheme | NULL (flexible) | `AlgNull` | PASS |

**Implementation**: `client/tpm_client.go:536-550` (certKeyTemplate)

### TPM2_Certify Attestation

| Requirement | WebAuthn/TCG | Implementation | Status |
|-------------|--------------|----------------|--------|
| Magic value | `0xff544347` (TPM_GENERATED) | Verified by OpenBao | PASS |
| Type | `TPM_ST_ATTEST_CERTIFY` | Verified by OpenBao | PASS |
| extraData | SHA-256(keyAuthorization) | `sha256.Sum256(keyAuthorization)` | PASS |
| Attested Name | Hash of pubArea | Verified by OpenBao | PASS |
| Signature | AK signs certInfo | RSASSA-SHA256 | PASS |

**Implementation**: `client/tpm_client.go:652-712`

### TCG Compliance Summary

The implementation is **fully compliant** with TCG TPM 2.0 Keys for Device Identity and Attestation:

- ✅ AK has correct restricted signing key attributes
- ✅ LAK certificate has correct key usage and EKU OID
- ✅ MakeCredential/ActivateCredential flow per TCG Credential Profiles
- ✅ Agent key is non-restricted but hardware-bound (FixedTPM)
- ✅ TPM2_Certify provides attestation of key properties
- ✅ Permanent identifier in SAN binds certificate to device

---

## Related Standards

| Standard | Relevance |
|----------|-----------|
| [TCG TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf) | LAK/IAK certificate and key requirements |
| [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf) | EK certificate validation |
| [TCG OID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00_pub-1.pdf) | OID 2.23.133.8.3 (tcg-kp-AttestationKey) |
| [RFC 4043](https://datatracker.ietf.org/doc/html/rfc4043) | Permanent Identifier format |
| [RFC 4108](https://datatracker.ietf.org/doc/html/rfc4108) | Hardware Module Name |
| [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) | ACME protocol |
| [WebAuthn L2](https://www.w3.org/TR/webauthn-2/) | Attestation statement format (TPM) |
| [TPM 2.0 Part 2](https://trustedcomputinggroup.org/resource/tpm-library-specification/) | TPM structures (TPMS_ATTEST, TPMT_PUBLIC) |
| [draft-ietf-acme-device-attest-07](https://datatracker.ietf.org/doc/draft-acme-device-attest/) | ACME device-attest-01 challenge |
| [draft-ietf-rats-tpm-based-network-device-attest](https://datatracker.ietf.org/doc/draft-ietf-rats-tpm-based-network-device-attest/) | Network device RIV |

---

## Summary

The implementation provides a solid foundation for ACME device attestation with TPM 2.0 support.
The core flow (order -> challenge -> attestation -> certificate) is fully functional and largely
conformant with draft-acme-device-attest-07 and TCG specifications.

**TCG Compliance:**
- ✅ AK attributes per TCG TPM 2.0 Keys for Device Identity spec
- ✅ LAK certificate with correct Key Usage and EKU (OID 2.23.133.8.3)
- ✅ MakeCredential/ActivateCredential per TCG Credential Profiles
- ✅ EK certificate validation against manufacturer CAs
- ✅ Permanent identifier in SAN URI format

**ACME device-attest-01 Compliance:**
- ✅ Complete TPM 2.0 attestation validation pipeline
- ✅ Proper TPM2_Certify flow with pubArea/certInfo verification
- ✅ AIK/LAK certificate chain validation
- ✅ Public key binding between attestation and CSR
- ✅ Key authorization hash in extraData

**WebAuthn TPM Attestation Compliance:**
- ✅ Attestation object format (CBOR encoded)
- ✅ certInfo (TPMS_ATTEST) structure
- ✅ pubArea (TPMT_PUBLIC) structure
- ✅ Signature verification
- ✅ authData field correctly omitted

**Remaining Work:**
1. Complete hardware-module identifier support end-to-end
2. Add rate limiting for enrollment endpoints
3. Multiple attestation format support (android-key, apple)

---

*Document updated: 2025-12-01*
*Standards analyzed: draft-ietf-acme-device-attest-07, TCG TPM 2.0 Keys for Device Identity v1.0*
