# Security Considerations for TPM Device Attestation

## ⚠️ CRITICAL: Production vs PoC Enrollment

### PoC Implementation (Current)

This PoC demonstrates a **simplified enrollment flow** where:
- Clients send their own TPM EK root CA certificates
- Clients request allowlisting of their permanent identifiers
- Enrollment happens automatically via gRPC

**THIS IS FOR DEMONSTRATION ONLY AND MUST NOT BE USED IN PRODUCTION.**

### Production Implementation (Required)

In a production environment, TPM enrollment **MUST** follow these security practices:

#### 1. Administrator-Only Enrollment

**WHO**: Only authorized administrators with proper credentials and access controls.

**HOW**: Through secure, authenticated administrative interfaces:
- Dedicated admin API with strong authentication (mTLS, OAuth2, OIDC)
- Admin console with MFA and audit logging
- Infrastructure-as-Code (Terraform, Ansible) with proper secret management
- Manual approval workflows for high-security environments

**NEVER**: Allow clients to self-enroll or provide their own trust anchors.

#### 2. Out-of-Band TPM Verification

**Before enrollment**, administrators must verify:

1. **Physical Device Inspection**
   - Verify TPM is genuine hardware (not simulated)
   - Check manufacturer seals and tamper-evident packaging
   - Validate serial numbers match documentation

2. **EK Certificate Validation**
   - Extract EK certificate from the TPM
   - Verify it chains to the manufacturer's published root CA
   - Download manufacturer root CAs from official sources:
     - Intel: https://trustedservices.intel.com/
     - Infineon: https://pki.infineon.com/
     - AMD, Nuvoton, STMicroelectronics: Official manufacturer PKI portals

3. **Permanent Identifier Verification**
   - Extract permanent identifier from AIK certificate during initial attestation
   - Verify it matches expected format for the manufacturer
   - Cross-reference with device inventory management system

#### 3. EK Certificate Validation (Security Default)

**IMPORTANT**: As of this implementation, EK certificate validation is **enabled by default** (`validate_ek_certificate=true`).

**What this means**:
- All TPM attestations MUST have valid EK certificate chains
- EK root CA certificates MUST be configured via `/pki/config/acme/ek-roots/`
- Only TPMs with certificates from trusted manufacturers can attest

**To disable** (NOT RECOMMENDED for production):
- Set `validate_ek_certificate=false` in role or global configuration
- This weakens security by allowing rogue/untrusted TPMs to attest

**Production requirement**: Always keep EK validation enabled and properly configure manufacturer root CAs.

#### 4. Secure Configuration Workflow

```
┌─────────────────┐
│ Admin Portal    │
│ (Authenticated) │
└────────┬────────┘
         │
         │ 1. Admin uploads manufacturer EK root CA (verified offline)
         ▼
┌─────────────────────────┐
│ OpenBao Admin API       │
│ POST /pki/config/       │
│      acme/ek-roots/{mfr}│
└────────┬────────────────┘
         │
         │ 2. Admin allowlists specific TPM permanent ID (from verified device)
         ▼
┌─────────────────────────┐
│ OpenBao Admin API       │
│ POST /pki/roles/{role}  │
│ - allowed_tpm_identifiers│
│ - validate_ek_certificate│
└─────────────────────────┘
```

#### 5. Role-Based Access Control (RBAC)

- **Enrollment Operations**: Restricted to `admin` or `tpm-enrollment` role
- **Certificate Requests**: Allowed for enrolled devices via ACME (unprivileged)
- **Audit Logging**: All enrollment actions logged with admin identity

#### 6. Secure Storage of Trust Anchors

EK Root CA certificates must be:
- Downloaded directly from manufacturer official sources
- Verified using published checksums/signatures
- Stored in secure configuration management (HashiCorp Vault, AWS Secrets Manager)
- Version controlled with approval workflows

## API Security Comparison

### PoC (Current - Insecure)

```go
// Client code (INSECURE - PoC only)
client.EnrollTPM(ctx, &TPMEnrollmentRequest{
    PermanentIdentifier: clientGeneratedID,
    EkRootCaPem:         clientProvidedCA,  // ❌ Client provides own trust anchor
})
```

### Production (Secure)

```go
// Admin code (via authenticated admin API)
adminClient.EnrollTPMDevice(ctx, &AdminEnrollmentRequest{
    DeviceSerialNumber:  "TPM-SN-123456",          // From physical label
    PermanentIdentifier: verifiedPermanentID,      // Extracted during verification
    Manufacturer:        "intel",                   // Pre-configured root CA
    ApprovalTicket:      "SEC-2024-001",           // Change management ticket
})
```

## Implementation Checklist for Production

- [ ] Remove client-initiated enrollment endpoint (`EnrollTPM` RPC)
- [ ] Implement admin-only enrollment API with authentication
- [ ] Add multi-factor authentication (MFA) for admin operations
- [ ] Configure audit logging for all enrollment events
- [ ] Establish offline EK root CA verification process
- [ ] Document manufacturer root CA sources and update procedures
- [ ] Implement device inventory management integration
- [ ] Set up approval workflows for TPM enrollment requests
- [ ] Configure automated alerts for enrollment anomalies
- [ ] Regular audits of allowlisted TPM identifiers

## Attack Scenarios Prevented by Proper Enrollment

### 1. Rogue Device Attack

**PoC Vulnerability**: Attacker creates fake TPM, generates own "root CA", enrolls it.

**Production Defense**: Only pre-verified manufacturer root CAs accepted. Admin must physically verify device.

### 2. Stolen Credentials Attack

**PoC Vulnerability**: Attacker with API access can enroll any device.

**Production Defense**: Admin API requires strong authentication + MFA. Enrollment requires approval workflow.

### 3. Supply Chain Attack

**PoC Vulnerability**: Compromised device could self-enroll with malicious root CA.

**Production Defense**: Root CAs sourced only from verified manufacturer channels. Physical device verification required.

## References

- NIST SP 800-57: Recommendation for Key Management
- TCG PC Client Platform TPM Profile Specification
- Draft ACME Device Attestation: https://datatracker.ietf.org/doc/html/draft-acme-device-attest
- FIPS 140-2/140-3: Security Requirements for Cryptographic Modules

## Support

For production deployment guidance, consult:
- Your organization's security team
- TPM manufacturer technical support
- OpenBao community: https://github.com/openbao/openbao
