// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

// TPMAttestationValidator implements AttestationValidator for TPM 2.0 attestation
type TPMAttestationValidator struct{}

// init registers the TPM validator
func init() {
	RegisterAttestationValidator(AttestationFormatTPM, &TPMAttestationValidator{})
}

// SupportsFormat returns true if this validator supports the given format
func (v *TPMAttestationValidator) SupportsFormat(format AttestationFormat) bool {
	return format == AttestationFormatTPM
}

// ValidateAttestation validates a TPM attestation statement
func (v *TPMAttestationValidator) ValidateAttestation(
	ctx context.Context,
	attObj *AttestationObject,
	keyAuthorization string,
	config *AttestationValidationConfig,
) (*AttestationResult, error) {
	// Verify format is TPM
	if attObj.Format != string(AttestationFormatTPM) {
		return nil, fmt.Errorf("%w: expected format 'tpm', got '%s'", ErrUnsupportedAttestationFormat, attObj.Format)
	}

	// Parse TPM attestation statement
	stmt, err := v.parseTPMAttestationStatement(attObj.AttStatement)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadAttestationStatement, err)
	}

	// Verify TPM version is 2.0
	if stmt.Ver != "2.0" {
		return nil, fmt.Errorf("%w: unsupported TPM version %s (only 2.0 is supported)", ErrBadAttestationStatement, stmt.Ver)
	}

	// Extract AIK certificate from x5c
	if len(stmt.X5c) == 0 {
		return nil, fmt.Errorf("%w: no AIK certificate in attestation statement", ErrBadAttestationStatement)
	}
	aikCert, err := x509.ParseCertificate(stmt.X5c[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse AIK certificate: %v", ErrBadAttestationStatement, err)
	}

	// Validate AIK certificate chain if required
	if config.ValidateEKCertificate {
		if err := validateAIKCertificateChain(stmt.X5c, config.AKCARootCertificates); err != nil {
			return nil, fmt.Errorf("AIK certificate validation failed: %w", err)
		}
	}

	// Parse TPMS_ATTEST from certInfo using go-tpm
	attestData, err := tpm2.DecodeAttestationData(stmt.CertInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
	}

	// Validate magic value (TPM_GENERATED_VALUE = 0xff544347)
	if attestData.Magic != 0xff544347 {
		return nil, fmt.Errorf("invalid magic value: got 0x%x, expected 0xff544347", attestData.Magic)
	}

	// Validate attestation type (TPM_ST_ATTEST_CERTIFY = 0x8017)
	if attestData.Type != tpm2.TagAttestCertify {
		return nil, fmt.Errorf("unsupported attestation type: 0x%x (expected TPM_ST_ATTEST_CERTIFY 0x8017)", attestData.Type)
	}

	// Compute expected qualifying data (SHA-256 of key authorization)
	expectedQualifyingData := ComputeKeyAuthorizationHash(keyAuthorization)

	// Verify extraData matches expected key authorization hash
	if !bytes.Equal([]byte(attestData.ExtraData), expectedQualifyingData) {
		return nil, fmt.Errorf("extraData mismatch: key authorization validation failed (expected %x, got %x)",
			expectedQualifyingData, []byte(attestData.ExtraData))
	}

	// Parse TPMT_PUBLIC from pubArea using go-tpm
	pubKey, err := tpm2.DecodePublic(stmt.PubArea)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPMT_PUBLIC: %w", err)
	}

	// Verify the signature over certInfo using the AIK certificate's public key
	if err := verifyTPMSignature(aikCert, stmt.CertInfo, stmt.Sig); err != nil {
		return nil, fmt.Errorf("TPM signature verification failed: %w", err)
	}

	// Verify that the pubArea matches the certified object
	// The TPMS_CERTIFY_INFO.Name should match the hash of pubArea
	pubAreaName, err := pubKey.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to compute public area name: %w", err)
	}

	// Get the certified name from attestation data
	certifiedName := attestData.AttestedCertifyInfo.Name
	if !bytes.Equal(certifiedName.Digest.Value, pubAreaName.Digest.Value) {
		return nil, fmt.Errorf("certified object name mismatch: public area validation failed (expected name %x, got %x)",
			pubAreaName.Digest.Value, certifiedName.Digest.Value)
	}

	// Extract the attested public key from pubArea using go-tpm
	// Per draft-acme-device-attest-07 Section 5, the server MUST verify
	// that the CSR contains this public key before issuing the certificate
	attestedPublicKey, err := pubKey.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from pubArea: %w", err)
	}

	// Extract permanent identifier from AIK certificate
	permanentID, err := ExtractPermanentIdentifierFromCert(aikCert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract permanent identifier: %w", err)
	}

	// Build result
	result := &AttestationResult{
		PermanentIdentifier: permanentID,
		Format:              AttestationFormatTPM,
		Certificate:         aikCert,
		AttestedPublicKey:   attestedPublicKey,
		Metadata: map[string]interface{}{
			"tpm_version": stmt.Ver,
			"alg":         stmt.Alg,
		},
	}

	// Try to extract hardware module name (optional)
	if hwModuleName, err := ExtractHardwareModuleNameFromCert(aikCert); err == nil {
		result.HardwareModuleName = hwModuleName
	}

	return result, nil
}

// parseTPMAttestationStatement parses a TPM attestation statement from raw map
func (v *TPMAttestationValidator) parseTPMAttestationStatement(attStmt map[string]interface{}) (*TPMAttestationStatement, error) {
	// Convert map to JSON and back to struct for type safety
	jsonBytes, err := json.Marshal(attStmt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation statement: %w", err)
	}

	var stmt TPMAttestationStatement
	if err := json.Unmarshal(jsonBytes, &stmt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TPM attestation statement: %w", err)
	}

	// Validate required fields
	if stmt.Ver == "" {
		return nil, fmt.Errorf("missing 'ver' field in TPM attestation statement")
	}
	if len(stmt.X5c) == 0 {
		return nil, fmt.Errorf("missing 'x5c' field in TPM attestation statement")
	}
	if len(stmt.Sig) == 0 {
		return nil, fmt.Errorf("missing 'sig' field in TPM attestation statement")
	}
	if len(stmt.CertInfo) == 0 {
		return nil, fmt.Errorf("missing 'certInfo' field in TPM attestation statement")
	}
	if len(stmt.PubArea) == 0 {
		return nil, fmt.Errorf("missing 'pubArea' field in TPM attestation statement")
	}

	return &stmt, nil
}

// verifyTPMSignature verifies a TPM signature over certInfo using the AIK certificate.
//
// Per draft-acme-device-attest-07 Section 5.1, the sig field in TPM attestation
// statements MUST contain a TPMT_SIGNATURE structure (TPM 2.0 Part 2, Section 11.3.4):
//   - sigAlg (2 bytes) - the signature algorithm
//   - signature union containing hash algorithm and actual signature bytes
func verifyTPMSignature(aikCert *x509.Certificate, certInfo []byte, signature []byte) error {
	// Parse TPMT_SIGNATURE using go-tpm
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(signature))
	if err != nil {
		return fmt.Errorf("failed to parse TPMT_SIGNATURE: %w", err)
	}

	// Verify signature based on algorithm and public key type
	switch pub := aikCert.PublicKey.(type) {
	case *rsa.PublicKey:
		// Handle RSA signatures (RSASSA and RSAPSS)
		if sig.RSA == nil {
			return fmt.Errorf("RSA signature expected but not present in TPMT_SIGNATURE")
		}
		hashAlg, err := sig.RSA.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("unsupported hash algorithm: %w", err)
		}
		if !hashAlg.Available() {
			return fmt.Errorf("hash algorithm not available: %v", hashAlg)
		}
		h := hashAlg.New()
		h.Write(certInfo)
		digest := h.Sum(nil)

		if sig.Alg == tpm2.AlgRSAPSS {
			return rsa.VerifyPSS(pub, hashAlg, digest, sig.RSA.Signature, nil)
		}
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig.RSA.Signature)

	case *ecdsa.PublicKey:
		// Handle ECDSA signatures
		if sig.ECC == nil {
			return fmt.Errorf("ECDSA signature expected but not present in TPMT_SIGNATURE")
		}
		hashAlg, err := sig.ECC.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("unsupported hash algorithm: %w", err)
		}
		if !hashAlg.Available() {
			return fmt.Errorf("hash algorithm not available: %v", hashAlg)
		}
		h := hashAlg.New()
		h.Write(certInfo)
		digest := h.Sum(nil)

		if !ecdsa.Verify(pub, digest, sig.ECC.R, sig.ECC.S) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

