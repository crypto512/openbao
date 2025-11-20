// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
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

	// Parse TPMS_ATTEST from certInfo
	attestData, err := ParseTPMS_ATTEST(stmt.CertInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
	}

	// Compute expected qualifying data (SHA-256 of key authorization)
	expectedQualifyingData := ComputeKeyAuthorizationHash(keyAuthorization)

	// Verify extraData matches expected key authorization hash
	if !bytesEqual(attestData.ExtraData, expectedQualifyingData) {
		return nil, fmt.Errorf("extraData mismatch: key authorization validation failed (expected %x, got %x)",
			expectedQualifyingData, attestData.ExtraData)
	}

	// Parse TPMT_PUBLIC from pubArea
	pubKey, err := ParseTPMT_PUBLIC(stmt.PubArea)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPMT_PUBLIC: %w", err)
	}

	// Verify the signature over certInfo using the AIK certificate's public key
	if err := verifyTPMSignature(aikCert, stmt.CertInfo, stmt.Sig, stmt.Alg); err != nil {
		return nil, fmt.Errorf("TPM signature verification failed: %w", err)
	}

	// Verify that the pubArea matches the certified object
	// The TPMS_CERTIFY_INFO.Name should match the hash of pubArea
	pubAreaName, err := pubKey.ComputeName(stmt.PubArea)
	if err != nil {
		return nil, fmt.Errorf("failed to compute public area name: %w", err)
	}
	if !bytesEqual(attestData.AttestedCertify.Name, pubAreaName) {
		return nil, fmt.Errorf("certified object name mismatch: public area validation failed (expected name %x, got %x)",
			pubAreaName, attestData.AttestedCertify.Name)
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

// coseAlgToHashAlg converts a COSE algorithm identifier to a crypto.Hash
// COSE Algorithm Registry: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
func coseAlgToHashAlg(alg int64) (crypto.Hash, error) {
	switch alg {
	case -257: // RS256
		return crypto.SHA256, nil
	case -258: // RS384
		return crypto.SHA384, nil
	case -259: // RS512
		return crypto.SHA512, nil
	case -7: // ES256
		return crypto.SHA256, nil
	case -35: // ES384
		return crypto.SHA384, nil
	case -36: // ES512
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported COSE algorithm identifier: %d", alg)
	}
}

// verifyTPMSignature verifies a TPM signature over certInfo using the AIK certificate
func verifyTPMSignature(aikCert *x509.Certificate, certInfo []byte, signature []byte, coseAlg int64) error {
	// Get the hash algorithm from COSE algorithm identifier
	hashAlg, err := coseAlgToHashAlg(coseAlg)
	if err != nil {
		return err
	}

	// Hash the certInfo
	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm: %v", hashAlg)
	}
	h.Write(certInfo)
	digest := h.Sum(nil)

	// Verify signature based on public key type
	switch pub := aikCert.PublicKey.(type) {
	case *rsa.PublicKey:
		// RSA signature verification
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, signature)

	case *ecdsa.PublicKey:
		// ECDSA signature verification
		// ECDSA signature in TPM format is r || s (concatenated)
		if len(signature)%2 != 0 {
			return fmt.Errorf("invalid ECDSA signature length: %d", len(signature))
		}
		r := new(big.Int).SetBytes(signature[:len(signature)/2])
		s := new(big.Int).SetBytes(signature[len(signature)/2:])

		if !ecdsa.Verify(pub, digest, r, s) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// bytesEqual compares two byte slices in constant time
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

