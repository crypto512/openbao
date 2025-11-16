// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// AttestationFormat represents the attestation statement format
type AttestationFormat string

const (
	// AttestationFormatTPM represents TPM 2.0 attestation format
	AttestationFormatTPM AttestationFormat = "tpm"
	// AttestationFormatAndroidKey represents Android Key Attestation format
	AttestationFormatAndroidKey AttestationFormat = "android-key"
	// AttestationFormatApple represents Apple Device Attestation format
	AttestationFormatApple AttestationFormat = "apple"
	// AttestationFormatChromeOS represents Chrome OS Verified Access format
	AttestationFormatChromeOS AttestationFormat = "chromeos"
)

// AttestationObject represents a WebAuthn-style attestation object
// as defined in draft-acme-device-attest-07
type AttestationObject struct {
	// Format identifier for the attestation statement
	Format string `json:"fmt" cbor:"fmt"`
	// AttStatement contains the attestation statement
	AttStatement map[string]interface{} `json:"attStmt" cbor:"attStmt"`
}

// TPMAttestationStatement represents a TPM attestation statement
// Format reference: https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
type TPMAttestationStatement struct {
	// Ver is the TPM version (e.g., "2.0")
	Ver string `json:"ver"`
	// Alg is the COSEAlgorithmIdentifier for the signature algorithm
	// -257 = RS256, -258 = RS384, -259 = RS512
	Alg int64 `json:"alg"`
	// X5c is the AIK certificate chain (DER-encoded)
	X5c [][]byte `json:"x5c"`
	// Sig is the signature over certInfo
	Sig []byte `json:"sig"`
	// CertInfo is the TPMS_ATTEST structure
	CertInfo []byte `json:"certInfo"`
	// PubArea is the TPMT_PUBLIC structure
	PubArea []byte `json:"pubArea"`
}

// AttestationValidator defines the interface for validating attestation statements
type AttestationValidator interface {
	// ValidateAttestation validates an attestation statement and returns the permanent identifier
	ValidateAttestation(ctx context.Context, attObj *AttestationObject, keyAuthorization string, config *AttestationValidationConfig) (*AttestationResult, error)

	// SupportsFormat returns true if this validator supports the given format
	SupportsFormat(format AttestationFormat) bool
}

// AttestationValidationConfig contains configuration for attestation validation
type AttestationValidationConfig struct {
	// RequiredFormats lists the acceptable attestation formats
	RequiredFormats []AttestationFormat
	// ValidateEKCertificate enables EK certificate chain validation
	ValidateEKCertificate bool
	// EKRootCertificates contains trusted manufacturer CA certificates
	EKRootCertificates []*x509.Certificate
	// AllowedPolicyOIDs lists acceptable policy OIDs in certificates
	AllowedPolicyOIDs []string
	// AllowedTPMIdentifiers lists the allowed TPM permanent identifiers
	AllowedTPMIdentifiers []string
	// BlockedTPMIdentifiers lists the blocked TPM permanent identifiers
	BlockedTPMIdentifiers []string
}

// AttestationResult contains the result of attestation validation
type AttestationResult struct {
	// PermanentIdentifier is the device's permanent identifier
	PermanentIdentifier string
	// HardwareModuleName is the hardware module identifier (optional)
	HardwareModuleName string
	// Format is the attestation format used
	Format AttestationFormat
	// Certificate is the attestation key certificate
	Certificate *x509.Certificate
	// Metadata contains format-specific metadata
	Metadata map[string]interface{}
}

// attestationValidatorRegistry holds registered attestation validators
var attestationValidatorRegistry = make(map[AttestationFormat]AttestationValidator)

// RegisterAttestationValidator registers a validator for a specific format
func RegisterAttestationValidator(format AttestationFormat, validator AttestationValidator) {
	attestationValidatorRegistry[format] = validator
}

// GetAttestationValidator retrieves a validator for the given format
func GetAttestationValidator(format AttestationFormat) (AttestationValidator, error) {
	validator, ok := attestationValidatorRegistry[format]
	if !ok {
		return nil, fmt.Errorf("no validator registered for attestation format: %s", format)
	}
	return validator, nil
}

// ParseAttestationObject decodes a base64url-encoded CBOR attestation object
func ParseAttestationObject(attObjB64 string) (*AttestationObject, error) {
	// Decode base64url
	attObjBytes, err := base64.RawURLEncoding.DecodeString(attObjB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode attestation object: %w", err)
	}

	// Decode CBOR
	var attObj AttestationObject
	if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR attestation object: %w", err)
	}

	return &attObj, nil
}

// ComputeKeyAuthorizationHash computes SHA-256 hash of the key authorization
// This is used as qualifying data in TPM attestation
func ComputeKeyAuthorizationHash(keyAuthorization string) []byte {
	hash := sha256.Sum256([]byte(keyAuthorization))
	return hash[:]
}

// ExtractPermanentIdentifierFromCert extracts the permanent identifier from a certificate
// Permanent identifiers can be in Subject DN or SAN extension (OID 1.3.6.1.5.5.7.8.3)
func ExtractPermanentIdentifierFromCert(cert *x509.Certificate) (string, error) {
	// Use the complete implementation from acme_cert_extensions.go
	return ParsePermanentIdentifierFromCert(cert)
}

// ExtractHardwareModuleNameFromCert extracts the hardware module name from a certificate
// Hardware module names are in SAN extension (OID 1.3.6.1.5.5.7.8.4)
func ExtractHardwareModuleNameFromCert(cert *x509.Certificate) (string, error) {
	// Use the complete implementation from acme_cert_extensions.go
	return ParseHardwareModuleNameFromCert(cert)
}

// LoadAttestationValidationConfig loads attestation configuration from role entry
func LoadAttestationValidationConfig(b *backend, s logical.Storage, ctx context.Context, roleName string) (*AttestationValidationConfig, error) {
	role, err := b.getRole(ctx, s, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to load role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role not found: %s", roleName)
	}

	config := &AttestationValidationConfig{
		RequiredFormats:       make([]AttestationFormat, 0),
		ValidateEKCertificate: role.ValidateEKCertificate,
		EKRootCertificates:    make([]*x509.Certificate, 0),
		AllowedPolicyOIDs:     role.AttestationPolicies,
		AllowedTPMIdentifiers: role.AllowedTPMIdentifiers,
		BlockedTPMIdentifiers: role.BlockedTPMIdentifiers,
	}

	// Parse required attestation formats
	for _, formatStr := range role.RequiredAttestationFormats {
		config.RequiredFormats = append(config.RequiredFormats, AttestationFormat(formatStr))
	}

	// Load EK root certificates if validation is enabled
	if config.ValidateEKCertificate {
		ekRoots, err := loadEKRootCertificates(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("failed to load EK root certificates: %w", err)
		}
		config.EKRootCertificates = ekRoots
	}

	return config, nil
}

// loadEKRootCertificates loads trusted EK root CA certificates from storage
func loadEKRootCertificates(ctx context.Context, s logical.Storage) ([]*x509.Certificate, error) {
	// Use the loadAllEkRootCertificates function from path_acme_ek_roots.go
	return loadAllEkRootCertificates(ctx, s)
}
