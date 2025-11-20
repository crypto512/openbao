// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// SimulatedTPM simulates a TPM 2.0 device for testing
type SimulatedTPM struct {
	aikKey       *rsa.PrivateKey
	aikCert      *x509.Certificate
	rootCA       *x509.Certificate
	rootCAKey    *rsa.PrivateKey
	permanentID  string
	manufacturer string
}

// NewSimulatedTPM creates a new simulated TPM with a complete certificate chain
func NewSimulatedTPM(t *testing.T, permanentID, manufacturer string) *SimulatedTPM {
	// Generate Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   manufacturer + " TPM Root CA",
			Organization: []string{manufacturer},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Generate AIK key and certificate
	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	aikTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "AIK Certificate",
			SerialNumber: permanentID,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	aikCertDER, err := x509.CreateCertificate(rand.Reader, aikTemplate, rootCert, &aikKey.PublicKey, rootKey)
	require.NoError(t, err)

	aikCert, err := x509.ParseCertificate(aikCertDER)
	require.NoError(t, err)

	return &SimulatedTPM{
		aikKey:       aikKey,
		aikCert:      aikCert,
		rootCA:       rootCert,
		rootCAKey:    rootKey,
		permanentID:  permanentID,
		manufacturer: manufacturer,
	}
}

// GenerateAttestation generates a TPM attestation object for the given key authorization
func (s *SimulatedTPM) GenerateAttestation(t *testing.T, keyAuthorization string, certKey *rsa.PublicKey) string {
	// Compute expected qualifying data (SHA-256 of key authorization)
	qualifyingData := ComputeKeyAuthorizationHash(keyAuthorization)

	// Create pubArea for the certified key
	pubArea := s.createPubArea(t, certKey)

	// Create certInfo
	certInfo := s.createCertInfo(t, qualifyingData, pubArea)

	// Sign certInfo with AIK key
	hash := sha256.Sum256(certInfo)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.aikKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	// Build attestation statement
	attStmt := map[string]interface{}{
		"ver":      "2.0",
		"alg":      int64(-257), // RS256
		"x5c":      [][]byte{s.aikCert.Raw},
		"sig":      signature,
		"certInfo": certInfo,
		"pubArea":  pubArea,
	}

	// Build attestation object
	attObj := map[string]interface{}{
		"fmt":     string(AttestationFormatTPM),
		"attStmt": attStmt,
	}

	// Encode to CBOR
	cborBytes, err := cbor.Marshal(attObj)
	require.NoError(t, err)

	// Base64url encode
	return base64.RawURLEncoding.EncodeToString(cborBytes)
}

// createPubArea creates a TPMT_PUBLIC structure for the given RSA public key
func (s *SimulatedTPM) createPubArea(t *testing.T, pubKey *rsa.PublicKey) []byte {
	buf := new(bytes.Buffer)

	// Type (RSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSA))
	// NameAlg (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))
	// ObjectAttributes
	binary.Write(buf, binary.BigEndian, uint32(0x00060472)) // Standard AIK attributes
	// AuthPolicy (empty)
	s.writeTPM2B(buf, nil)
	// RSA Parameters
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_NULL))   // symmetric
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSASSA)) // scheme
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256)) // hash alg
	binary.Write(buf, binary.BigEndian, uint16(2048))           // keyBits
	binary.Write(buf, binary.BigEndian, uint32(65537))          // exponent
	// Unique (RSA modulus)
	s.writeTPM2B(buf, pubKey.N.Bytes())

	return buf.Bytes()
}

// createCertInfo creates a TPMS_ATTEST structure
func (s *SimulatedTPM) createCertInfo(t *testing.T, qualifyingData []byte, pubArea []byte) []byte {
	buf := new(bytes.Buffer)

	// Magic
	binary.Write(buf, binary.BigEndian, uint32(TPM_GENERATED_VALUE))
	// Type
	binary.Write(buf, binary.BigEndian, uint16(TPM_ST_ATTEST_CERTIFY))
	// QualifiedSigner
	s.writeTPM2B(buf, []byte("signer"))
	// ExtraData (this is the key authorization hash!)
	s.writeTPM2B(buf, qualifyingData)
	// ClockInfo
	binary.Write(buf, binary.BigEndian, uint64(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, byte(1))
	// FirmwareVersion
	binary.Write(buf, binary.BigEndian, uint64(0x0001000200030004))

	// TPMS_CERTIFY_INFO
	// Compute the name of the certified object
	pub, err := ParseTPMT_PUBLIC(pubArea)
	require.NoError(t, err)
	name, err := pub.ComputeName(pubArea)
	require.NoError(t, err)

	s.writeTPM2B(buf, name)
	s.writeTPM2B(buf, []byte("qualified-name"))

	return buf.Bytes()
}

// writeTPM2B writes a TPM2B_* structure (2-byte size prefix + data)
func (s *SimulatedTPM) writeTPM2B(w *bytes.Buffer, data []byte) {
	if data == nil {
		binary.Write(w, binary.BigEndian, uint16(0))
		return
	}
	binary.Write(w, binary.BigEndian, uint16(len(data)))
	w.Write(data)
}

// TestACMEDeviceAttestationEndToEnd tests the complete ACME device attestation flow
func TestACMEDeviceAttestationEndToEnd(t *testing.T) {
	b, s := CreateBackendWithStorage(t)

	// Create a root certificate
	resp, err := CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "1h",
		"issuer_name": "root",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data["certificate"])

	// Create a simulated TPM
	tpm := NewSimulatedTPM(t, "TPM-DEVICE-12345", "Test Manufacturer")

	// Note: In a full implementation, attestation configuration would be stored via API endpoints
	// For this integration test, we'll construct the configuration directly

	// In a real test, we would use the ACME client to create an account
	// For this integration test, we simulate the key steps

	t.Log("Step 1: ACME account created (simulated)")

	// Create an order with device-attest-01 challenge
	// The order would specify that device attestation is required
	t.Log("Step 2: Creating ACME order with device-attest-01 challenge")

	// Generate certificate key
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Simulate key authorization (in real ACME this would come from the challenge)
	token := "test-token-12345678901234567890"
	// In real ACME, thumbprint is computed from account key JWK
	thumbprint := "dGVzdC10aHVtYnByaW50MTIzNDU2Nzg5MA" // Simulated
	keyAuthorization := token + "." + thumbprint

	t.Log("Step 3: Generating TPM attestation for key authorization")

	// Generate attestation using simulated TPM
	attestationObject := tpm.GenerateAttestation(t, keyAuthorization, &certKey.PublicKey)

	t.Log("Step 4: Validating attestation object")

	// Parse and validate the attestation
	attObj, err := ParseAttestationObject(attestationObject)
	require.NoError(t, err)
	require.Equal(t, string(AttestationFormatTPM), attObj.Format)

	// Construct validation config directly
	// In a full implementation, this would be loaded from storage
	config := &AttestationValidationConfig{
		ValidateEKCertificate: true,
		EKRootCertificates:    []*x509.Certificate{tpm.rootCA},
		RequiredFormats:       []AttestationFormat{AttestationFormatTPM},
	}

	// Validate the attestation
	validator, err := GetAttestationValidator(AttestationFormatTPM)
	require.NoError(t, err)

	result, err := validator.ValidateAttestation(context.Background(), attObj, keyAuthorization, config)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "TPM-DEVICE-12345", result.PermanentIdentifier)
	require.Equal(t, AttestationFormatTPM, result.Format)

	t.Log("Step 5: Attestation validated successfully")
	t.Log("Step 6: Successfully validated TPM attestation")
	t.Log("  - Verified AIK certificate chain to trusted root")
	t.Log("  - Validated key authorization binding via extraData")
	t.Log("  - Verified certified object name matches public key")
	t.Log("  - Extracted permanent identifier: " + result.PermanentIdentifier)
	t.Log("✓ End-to-end TPM device attestation validation completed successfully")

	// Note: In a full ACME implementation, the permanent identifier would be added
	// to the certificate during issuance. This would require additional integration
	// with the certificate signing process and is beyond the scope of this test.
}

// TestACMEDeviceAttestationEndToEnd_WithIntermediateCA tests attestation with intermediate CA in chain
func TestACMEDeviceAttestationEndToEnd_WithIntermediateCA(t *testing.T) {
	b, s := CreateBackendWithStorage(t)

	// Create a root certificate
	resp, err := CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "1h",
		"issuer_name": "root",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Generate Root CA for TPM manufacturer
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Root CA",
			Organization: []string{"Test Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Generate Intermediate CA
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test TPM Intermediate CA",
			Organization: []string{"Test Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)

	intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
	require.NoError(t, err)

	// Generate AIK certificate signed by intermediate
	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	aikTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "AIK Certificate",
			SerialNumber: "TPM-DEVICE-67890",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	aikCertDER, err := x509.CreateCertificate(rand.Reader, aikTemplate, intermediateCert, &aikKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	aikCert, err := x509.ParseCertificate(aikCertDER)
	require.NoError(t, err)

	// Note: In a full implementation, attestation configuration would be stored via API endpoints
	// For this integration test, we'll construct the configuration directly

	// Generate certificate key
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create key authorization
	keyAuthorization := "test-token.test-thumbprint"

	// Create attestation with intermediate in x5c chain
	qualifyingData := ComputeKeyAuthorizationHash(keyAuthorization)

	// Create pubArea
	pubArea := createTestPubArea(t, &certKey.PublicKey)

	// Create certInfo with proper name
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(TPM_GENERATED_VALUE))
	binary.Write(buf, binary.BigEndian, uint16(TPM_ST_ATTEST_CERTIFY))
	writeTPM2B(buf, []byte("signer"))
	writeTPM2B(buf, qualifyingData)
	binary.Write(buf, binary.BigEndian, uint64(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, byte(1))
	binary.Write(buf, binary.BigEndian, uint64(0x0001000200030004))

	pub, err := ParseTPMT_PUBLIC(pubArea)
	require.NoError(t, err)
	name, err := pub.ComputeName(pubArea)
	require.NoError(t, err)

	writeTPM2B(buf, name)
	writeTPM2B(buf, []byte("qualified-name"))
	certInfo := buf.Bytes()

	// Sign with AIK key
	hash := sha256.Sum256(certInfo)
	signature, err := rsa.SignPKCS1v15(rand.Reader, aikKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	// Build attestation statement with FULL CHAIN (AIK + Intermediate)
	attStmt := map[string]interface{}{
		"ver": "2.0",
		"alg": int64(-257),
		"x5c": [][]byte{
			aikCert.Raw,
			intermediateCert.Raw, // Include intermediate
		},
		"sig":      signature,
		"certInfo": certInfo,
		"pubArea":  pubArea,
	}

	attObj := map[string]interface{}{
		"fmt":     string(AttestationFormatTPM),
		"attStmt": attStmt,
	}

	cborBytes, err := cbor.Marshal(attObj)
	require.NoError(t, err)

	attestationObject := base64.RawURLEncoding.EncodeToString(cborBytes)

	// Parse and validate
	parsedAttObj, err := ParseAttestationObject(attestationObject)
	require.NoError(t, err)

	// Construct validation config directly
	config := &AttestationValidationConfig{
		ValidateEKCertificate: true,
		EKRootCertificates:    []*x509.Certificate{rootCert},
		RequiredFormats:       []AttestationFormat{AttestationFormatTPM},
	}

	validator, err := GetAttestationValidator(AttestationFormatTPM)
	require.NoError(t, err)

	result, err := validator.ValidateAttestation(context.Background(), parsedAttObj, keyAuthorization, config)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "TPM-DEVICE-67890", result.PermanentIdentifier)

	t.Log("✓ Successfully validated TPM attestation with intermediate CA in chain")
}

