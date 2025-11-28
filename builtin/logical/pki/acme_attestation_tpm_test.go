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
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

// TPM 2.0 constants for testing (matching go-tpm values)
const (
	testTPMGeneratedValue  = 0xff544347
	testTPMSTAttestCertify = 0x8017
)

func TestTPMAttestationValidator_SupportsFormat(t *testing.T) {
	validator := &TPMAttestationValidator{}

	require.True(t, validator.SupportsFormat(AttestationFormatTPM))
	require.False(t, validator.SupportsFormat(AttestationFormatAndroidKey))
	require.False(t, validator.SupportsFormat(AttestationFormat("unknown")))
}

func TestTPMAttestationValidator_ParseTPMAttestationStatement(t *testing.T) {
	validator := &TPMAttestationValidator{}

	// Create a valid TPM attestation statement
	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	aikCert := createTestAIKCertificate(t, aikKey, "test-device-123")

	attStmt := map[string]interface{}{
		"ver": "2.0",
		"alg": int64(-257), // RS256
		"x5c": [][]byte{aikCert.Raw},
		"sig": []byte("test-signature"),
		"certInfo": createTestCertInfo(t, []byte("test-extra-data")),
		"pubArea":  createTestPubArea(t, &aikKey.PublicKey),
	}

	// Parse
	stmt, err := validator.parseTPMAttestationStatement(attStmt)
	require.NoError(t, err)
	require.NotNil(t, stmt)
	require.Equal(t, "2.0", stmt.Ver)
	require.Equal(t, int64(-257), stmt.Alg)
	require.Len(t, stmt.X5c, 1)
	require.NotEmpty(t, stmt.Sig)
	require.NotEmpty(t, stmt.CertInfo)
	require.NotEmpty(t, stmt.PubArea)
}

func TestTPMAttestationValidator_ParseTPMAttestationStatement_MissingFields(t *testing.T) {
	validator := &TPMAttestationValidator{}

	tests := []struct {
		name        string
		attStmt     map[string]interface{}
		errContains string
	}{
		{
			name: "missing ver",
			attStmt: map[string]interface{}{
				"alg":      int64(-257),
				"x5c":      [][]byte{[]byte("cert")},
				"sig":      []byte("sig"),
				"certInfo": []byte("certInfo"),
				"pubArea":  []byte("pubArea"),
			},
			errContains: "missing 'ver' field",
		},
		{
			name: "missing x5c",
			attStmt: map[string]interface{}{
				"ver":      "2.0",
				"alg":      int64(-257),
				"sig":      []byte("sig"),
				"certInfo": []byte("certInfo"),
				"pubArea":  []byte("pubArea"),
			},
			errContains: "missing 'x5c' field",
		},
		{
			name: "missing sig",
			attStmt: map[string]interface{}{
				"ver":      "2.0",
				"alg":      int64(-257),
				"x5c":      [][]byte{[]byte("cert")},
				"certInfo": []byte("certInfo"),
				"pubArea":  []byte("pubArea"),
			},
			errContains: "missing 'sig' field",
		},
		{
			name: "missing certInfo",
			attStmt: map[string]interface{}{
				"ver":     "2.0",
				"alg":     int64(-257),
				"x5c":     [][]byte{[]byte("cert")},
				"sig":     []byte("sig"),
				"pubArea": []byte("pubArea"),
			},
			errContains: "missing 'certInfo' field",
		},
		{
			name: "missing pubArea",
			attStmt: map[string]interface{}{
				"ver":      "2.0",
				"alg":      int64(-257),
				"x5c":      [][]byte{[]byte("cert")},
				"sig":      []byte("sig"),
				"certInfo": []byte("certInfo"),
			},
			errContains: "missing 'pubArea' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.parseTPMAttestationStatement(tt.attStmt)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestVerifyTPMSignature_RSA(t *testing.T) {
	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create AIK certificate
	aikCert := createTestAIKCertificate(t, privKey, "test-device")

	// Data to sign
	certInfo := []byte("test-cert-info-data")

	// Sign with RS256
	hash := sha256.Sum256(certInfo)
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	// Wrap in TPMT_SIGNATURE structure using go-tpm constants
	signature := createTestTPMTSignature(rawSignature, uint16(tpm2.AlgRSASSA), uint16(tpm2.AlgSHA256))

	// Verify
	err = verifyTPMSignature(aikCert, certInfo, signature)
	require.NoError(t, err)
}

func TestVerifyTPMSignature_InvalidSignature(t *testing.T) {
	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create AIK certificate
	aikCert := createTestAIKCertificate(t, privKey, "test-device")

	// Data to sign
	certInfo := []byte("test-cert-info-data")

	// Invalid signature (random bytes wrapped in TPMT_SIGNATURE)
	invalidRawSig := make([]byte, 256)
	rand.Read(invalidRawSig)
	invalidSignature := createTestTPMTSignature(invalidRawSig, uint16(tpm2.AlgRSASSA), uint16(tpm2.AlgSHA256))

	// Verify should fail
	err = verifyTPMSignature(aikCert, certInfo, invalidSignature)
	require.Error(t, err)
}

// createTestTPMTSignature creates a TPMT_SIGNATURE structure for testing
func createTestTPMTSignature(rawSig []byte, sigAlg, hashAlg uint16) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, sigAlg)
	binary.Write(buf, binary.BigEndian, hashAlg)
	binary.Write(buf, binary.BigEndian, uint16(len(rawSig)))
	buf.Write(rawSig)
	return buf.Bytes()
}



func TestTPMAttestationValidator_ValidateAttestation_WrongFormat(t *testing.T) {
	validator := &TPMAttestationValidator{}

	attObj := &AttestationObject{
		Format:       "android-key",
		AttStatement: map[string]interface{}{},
	}

	config := &AttestationValidationConfig{
		ValidateEKCertificate: false, // Explicitly disable for this test
	}

	_, err := validator.ValidateAttestation(context.Background(), attObj, "test", config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected format 'tpm'")
}

func TestTPMAttestationValidator_ValidateAttestation_UnsupportedVersion(t *testing.T) {
	validator := &TPMAttestationValidator{}

	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	aikCert := createTestAIKCertificate(t, aikKey, "test-device")

	attObj := &AttestationObject{
		Format: string(AttestationFormatTPM),
		AttStatement: map[string]interface{}{
			"ver":      "1.0", // Unsupported version
			"alg":      int64(-257),
			"x5c":      [][]byte{aikCert.Raw},
			"sig":      []byte("sig"),
			"certInfo": []byte("certInfo"),
			"pubArea":  []byte("pubArea"),
		},
	}

	config := &AttestationValidationConfig{
		ValidateEKCertificate: false, // Explicitly disable for this test
	}

	_, err = validator.ValidateAttestation(context.Background(), attObj, "test", config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported TPM version")
}

// Helper functions

func createTestAIKCertificate(t *testing.T, privKey *rsa.PrivateKey, permanentID string) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test AIK Certificate",
			SerialNumber: permanentID,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// writeTPM2B writes a TPM2B structure (2-byte size prefix + data)
func writeTPM2B(buf *bytes.Buffer, data []byte) {
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
}

func createTestCertInfo(t *testing.T, extraData []byte) []byte {
	buf := new(bytes.Buffer)

	// Magic (TPM_GENERATED_VALUE = 0xff544347)
	binary.Write(buf, binary.BigEndian, uint32(testTPMGeneratedValue))
	// Type (TPM_ST_ATTEST_CERTIFY = 0x8017)
	binary.Write(buf, binary.BigEndian, uint16(testTPMSTAttestCertify))
	// QualifiedSigner
	writeTPM2B(buf, []byte("test-signer"))
	// ExtraData
	writeTPM2B(buf, extraData)
	// ClockInfo
	binary.Write(buf, binary.BigEndian, uint64(12345))
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(2))
	binary.Write(buf, binary.BigEndian, byte(1))
	// FirmwareVersion
	binary.Write(buf, binary.BigEndian, uint64(0x0001000200030004))
	// TPMS_CERTIFY_INFO
	// For now, use placeholder names - in a full test we'd compute the actual name
	writeTPM2B(buf, []byte("test-name-placeholder-1234567890"))
	writeTPM2B(buf, []byte("test-qualified-name"))

	return buf.Bytes()
}

func createTestPubArea(t *testing.T, pubKey *rsa.PublicKey) []byte {
	buf := new(bytes.Buffer)

	// Type (RSA)
	binary.Write(buf, binary.BigEndian, uint16(tpm2.AlgRSA))
	// NameAlg (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(tpm2.AlgSHA256))
	// ObjectAttributes
	binary.Write(buf, binary.BigEndian, uint32(0x00000001))
	// AuthPolicy (empty)
	writeTPM2B(buf, nil)
	// RSA Parameters
	binary.Write(buf, binary.BigEndian, uint16(tpm2.AlgNull))   // symmetric
	binary.Write(buf, binary.BigEndian, uint16(tpm2.AlgRSASSA)) // scheme
	binary.Write(buf, binary.BigEndian, uint16(tpm2.AlgSHA256)) // hash alg
	binary.Write(buf, binary.BigEndian, uint16(2048))           // keyBits
	binary.Write(buf, binary.BigEndian, uint32(0))              // exponent (0 = 65537)
	// Unique (RSA modulus)
	writeTPM2B(buf, pubKey.N.Bytes())

	return buf.Bytes()
}

func TestFullTPMAttestationFlow(t *testing.T) {
	t.Skip("Skipping full integration test - requires complete TPM name computation")

	// This test demonstrates the full flow but is skipped because
	// the TPMS_CERTIFY_INFO.Name field requires computing the TPM name
	// of the certified key, which requires the full public key structure.
	//
	// In a real implementation, this would be computed as:
	// Name = nameAlg || H(pubArea)
	//
	// This is implemented in the ComputeName method but requires
	// careful coordination between the certInfo and pubArea structures.
}

// TestTPMAttestationObject_CBOR tests CBOR encoding/decoding of attestation objects
func TestTPMAttestationObject_CBOR(t *testing.T) {
	// Create a test TPM attestation statement
	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	aikCert := createTestAIKCertificate(t, aikKey, "test-device-456")

	attStmt := map[string]interface{}{
		"ver":      "2.0",
		"alg":      int64(-257), // RS256
		"x5c":      [][]byte{aikCert.Raw},
		"sig":      []byte("test-signature-bytes"),
		"certInfo": createTestCertInfo(t, []byte("test-extra-data-32-bytes-long!!")),
		"pubArea":  createTestPubArea(t, &aikKey.PublicKey),
	}

	// Create attestation object
	attObj := map[string]interface{}{
		"fmt":     string(AttestationFormatTPM),
		"attStmt": attStmt,
	}

	// Encode to CBOR
	cborBytes, err := cbor.Marshal(attObj)
	require.NoError(t, err)
	require.NotEmpty(t, cborBytes)

	// Decode back
	var decoded map[string]interface{}
	err = cbor.Unmarshal(cborBytes, &decoded)
	require.NoError(t, err)

	// Verify format
	require.Equal(t, string(AttestationFormatTPM), decoded["fmt"])
	require.NotNil(t, decoded["attStmt"])
}
