// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTPMS_ATTEST(t *testing.T) {
	// Create a minimal valid TPMS_ATTEST structure
	buf := new(bytes.Buffer)

	// Magic (4 bytes)
	binary.Write(buf, binary.BigEndian, uint32(TPM_GENERATED_VALUE))

	// Type (2 bytes)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ST_ATTEST_CERTIFY))

	// QualifiedSigner (TPM2B_NAME)
	writeTPM2B(buf, []byte("test-signer"))

	// ExtraData (TPM2B_DATA)
	extraData := []byte("test-extra-data-12345678901234567890") // 32 bytes
	writeTPM2B(buf, extraData)

	// ClockInfo
	binary.Write(buf, binary.BigEndian, uint64(12345)) // clock
	binary.Write(buf, binary.BigEndian, uint32(1))     // resetCount
	binary.Write(buf, binary.BigEndian, uint32(2))     // restartCount
	binary.Write(buf, binary.BigEndian, byte(1))       // safe

	// FirmwareVersion
	binary.Write(buf, binary.BigEndian, uint64(0x0001000200030004))

	// TPMS_CERTIFY_INFO
	writeTPM2B(buf, []byte("test-name"))
	writeTPM2B(buf, []byte("test-qualified-name"))

	// Parse
	attest, err := ParseTPMS_ATTEST(buf.Bytes())
	require.NoError(t, err)

	// Verify fields
	require.Equal(t, uint32(TPM_GENERATED_VALUE), attest.Magic)
	require.Equal(t, uint16(TPM_ST_ATTEST_CERTIFY), attest.Type)
	require.Equal(t, []byte("test-signer"), attest.QualifiedSigner)
	require.Equal(t, extraData, attest.ExtraData)
	require.Equal(t, uint64(12345), attest.ClockInfo.Clock)
	require.Equal(t, uint32(1), attest.ClockInfo.ResetCount)
	require.Equal(t, uint32(2), attest.ClockInfo.RestartCount)
	require.Equal(t, byte(1), attest.ClockInfo.Safe)
	require.Equal(t, uint64(0x0001000200030004), attest.FirmwareVersion)
	require.NotNil(t, attest.AttestedCertify)
	require.Equal(t, []byte("test-name"), attest.AttestedCertify.Name)
	require.Equal(t, []byte("test-qualified-name"), attest.AttestedCertify.QualifiedName)
}

func TestParseTPMS_ATTEST_InvalidMagic(t *testing.T) {
	buf := new(bytes.Buffer)

	// Invalid magic
	binary.Write(buf, binary.BigEndian, uint32(0x12345678))
	binary.Write(buf, binary.BigEndian, uint16(TPM_ST_ATTEST_CERTIFY))

	_, err := ParseTPMS_ATTEST(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid magic value")
}

func TestParseTPMS_ATTEST_InvalidType(t *testing.T) {
	buf := new(bytes.Buffer)

	// Valid magic but invalid type
	binary.Write(buf, binary.BigEndian, uint32(TPM_GENERATED_VALUE))
	binary.Write(buf, binary.BigEndian, uint16(0x9999)) // Invalid type

	_, err := ParseTPMS_ATTEST(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported attestation type")
}

func TestParseTPMT_PUBLIC_RSA(t *testing.T) {
	buf := new(bytes.Buffer)

	// Type (RSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSA))

	// NameAlg (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))

	// ObjectAttributes
	binary.Write(buf, binary.BigEndian, uint32(0x00000001))

	// AuthPolicy (empty)
	writeTPM2B(buf, nil)

	// RSA Parameters
	// Symmetric (NULL)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_NULL))
	// Scheme (RSASSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSASSA))
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256)) // hash alg for scheme
	// KeyBits
	binary.Write(buf, binary.BigEndian, uint16(2048))
	// Exponent (0 = default 65537)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Unique (RSA modulus)
	// Generate a test RSA key
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	modulus := testKey.PublicKey.N.Bytes()
	writeTPM2B(buf, modulus)

	// Parse
	pub, err := ParseTPMT_PUBLIC(buf.Bytes())
	require.NoError(t, err)

	// Verify fields
	require.Equal(t, uint16(TPM_ALG_RSA), pub.Type)
	require.Equal(t, uint16(TPM_ALG_SHA256), pub.NameAlg)
	require.NotNil(t, pub.Parameters.RSADetail)
	require.Equal(t, uint16(2048), pub.Parameters.RSADetail.KeyBits)
	require.Equal(t, uint32(0), pub.Parameters.RSADetail.Exponent)
	require.NotNil(t, pub.Unique.RSA)
	require.Equal(t, modulus, pub.Unique.RSA)
}

func TestToRSAPublicKey(t *testing.T) {
	// Generate a test RSA key
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	modulus := testKey.PublicKey.N.Bytes()

	// Create TPMT_PUBLIC
	pub := &TPMT_PUBLIC{
		Type:    TPM_ALG_RSA,
		NameAlg: TPM_ALG_SHA256,
		Parameters: &TPMUPublicParms{
			RSADetail: &TPMSRSAParms{
				KeyBits:  2048,
				Exponent: 0, // Default 65537
			},
		},
		Unique: &TPMUPublicID{
			RSA: modulus,
		},
	}

	// Convert to RSA public key
	rsaPub, err := pub.ToRSAPublicKey()
	require.NoError(t, err)
	require.NotNil(t, rsaPub)
	require.Equal(t, 65537, rsaPub.E)
	require.Equal(t, new(big.Int).SetBytes(modulus), rsaPub.N)
}

func TestToRSAPublicKey_CustomExponent(t *testing.T) {
	// Generate a test RSA key
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	modulus := testKey.PublicKey.N.Bytes()

	// Create TPMT_PUBLIC with custom exponent
	pub := &TPMT_PUBLIC{
		Type:    TPM_ALG_RSA,
		NameAlg: TPM_ALG_SHA256,
		Parameters: &TPMUPublicParms{
			RSADetail: &TPMSRSAParms{
				KeyBits:  2048,
				Exponent: 3, // Custom exponent
			},
		},
		Unique: &TPMUPublicID{
			RSA: modulus,
		},
	}

	// Convert to RSA public key
	rsaPub, err := pub.ToRSAPublicKey()
	require.NoError(t, err)
	require.NotNil(t, rsaPub)
	require.Equal(t, 3, rsaPub.E)
}

func TestToRSAPublicKey_WrongType(t *testing.T) {
	pub := &TPMT_PUBLIC{
		Type:    TPM_ALG_ECDSA,
		NameAlg: TPM_ALG_SHA256,
	}

	_, err := pub.ToRSAPublicKey()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an RSA key")
}

func TestComputeTPMName(t *testing.T) {
	// Create a simple public area
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSA))
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))
	pubAreaBytes := buf.Bytes()

	pub := &TPMT_PUBLIC{
		Type:    TPM_ALG_RSA,
		NameAlg: TPM_ALG_SHA256,
	}

	// Compute name
	name, err := pub.ComputeName(pubAreaBytes)
	require.NoError(t, err)
	require.NotNil(t, name)

	// Name should be: nameAlg (2 bytes) || SHA256(pubArea) (32 bytes)
	require.Len(t, name, 34)

	// First 2 bytes should be the algorithm identifier
	algID := binary.BigEndian.Uint16(name[0:2])
	require.Equal(t, uint16(TPM_ALG_SHA256), algID)
}

func TestComputeTPMName_UnsupportedAlg(t *testing.T) {
	pub := &TPMT_PUBLIC{
		Type:    TPM_ALG_RSA,
		NameAlg: 0x9999, // Unsupported algorithm
	}

	_, err := pub.ComputeName([]byte("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported name algorithm")
}

// Helper function to write TPM2B_* structures
func writeTPM2B(w *bytes.Buffer, data []byte) {
	if data == nil {
		binary.Write(w, binary.BigEndian, uint16(0))
		return
	}
	binary.Write(w, binary.BigEndian, uint16(len(data)))
	w.Write(data)
}

func TestParseTPMT_SIGNATURE_RSASSA(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (RSASSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSASSA))

	// Hash algorithm (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))

	// Signature data (TPM2B)
	testSig := make([]byte, 256) // 2048-bit RSA signature
	for i := range testSig {
		testSig[i] = byte(i)
	}
	writeTPM2B(buf, testSig)

	// Parse
	sigBytes, algID, hashAlg, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, uint16(TPM_ALG_RSASSA), algID)
	require.Equal(t, uint16(TPM_ALG_SHA256), hashAlg)
	require.Equal(t, testSig, sigBytes)
}

func TestParseTPMT_SIGNATURE_RSAPSS(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (RSAPSS)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSAPSS))

	// Hash algorithm (SHA384)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA384))

	// Signature data (TPM2B)
	testSig := make([]byte, 256) // 2048-bit RSA signature
	for i := range testSig {
		testSig[i] = byte(i)
	}
	writeTPM2B(buf, testSig)

	// Parse
	sigBytes, algID, hashAlg, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, uint16(TPM_ALG_RSAPSS), algID)
	require.Equal(t, uint16(TPM_ALG_SHA384), hashAlg)
	require.Equal(t, testSig, sigBytes)
}

func TestParseTPMT_SIGNATURE_ECDSA(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (ECDSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_ECDSA))

	// Hash algorithm (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))

	// Signature R (TPM2B)
	testR := make([]byte, 32) // 256-bit ECDSA R value
	for i := range testR {
		testR[i] = byte(i)
	}
	writeTPM2B(buf, testR)

	// Signature S (TPM2B)
	testS := make([]byte, 32) // 256-bit ECDSA S value
	for i := range testS {
		testS[i] = byte(i + 32)
	}
	writeTPM2B(buf, testS)

	// Parse
	sigBytes, algID, hashAlg, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, uint16(TPM_ALG_ECDSA), algID)
	require.Equal(t, uint16(TPM_ALG_SHA256), hashAlg)

	// ECDSA signature should be r || s concatenated
	expectedSig := append(testR, testS...)
	require.Equal(t, expectedSig, sigBytes)
}

func TestParseTPMT_SIGNATURE_NULLAlgorithm(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (NULL)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_NULL))

	// Parse should fail
	_, _, _, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "NULL algorithm")
}

func TestParseTPMT_SIGNATURE_UnsupportedAlgorithm(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (unsupported)
	binary.Write(buf, binary.BigEndian, uint16(0x9999))

	// Parse should fail
	_, _, _, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signature algorithm")
}

func TestParseTPMT_SIGNATURE_TooShort(t *testing.T) {
	// Empty data
	_, _, _, err := ParseTPMT_SIGNATURE([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")

	// Only 1 byte
	_, _, _, err = ParseTPMT_SIGNATURE([]byte{0x00})
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestParseTPMT_SIGNATURE_TruncatedRSA(t *testing.T) {
	buf := new(bytes.Buffer)

	// Algorithm ID (RSASSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSASSA))
	// No hash alg or signature data

	_, _, _, err := ParseTPMT_SIGNATURE(buf.Bytes())
	require.Error(t, err)
}

func TestTPMHashAlgToGo(t *testing.T) {
	tests := []struct {
		tpmAlg    uint16
		expected  int
		supported bool
	}{
		{TPM_ALG_SHA1, 3, true},   // crypto.SHA1 = 3
		{TPM_ALG_SHA256, 5, true}, // crypto.SHA256 = 5
		{TPM_ALG_SHA384, 6, true}, // crypto.SHA384 = 6
		{TPM_ALG_SHA512, 7, true}, // crypto.SHA512 = 7
		{0x9999, 0, false},        // Unsupported
		{TPM_ALG_NULL, 0, false},  // NULL algorithm
	}

	for _, tc := range tests {
		t.Run(string(rune(tc.tpmAlg)), func(t *testing.T) {
			hashAlg, supported := TPMHashAlgToGo(tc.tpmAlg)
			require.Equal(t, tc.supported, supported)
			if tc.supported {
				require.Equal(t, tc.expected, hashAlg)
			}
		})
	}
}
