// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestComputeKeyAuthorizationHash(t *testing.T) {
	// Test vector from draft-acme-device-attest-07
	keyAuth := "test-token.dGVzdC10aHVtYnByaW50"

	hash := ComputeKeyAuthorizationHash(keyAuth)

	// Verify hash length
	require.Len(t, hash, 32, "SHA-256 hash should be 32 bytes")

	// Verify it matches direct SHA-256 computation
	expectedHash := sha256.Sum256([]byte(keyAuth))
	require.Equal(t, expectedHash[:], hash, "Hash should match SHA-256 of key authorization")
}

func TestParseAttestationObject(t *testing.T) {
	tests := []struct {
		name        string
		format      AttestationFormat
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid TPM attestation object",
			format:  AttestationFormatTPM,
			wantErr: false,
		},
		{
			name:    "valid Android Key attestation object",
			format:  AttestationFormatAndroidKey,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal attestation object
			attObj := map[string]interface{}{
				"fmt": string(tt.format),
				"attStmt": map[string]interface{}{
					"ver": "2.0",
				},
			}

			// Encode to CBOR
			cborBytes, err := cbor.Marshal(attObj)
			require.NoError(t, err, "Failed to marshal test attestation object")

			// Base64url encode
			attObjB64 := base64.RawURLEncoding.EncodeToString(cborBytes)

			// Parse
			parsed, err := ParseAttestationObject(attObjB64)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, parsed)
				require.Equal(t, string(tt.format), parsed.Format)
			}
		})
	}
}

func TestParseAttestationObject_InvalidBase64(t *testing.T) {
	// Test with invalid base64
	_, err := ParseAttestationObject("not-valid-base64!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to base64url decode")
}

func TestParseAttestationObject_InvalidCBOR(t *testing.T) {
	// Test with invalid CBOR (valid base64 but not CBOR)
	invalidCBOR := base64.RawURLEncoding.EncodeToString([]byte("not cbor data"))
	_, err := ParseAttestationObject(invalidCBOR)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal CBOR")
}

func TestGetAttestationValidator(t *testing.T) {
	tests := []struct {
		name    string
		format  AttestationFormat
		wantErr bool
	}{
		{
			name:    "TPM validator",
			format:  AttestationFormatTPM,
			wantErr: false,
		},
		{
			name:    "unsupported format",
			format:  AttestationFormat("unsupported"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := GetAttestationValidator(tt.format)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, validator)
			} else {
				require.NoError(t, err)
				require.NotNil(t, validator)
				require.True(t, validator.SupportsFormat(tt.format))
			}
		})
	}
}

func TestRegisterAttestationValidator(t *testing.T) {
	// Create a test validator
	testFormat := AttestationFormat("test-format")
	testValidator := &TPMAttestationValidator{}

	// Register it
	RegisterAttestationValidator(testFormat, testValidator)

	// Verify it was registered
	validator, err := GetAttestationValidator(testFormat)
	require.NoError(t, err)
	require.NotNil(t, validator)
}
