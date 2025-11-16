// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestValidateEKCertificateChain_ValidChainWithIntermediate tests validation
// of a complete certificate chain with an intermediate CA
func TestValidateEKCertificateChain_ValidChainWithIntermediate(t *testing.T) {
	// Create a 3-level chain: Root CA -> Intermediate CA -> Leaf (AIK) cert

	// Generate Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Root CA",
			Organization: []string{"Test Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

	// Generate Leaf (AIK) certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test AIK Certificate",
			SerialNumber: "test-device-12345",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateTemplate, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	// Build x5c chain (leaf first, then intermediate)
	x5c := [][]byte{
		leafCertDER,
		intermediateCertDER,
	}

	// Validate chain
	trustedRoots := []*x509.Certificate{rootCert}
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.NoError(t, err)
}

// TestValidateEKCertificateChain_ValidChainDirectToRoot tests validation
// when the leaf is signed directly by the root (no intermediate)
func TestValidateEKCertificateChain_ValidChainDirectToRoot(t *testing.T) {
	// Generate Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Root CA",
			Organization: []string{"Test Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Generate Leaf (AIK) certificate signed directly by root
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test AIK Certificate",
			SerialNumber: "test-device-67890",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	// Build x5c chain (only leaf, no intermediate)
	x5c := [][]byte{leafCertDER}

	// Validate chain
	trustedRoots := []*x509.Certificate{rootCert}
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.NoError(t, err)
}

// TestValidateEKCertificateChain_UntrustedRoot tests validation failure
// when the chain leads to an untrusted root
func TestValidateEKCertificateChain_UntrustedRoot(t *testing.T) {
	// Generate Root CA (untrusted)
	untrustedRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	untrustedRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Untrusted TPM Root CA",
			Organization: []string{"Untrusted Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	untrustedRootCertDER, err := x509.CreateCertificate(rand.Reader, untrustedRootTemplate, untrustedRootTemplate, &untrustedRootKey.PublicKey, untrustedRootKey)
	require.NoError(t, err)

	untrustedRootCert, err := x509.ParseCertificate(untrustedRootCertDER)
	require.NoError(t, err)

	// Generate Leaf certificate signed by untrusted root
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test AIK Certificate",
			SerialNumber: "test-device-99999",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, untrustedRootCert, &leafKey.PublicKey, untrustedRootKey)
	require.NoError(t, err)

	// Build x5c chain
	x5c := [][]byte{leafCertDER}

	// Create a DIFFERENT trusted root
	trustedRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	trustedRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Trusted TPM Root CA",
			Organization: []string{"Trusted Manufacturer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	trustedRootCertDER, err := x509.CreateCertificate(rand.Reader, trustedRootTemplate, trustedRootTemplate, &trustedRootKey.PublicKey, trustedRootKey)
	require.NoError(t, err)

	trustedRootCert, err := x509.ParseCertificate(trustedRootCertDER)
	require.NoError(t, err)

	// Validate chain should fail
	trustedRoots := []*x509.Certificate{trustedRootCert}
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify AIK certificate chain")
}

// TestValidateEKCertificateChain_EmptyX5c tests validation failure
// when x5c is empty
func TestValidateEKCertificateChain_EmptyX5c(t *testing.T) {
	// Create a trusted root (doesn't matter for this test)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Empty x5c
	x5c := [][]byte{}

	// Validate should fail
	trustedRoots := []*x509.Certificate{rootCert}
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no certificates in x5c chain")
}

// TestValidateEKCertificateChain_NoTrustedRoots tests validation failure
// when no trusted roots are configured
func TestValidateEKCertificateChain_NoTrustedRoots(t *testing.T) {
	// Generate a certificate (doesn't matter what it is)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)

	// Build x5c
	x5c := [][]byte{leafCertDER}

	// No trusted roots
	trustedRoots := []*x509.Certificate{}

	// Validate should fail
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no trusted roots are configured")
}

// TestValidateEKCertificateChain_InvalidIntermediateCertificate tests validation failure
// when an intermediate certificate in x5c is malformed
func TestValidateEKCertificateChain_InvalidIntermediateCertificate(t *testing.T) {
	// Generate Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Generate Leaf certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Leaf Certificate",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	// Build x5c with invalid intermediate certificate
	x5c := [][]byte{
		leafCertDER,
		[]byte("this is not a valid certificate"), // Invalid intermediate
	}

	// Validate should fail
	trustedRoots := []*x509.Certificate{rootCert}
	err = validateEKCertificateChain(x5c, trustedRoots)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse intermediate certificate")
}

// TestExtractTPMManufacturer tests manufacturer extraction from certificates
func TestExtractTPMManufacturer(t *testing.T) {
	// This is a placeholder test since extractTPMManufacturer
	// looks for specific OIDs that would need to be added to test certificates
	// In practice, real TPM manufacturer certificates would have these OIDs

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		// Note: We don't add manufacturer OID extensions here
		// In a real test we would add them manually
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	// Should fail since we didn't add manufacturer OID
	_, err = extractTPMManufacturer(cert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TPM manufacturer OID not found")
}
