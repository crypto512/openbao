// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddPermanentIdentifierToTemplate(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	identifier := "test-device-12345"

	err := AddPermanentIdentifierToTemplate(template, identifier)
	require.NoError(t, err)

	// Verify identifier was added to Subject DN
	require.Equal(t, identifier, template.Subject.SerialNumber)

	// Verify SAN extension was added
	require.NotEmpty(t, template.ExtraExtensions)

	// Find the SAN extension
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	var foundSAN bool
	for _, ext := range template.ExtraExtensions {
		if ext.Id.Equal(sanOID) {
			foundSAN = true
			break
		}
	}
	require.True(t, foundSAN, "SAN extension should be present")
}

func TestParsePermanentIdentifierFromCert_SubjectDN(t *testing.T) {
	// Create a self-signed certificate with permanent identifier in Subject DN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	identifier := "test-device-67890"

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Device",
			SerialNumber: identifier,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier
	parsedID, err := ParsePermanentIdentifierFromCert(cert)
	require.NoError(t, err)
	require.Equal(t, identifier, parsedID)
}

func TestParsePermanentIdentifierFromCert_SAN(t *testing.T) {
	// Create a self-signed certificate with permanent identifier in SAN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	identifier := "san-device-12345"

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Add permanent identifier to template
	err = AddPermanentIdentifierToTemplate(template, identifier)
	require.NoError(t, err)

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier
	// Note: This will return the Subject DN serial number since we set both
	parsedID, err := ParsePermanentIdentifierFromCert(cert)
	require.NoError(t, err)
	require.Equal(t, identifier, parsedID)
}

func TestParsePermanentIdentifierFromCert_NotFound(t *testing.T) {
	// Create a certificate without permanent identifier
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Try to parse permanent identifier
	_, err = ParsePermanentIdentifierFromCert(cert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no permanent identifier found")
}

func TestEncodePermanentIdentifierExtension(t *testing.T) {
	identifier := "test-identifier-abc123"

	ext, err := encodePermanentIdentifierExtension(identifier)
	require.NoError(t, err)

	// Verify it's a SAN extension
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	require.True(t, ext.Id.Equal(sanOID), "Extension should have SAN OID")

	// Verify it's not marked critical
	require.False(t, ext.Critical)

	// Verify the extension value is not empty
	require.NotEmpty(t, ext.Value)
}

func TestParsePermanentIdentifierFromCert_URISAN(t *testing.T) {
	// Create a self-signed certificate with permanent identifier in URI SAN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	identifier := "sha256-ekpubkey-abcdef123456"
	uriStr := URNPermanentIdentifierPrefix + identifier

	uri, err := url.Parse(uriStr)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier
	parsedID, err := ParsePermanentIdentifierFromCert(cert)
	require.NoError(t, err)
	require.Equal(t, identifier, parsedID)
}

func TestParsePermanentIdentifierFromCert_URISAN_Priority(t *testing.T) {
	// Test that Subject.SerialNumber takes priority over URI SAN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subjectSerialID := "subject-serial-id"
	uriIdentifier := "uri-identifier"
	uriStr := URNPermanentIdentifierPrefix + uriIdentifier

	uri, err := url.Parse(uriStr)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Device",
			SerialNumber: subjectSerialID,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier - should return Subject.SerialNumber (higher priority)
	parsedID, err := ParsePermanentIdentifierFromCert(cert)
	require.NoError(t, err)
	require.Equal(t, subjectSerialID, parsedID)
}

func TestParsePermanentIdentifierFromCert_URISAN_MultipleURIs(t *testing.T) {
	// Test certificate with multiple URIs, only one has permanent-identifier prefix
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	identifier := "my-permanent-id-xyz"

	uri1, _ := url.Parse("https://example.com/device")
	uri2, _ := url.Parse(URNPermanentIdentifierPrefix + identifier)
	uri3, _ := url.Parse("urn:other:something")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri1, uri2, uri3},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier
	parsedID, err := ParsePermanentIdentifierFromCert(cert)
	require.NoError(t, err)
	require.Equal(t, identifier, parsedID)
}

func TestParsePermanentIdentifierFromCert_URISAN_OtherURNPrefix(t *testing.T) {
	// Test that other URN prefixes don't match
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use old format which should NOT be recognized
	uri1, _ := url.Parse("urn:ek:sha256:old-format-id")
	// Use other URN format
	uri2, _ := url.Parse("urn:uuid:12345678-1234-1234-1234-123456789abc")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri1, uri2},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Parse permanent identifier - should fail since no matching format
	_, err = ParsePermanentIdentifierFromCert(cert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no permanent identifier found")
}

func TestURNPermanentIdentifierPrefix(t *testing.T) {
	// Verify the constant is correct
	require.Equal(t, "urn:permanent-identifier:", URNPermanentIdentifierPrefix)
}
