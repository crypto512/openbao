package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

const spkiPinPrefix = "sha256//"

// ComputeSPKIPin computes the SPKI pin for a certificate.
// Returns format: sha256//<base64-encoded-hash>
// This follows the standard format used by curl, wget, and Chrome HPKP.
func ComputeSPKIPin(cert *x509.Certificate) string {
	// Hash the Subject Public Key Info (SPKI)
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return spkiPinPrefix + base64.StdEncoding.EncodeToString(hash[:])
}

// VerifyChainSPKI checks if any certificate in the chain matches the expected SPKI pin.
// The chain should include the leaf certificate and any intermediate/root CAs.
// Returns nil if a match is found, error otherwise.
func VerifyChainSPKI(chain []*x509.Certificate, expectedPin string) error {
	if !strings.HasPrefix(expectedPin, spkiPinPrefix) {
		return fmt.Errorf("invalid SPKI pin format: must start with %s", spkiPinPrefix)
	}

	for _, cert := range chain {
		pin := ComputeSPKIPin(cert)
		if pin == expectedPin {
			return nil
		}
	}

	// Build error message with all pins for debugging
	var pins []string
	for _, cert := range chain {
		pins = append(pins, ComputeSPKIPin(cert))
	}

	return fmt.Errorf("SPKI pin mismatch: expected %s, got chain pins: %v", expectedPin, pins)
}

// ExtractCAChainPEM extracts CA certificates from a certificate chain and returns them as PEM.
// It excludes the leaf certificate (first in chain) and includes only CA certificates.
// If the chain has only one certificate (self-signed CA), it returns that certificate.
func ExtractCAChainPEM(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return ""
	}

	var pemBlocks []string

	// If only one cert, return it (likely self-signed CA or single-cert chain)
	if len(chain) == 1 {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chain[0].Raw,
		}
		return string(pem.EncodeToMemory(block))
	}

	// Skip leaf (index 0), include intermediates and root
	for i := 1; i < len(chain); i++ {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chain[i].Raw,
		}
		pemBlocks = append(pemBlocks, string(pem.EncodeToMemory(block)))
	}

	return strings.Join(pemBlocks, "")
}

// ParseSPKIPin validates and extracts the hash from an SPKI pin string.
// Returns the base64-encoded hash portion if valid.
func ParseSPKIPin(pin string) (string, error) {
	if !strings.HasPrefix(pin, spkiPinPrefix) {
		return "", fmt.Errorf("invalid SPKI pin format: must start with %s", spkiPinPrefix)
	}

	hashB64 := strings.TrimPrefix(pin, spkiPinPrefix)
	if hashB64 == "" {
		return "", fmt.Errorf("invalid SPKI pin: empty hash")
	}

	// Validate base64 encoding
	decoded, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return "", fmt.Errorf("invalid SPKI pin: bad base64 encoding: %w", err)
	}

	// SHA256 hash should be 32 bytes
	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid SPKI pin: hash should be 32 bytes, got %d", len(decoded))
	}

	return hashB64, nil
}
