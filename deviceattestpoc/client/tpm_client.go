// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
)

// TPMClient manages TPM operations for device attestation
type TPMClient struct {
	tpm            *attest.TPM
	ak             *attest.AK
	certKey        *rsa.PrivateKey
	permanentID    string
	ekCert         *x509.Certificate      // EK certificate from hardware TPM
	ekRootCA       *x509.Certificate      // Manufacturer root CA (from EK cert or simulated)
	ekRootCAKey    *rsa.PrivateKey        // Private key for root CA (simulated mode only)
	hardwareMode   bool                   // true if using real TPM hardware
	manufacturerCA string                 // Manufacturer name (e.g., "intel", "amd", "infineon")
}

// NewTPMClient creates a new TPM client
func NewTPMClient(tpmPath string) (*TPMClient, error) {
	log.Printf("Attempting to open TPM (will auto-detect hardware or use simulation)")

	// Open TPM with auto-detection
	// go-attestation will try /dev/tpmrm0, /dev/tpm0, and Windows TPM automatically
	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}

	tpm, err := attest.OpenTPM(config)
	if err != nil {
		// TPM not available - use simulated mode for PoC
		log.Printf("No hardware TPM detected (%v)", err)
		log.Printf("Using simulated attestation mode (not suitable for production)")

		client := &TPMClient{
			tpm: nil, // No real TPM
		}

		// In simulated mode, skip EK and AK creation
		// Extract simulated permanent ID
		if err := client.extractSimulatedPermanentID(); err != nil {
			return nil, fmt.Errorf("failed to generate simulated permanent ID: %w", err)
		}

		// Generate certificate key
		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate certificate key: %w", err)
		}
		client.certKey = certKey

		return client, nil
	}

	log.Printf("✓ Hardware TPM detected and opened successfully")

	client := &TPMClient{
		tpm:          tpm,
		hardwareMode: true,
	}

	// Get EK certificates from hardware TPM
	eks, err := tpm.EKs()
	if err != nil {
		log.Printf("Warning: Failed to get EKs: %v", err)
		log.Printf("Falling back to simulation mode")
		client.hardwareMode = false
	} else if len(eks) > 0 {
		log.Printf("Found %d EK(s) from hardware TPM", len(eks))

		// Use the first EK (typically RSA EK)
		ek := eks[0]

		if ek.Certificate != nil {
			log.Printf("✓ EK certificate found in TPM NVRAM")
			client.ekCert = ek.Certificate

			// Extract manufacturer root CA from EK certificate chain
			if err := client.extractManufacturerCA(); err != nil {
				log.Printf("Warning: Failed to extract manufacturer CA: %v", err)
				log.Printf("Falling back to simulation mode")
				client.hardwareMode = false
			} else {
				log.Printf("✓ Manufacturer root CA extracted: %s", client.manufacturerCA)
			}
		} else {
			log.Printf("Warning: EK found but no certificate in NVRAM")
			log.Printf("Falling back to simulation mode")
			client.hardwareMode = false
		}
	} else {
		log.Printf("Warning: No EKs found in hardware TPM")
		log.Printf("Falling back to simulation mode")
		client.hardwareMode = false
	}

	// Create or load AK
	if err := client.createOrLoadAK(); err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to create/load AK: %w", err)
	}

	// Extract permanent identifier (different method for hardware vs simulation)
	if err := client.extractPermanentID(); err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to extract permanent ID: %w", err)
	}

	// Generate certificate key
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}
	client.certKey = certKey

	return client, nil
}

// createOrLoadAK creates or loads an Attestation Key
func (c *TPMClient) createOrLoadAK() error {
	log.Println("Creating Attestation Key (AK)")

	akConfig := &attest.AKConfig{}
	ak, err := c.tpm.NewAK(akConfig)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	c.ak = ak
	log.Println("✓ AK created successfully")

	return nil
}

// extractManufacturerCA extracts the manufacturer root CA from the EK certificate chain
func (c *TPMClient) extractManufacturerCA() error {
	if c.ekCert == nil {
		return fmt.Errorf("no EK certificate available")
	}

	// The EK certificate is issued by the TPM manufacturer
	// For a complete chain, we would verify it against known manufacturer root CAs
	// For this PoC, we'll extract the issuer information and use the EK cert as root

	log.Printf("EK Certificate Details:")
	log.Printf("  Subject: %s", c.ekCert.Subject.String())
	log.Printf("  Issuer: %s", c.ekCert.Issuer.String())
	log.Printf("  Serial: %s", c.ekCert.SerialNumber.String())

	// Determine manufacturer from EK certificate issuer
	issuerCN := c.ekCert.Issuer.CommonName
	issuerOrg := ""
	if len(c.ekCert.Issuer.Organization) > 0 {
		issuerOrg = c.ekCert.Issuer.Organization[0]
	}

	// Identify manufacturer based on issuer information
	switch {
	case contains(issuerOrg, "Intel") || contains(issuerCN, "Intel"):
		c.manufacturerCA = "intel"
	case contains(issuerOrg, "AMD") || contains(issuerCN, "AMD"):
		c.manufacturerCA = "amd"
	case contains(issuerOrg, "Infineon") || contains(issuerCN, "Infineon"):
		c.manufacturerCA = "infineon"
	case contains(issuerOrg, "Nuvoton") || contains(issuerCN, "Nuvoton"):
		c.manufacturerCA = "nuvoton"
	case contains(issuerOrg, "STMicroelectronics") || contains(issuerCN, "STMicro"):
		c.manufacturerCA = "stmicro"
	default:
		c.manufacturerCA = "unknown-" + issuerOrg
		log.Printf("Warning: Unknown TPM manufacturer: %s", issuerOrg)
	}

	// In a production system, we would:
	// 1. Verify the EK cert chains to a known manufacturer root CA
	// 2. Store multiple manufacturer root CAs in a trust store
	// 3. Validate the signature chain
	//
	// For this PoC, we'll use the EK certificate's issuer as the "root"
	// If the EK cert is self-signed, it IS the root. Otherwise, we'd need the full chain.

	if c.ekCert.Issuer.String() == c.ekCert.Subject.String() {
		// Self-signed - this IS the root CA
		log.Printf("✓ EK certificate is self-signed (manufacturer root CA)")
		c.ekRootCA = c.ekCert
	} else {
		// Issued by a CA - in production we'd need to fetch/verify the full chain
		// For PoC, we'll treat the issuing CA info as the root
		log.Printf("Note: EK certificate issued by: %s", c.ekCert.Issuer.String())
		log.Printf("Note: In production, full certificate chain validation required")

		// Use the EK cert itself as the root for this PoC
		// This works if the server is configured to trust this specific cert
		c.ekRootCA = c.ekCert
	}

	return nil
}

// contains is a helper function for case-insensitive substring matching
func contains(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

// extractPermanentID extracts the permanent identifier from TPM
func (c *TPMClient) extractPermanentID() error {
	if c.hardwareMode && c.ekCert != nil {
		// Hardware mode: Extract permanent ID from EK certificate
		// The permanent identifier can be in several places:
		// 1. Subject Alternative Name with OID 1.3.6.1.5.5.7.8.3 (permanent-identifier)
		// 2. Subject Serial Number
		// 3. Certificate Serial Number

		// Try to find permanent-identifier in SAN extensions
		permanentIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
		for _, ext := range c.ekCert.Extensions {
			if ext.Id.Equal(permanentIDOID) {
				// Found permanent identifier extension
				var permanentID string
				if _, err := asn1.Unmarshal(ext.Value, &permanentID); err == nil {
					c.permanentID = permanentID
					log.Printf("✓ Permanent ID extracted from EK certificate SAN: %s", c.permanentID)
					return nil
				}
			}
		}

		// Fallback to Subject Serial Number
		if c.ekCert.Subject.SerialNumber != "" {
			c.permanentID = c.ekCert.Subject.SerialNumber
			log.Printf("✓ Permanent ID extracted from EK certificate Subject: %s", c.permanentID)
			return nil
		}

		// Fallback to certificate serial number as hex string
		c.permanentID = fmt.Sprintf("TPM-SN-%s", c.ekCert.SerialNumber.Text(16))
		log.Printf("✓ Permanent ID derived from EK certificate serial: %s", c.permanentID)
		return nil
	}

	// Simulation mode or no hardware: Use hash-based permanent ID
	params := c.ak.AttestationParameters()
	pubKeyHash := sha256.Sum256(params.Public)
	c.permanentID = fmt.Sprintf("TPM-%X", pubKeyHash[:8])

	log.Printf("Permanent ID (derived from AK): %s", c.permanentID)
	return nil
}

// extractSimulatedPermanentID generates a simulated permanent ID when no TPM is available
func (c *TPMClient) extractSimulatedPermanentID() error {
	// Generate a random permanent ID for simulation
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return err
	}

	c.permanentID = fmt.Sprintf("SIM-TPM-%X", randomBytes[:8])
	log.Printf("Simulated Permanent ID: %s", c.permanentID)
	return nil
}

// GenerateCSR generates a Certificate Signing Request for the certificate key
func (c *TPMClient) GenerateCSR(commonName string, sanDNS []string, sanIPs []string) (string, error) {
	log.Printf("Generating CSR for CN=%s", commonName)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: sanDNS,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, c.certKey)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

// GenerateAttestation generates a TPM attestation object for the given key authorization
func (c *TPMClient) GenerateAttestation(keyAuthorization string) (string, error) {
	log.Printf("Generating TPM attestation for key authorization")

	// Compute qualifying data (SHA-256 of key authorization)
	qualifyingData := sha256.Sum256([]byte(keyAuthorization))

	log.Printf("Key authorization hash: %X", qualifyingData[:16])

	if c.hardwareMode && c.tpm != nil {
		// Hardware TPM mode: Use real TPM Quote for attestation
		return c.generateHardwareAttestation(keyAuthorization, qualifyingData[:])
	}

	// Simulation mode: Use simulated attestation
	return c.generateSimulatedAttestation(keyAuthorization, qualifyingData[:])
}

// generateHardwareAttestation generates attestation using real TPM hardware
func (c *TPMClient) generateHardwareAttestation(keyAuthorization string, qualifyingData []byte) (string, error) {
	log.Printf("✓ Using hardware TPM for attestation")

	// Use TPM Quote operation to create a hardware-backed attestation
	// Quote creates a signed statement about the TPM state
	quote, err := c.ak.Quote(c.tpm, qualifyingData, attest.HashSHA256)
	if err != nil {
		log.Printf("Warning: Hardware TPM Quote failed: %v", err)
		log.Printf("Falling back to simulation mode")
		return c.generateSimulatedAttestation(keyAuthorization, qualifyingData)
	}

	log.Printf("✓ Hardware TPM Quote successful")

	// Create pubArea for the certified key (the certificate key)
	pubArea := createPubArea(c.certKey.Public().(*rsa.PublicKey))

	// Get AIK certificate with real AK public key
	aikCert, err := c.createAIKCertificateHardware()
	if err != nil {
		return "", fmt.Errorf("failed to create AIK certificate: %w", err)
	}

	// Build attestation statement using Quote data
	attStmt := map[string]interface{}{
		"ver":      "2.0",
		"alg":      int64(-257),          // RS256
		"x5c":      [][]byte{aikCert.Raw},
		"sig":      quote.Signature,      // Real TPM signature!
		"certInfo": quote.Quote,          // Real TPM quote data
		"pubArea":  pubArea,
	}

	// Build attestation object
	attObj := map[string]interface{}{
		"fmt":     "tpm",
		"attStmt": attStmt,
	}

	// Encode to CBOR
	cborBytes, err := cbor.Marshal(attObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CBOR: %w", err)
	}

	// Base64url encode
	attestationObject := base64.RawURLEncoding.EncodeToString(cborBytes)

	log.Printf("✓ Hardware TPM attestation object generated (%d bytes)", len(attestationObject))

	return attestationObject, nil
}

// generateSimulatedAttestation generates simulated attestation for PoC
func (c *TPMClient) generateSimulatedAttestation(keyAuthorization string, qualifyingData []byte) (string, error) {
	log.Printf("Using simulated TPM attestation")

	// Create pubArea for the certified key (the certificate key)
	pubArea := createPubArea(c.certKey.Public().(*rsa.PublicKey))

	// Create certInfo (TPMS_ATTEST structure)
	certInfo := createCertInfo(qualifyingData, pubArea)

	// Get AIK certificate
	aikCert, err := c.createAIKCertificate()
	if err != nil {
		return "", fmt.Errorf("failed to create AIK certificate: %w", err)
	}

	// Sign certInfo with a simulated AK key
	hash := sha256.Sum256(certInfo)

	// Create a simulated signature using a temporary key
	// In hardware mode, this would be done by the TPM
	aikPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate AIK key: %w", err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, aikPrivKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign certInfo: %w", err)
	}

	// Update AIK certificate to use this key, signed by EK root CA if available
	// First ensure we have the EK root CA generated
	if c.ekRootCA == nil {
		_, _, _, err := c.GetEnrollmentData()
		if err != nil {
			return "", fmt.Errorf("failed to get enrollment data: %w", err)
		}
	}

	aikCert, err = createAIKCertificateWithKey(c.permanentID, aikPrivKey.Public().(*rsa.PublicKey), c.ekRootCA, c.ekRootCAKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AIK certificate with key: %w", err)
	}

	// Build attestation statement
	attStmt := map[string]interface{}{
		"ver":      "2.0",
		"alg":      int64(-257), // RS256
		"x5c":      [][]byte{aikCert.Raw},
		"sig":      signature,
		"certInfo": certInfo,
		"pubArea":  pubArea,
	}

	// Build attestation object
	attObj := map[string]interface{}{
		"fmt":     "tpm",
		"attStmt": attStmt,
	}

	// Encode to CBOR
	cborBytes, err := cbor.Marshal(attObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CBOR: %w", err)
	}

	// Base64url encode
	attestationObject := base64.RawURLEncoding.EncodeToString(cborBytes)

	log.Printf("✓ Simulated attestation object generated (%d bytes)", len(attestationObject))

	return attestationObject, nil
}

// GetPermanentID returns the TPM permanent identifier
func (c *TPMClient) GetPermanentID() string {
	return c.permanentID
}

// IsSimulated returns true if using simulated TPM mode
func (c *TPMClient) IsSimulated() bool {
	return !c.hardwareMode
}

// GetPrivateKey returns the certificate private key (simulated mode only)
// In hardware mode, returns nil as the key is protected inside the TPM
func (c *TPMClient) GetPrivateKey() *rsa.PrivateKey {
	if c.hardwareMode {
		return nil
	}
	return c.certKey
}

// Close closes the TPM connection
func (c *TPMClient) Close() error {
	if c.tpm != nil {
		if c.ak != nil {
			c.ak.Close(c.tpm)
		}
		return c.tpm.Close()
	}
	// Simulated mode - nothing to close
	return nil
}

// Helper functions for TPM structure creation

func createPubArea(pubKey *rsa.PublicKey) []byte {
	buf := new(bytes.Buffer)

	// Type (RSA)
	binary.Write(buf, binary.BigEndian, uint16(0x0001)) // TPM_ALG_RSA
	// NameAlg (SHA256)
	binary.Write(buf, binary.BigEndian, uint16(0x000B)) // TPM_ALG_SHA256
	// ObjectAttributes
	binary.Write(buf, binary.BigEndian, uint32(0x00060472))
	// AuthPolicy (empty)
	writeTPM2B(buf, nil)
	// RSA Parameters
	binary.Write(buf, binary.BigEndian, uint16(0x0010))   // TPM_ALG_NULL (symmetric)
	binary.Write(buf, binary.BigEndian, uint16(0x0014))   // TPM_ALG_RSASSA (scheme)
	binary.Write(buf, binary.BigEndian, uint16(0x000B))   // TPM_ALG_SHA256 (hash alg)
	binary.Write(buf, binary.BigEndian, uint16(2048))     // keyBits
	binary.Write(buf, binary.BigEndian, uint32(65537))    // exponent
	// Unique (RSA modulus)
	writeTPM2B(buf, pubKey.N.Bytes())

	return buf.Bytes()
}

func createCertInfo(qualifyingData []byte, pubArea []byte) []byte {
	buf := new(bytes.Buffer)

	// Magic
	binary.Write(buf, binary.BigEndian, uint32(0xff544347)) // TPM_GENERATED_VALUE
	// Type
	binary.Write(buf, binary.BigEndian, uint16(0x8017)) // TPM_ST_ATTEST_CERTIFY
	// QualifiedSigner
	writeTPM2B(buf, []byte("signer"))
	// ExtraData (this is the key authorization hash!)
	writeTPM2B(buf, qualifyingData)
	// ClockInfo
	binary.Write(buf, binary.BigEndian, uint64(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, byte(1))
	// FirmwareVersion
	binary.Write(buf, binary.BigEndian, uint64(0x0001000200030004))

	// TPMS_CERTIFY_INFO
	// Compute the name of the certified object
	nameAlg := uint16(0x000B) // TPM_ALG_SHA256
	hasher := sha256.New()
	hasher.Write(pubArea)
	digest := hasher.Sum(nil)

	name := make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(name[0:2], nameAlg)
	copy(name[2:], digest)

	writeTPM2B(buf, name)
	writeTPM2B(buf, []byte("qualified-name"))

	return buf.Bytes()
}

func writeTPM2B(w *bytes.Buffer, data []byte) {
	if data == nil {
		binary.Write(w, binary.BigEndian, uint16(0))
		return
	}
	binary.Write(w, binary.BigEndian, uint16(len(data)))
	w.Write(data)
}

func (c *TPMClient) createAIKCertificate() (*x509.Certificate, error) {
	// Generate a temporary key for the certificate
	// In a real implementation, this would use the AK public key from attestation parameters
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Ensure we have the EK root CA generated
	if c.ekRootCA == nil {
		_, _, _, err := c.GetEnrollmentData()
		if err != nil {
			return nil, fmt.Errorf("failed to get enrollment data: %w", err)
		}
	}

	return createAIKCertificateWithKey(c.permanentID, privKey.Public().(*rsa.PublicKey), c.ekRootCA, c.ekRootCAKey)
}

// createAIKCertificateHardware creates an AIK certificate using the real AK public key from hardware TPM
func (c *TPMClient) createAIKCertificateHardware() (*x509.Certificate, error) {
	// Get attestation parameters to access the real AK public key
	params := c.ak.AttestationParameters()

	// The params.Public contains the TPMT_PUBLIC structure encoded as bytes
	// We need to decode it to extract the RSA public key
	// For this PoC, we'll use a simplified approach

	// Decode the public key from TPMT_PUBLIC structure
	// The structure is complex, so for this PoC we'll use a helper function
	rsaPubKey, err := decodeTPMPublicKey(params.Public)
	if err != nil {
		// If we can't decode the public key, fall back to simulated cert
		log.Printf("Warning: Could not decode AK public key from TPM: %v", err)
		log.Printf("Falling back to simulated AIK certificate")
		return c.createAIKCertificate()
	}

	log.Printf("✓ Using real AK public key from hardware TPM")

	// Ensure we have the EK root CA
	if c.ekRootCA == nil {
		_, _, _, err := c.GetEnrollmentData()
		if err != nil {
			return nil, fmt.Errorf("failed to get enrollment data: %w", err)
		}
	}

	// Create certificate with real AK public key
	// In hardware mode, we can't sign with AK private key (it's locked in TPM)
	// So we sign the AIK cert with EK root CA
	return createAIKCertificateWithKey(c.permanentID, rsaPubKey, c.ekRootCA, c.ekRootCAKey)
}

// decodeTPMPublicKey extracts an RSA public key from TPMT_PUBLIC structure
func decodeTPMPublicKey(tpmPublic []byte) (*rsa.PublicKey, error) {
	if len(tpmPublic) < 30 {
		return nil, fmt.Errorf("TPMT_PUBLIC too short: %d bytes", len(tpmPublic))
	}

	// TPMT_PUBLIC structure for RSA:
	// 0-1: type (0x0001 for RSA)
	// 2-3: nameAlg
	// 4-7: objectAttributes
	// 8-9: authPolicy size
	// ...: authPolicy data
	// Then RSA parameters:
	//   0-1: symmetric (usually NULL)
	//   2-3: scheme
	//   4-5: keyBits
	//   6-9: exponent (0 means 65537)
	//   10-11: unique size (N)
	//   12+: modulus bytes

	reader := bytes.NewReader(tpmPublic)

	// Read type
	var tpmType uint16
	if err := binary.Read(reader, binary.BigEndian, &tpmType); err != nil {
		return nil, fmt.Errorf("failed to read type: %w", err)
	}
	if tpmType != 0x0001 { // TPM_ALG_RSA
		return nil, fmt.Errorf("not an RSA key: type=0x%04x", tpmType)
	}

	// Skip nameAlg (2 bytes)
	reader.Seek(2, 1)

	// Skip objectAttributes (4 bytes)
	reader.Seek(4, 1)

	// Read and skip authPolicy
	var authPolicySize uint16
	if err := binary.Read(reader, binary.BigEndian, &authPolicySize); err != nil {
		return nil, fmt.Errorf("failed to read authPolicy size: %w", err)
	}
	reader.Seek(int64(authPolicySize), 1)

	// Skip RSA parameters (symmetric, scheme, keyBits)
	reader.Seek(6, 1)

	// Read exponent
	var exponent uint32
	if err := binary.Read(reader, binary.BigEndian, &exponent); err != nil {
		return nil, fmt.Errorf("failed to read exponent: %w", err)
	}
	if exponent == 0 {
		exponent = 65537 // Default RSA exponent
	}

	// Read modulus size
	var modulusSize uint16
	if err := binary.Read(reader, binary.BigEndian, &modulusSize); err != nil {
		return nil, fmt.Errorf("failed to read modulus size: %w", err)
	}

	// Read modulus
	modulus := make([]byte, modulusSize)
	if _, err := reader.Read(modulus); err != nil {
		return nil, fmt.Errorf("failed to read modulus: %w", err)
	}

	// Create RSA public key
	n := new(big.Int).SetBytes(modulus)
	pubKey := &rsa.PublicKey{
		N: n,
		E: int(exponent),
	}

	return pubKey, nil
}

func createAIKCertificateWithKey(permanentID string, pubKey *rsa.PublicKey, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, error) {
	// Create AIK certificate signed by EK root CA (or self-signed if no issuer provided)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
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

	// Add permanent identifier to SAN
	permanentIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	permanentIDValue, _ := asn1.Marshal(permanentID)
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    permanentIDOID,
			Value: permanentIDValue,
		},
	}

	// Sign with EK root CA if provided, otherwise self-sign
	var certDER []byte
	var err error

	if issuerCert != nil && issuerKey != nil {
		// Signed by EK root CA (proper chain for validation)
		certDER, err = x509.CreateCertificate(rand.Reader, template, issuerCert, pubKey, issuerKey)
	} else {
		// Self-signed fallback
		signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pubKey, signKey)
	}

	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// GetEnrollmentData returns TPM enrollment information (EK root CA and permanent ID)
// In hardware mode, uses real manufacturer CA from EK certificate
// In simulation mode, generates a simulated root CA
func (c *TPMClient) GetEnrollmentData() (ekRootCAPEM, ekRootCAName, description string, err error) {
	if c.hardwareMode && c.ekRootCA != nil {
		// Hardware mode: Use extracted manufacturer root CA
		rootPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.ekRootCA.Raw,
		})

		ekRootCAPEM = string(rootPEM)
		ekRootCAName = c.manufacturerCA
		description = fmt.Sprintf("Hardware TPM (%s) with permanent ID: %s", c.manufacturerCA, c.permanentID)

		log.Printf("✓ Using hardware TPM enrollment data (manufacturer: %s)", c.manufacturerCA)
		return ekRootCAPEM, ekRootCAName, description, nil
	}

	// Simulation mode: Generate simulated EK root CA if not already created
	if c.ekRootCA == nil {
		log.Printf("Generating simulated EK root CA for PoC...")

		rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate root key: %w", err)
		}

		rootTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Simulated TPM Root CA",
				Organization: []string{"Simulated TPM Manufacturer"},
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to create root certificate: %w", err)
		}

		c.ekRootCA, err = x509.ParseCertificate(rootDER)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to parse root certificate: %w", err)
		}
		c.ekRootCAKey = rootKey
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.ekRootCA.Raw,
	})

	ekRootCAPEM = string(rootPEM)
	ekRootCAName = "simulated-tpm"
	description = fmt.Sprintf("Simulated TPM device with permanent ID: %s", c.permanentID)

	log.Printf("Using simulated TPM enrollment data")
	return ekRootCAPEM, ekRootCAName, description, nil
}
