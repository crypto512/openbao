// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
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
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMClient manages TPM operations for device attestation
type TPMClient struct {
	tpm                  *attest.TPM
	ak                   *attest.AK
	permanentID          string
	ekCert               *x509.Certificate      // EK certificate from TPM
	iakCert              *x509.Certificate      // IAK certificate (manufacturer pre-provisioned or OpenBao-issued)
	iakHandle            tpmutil.Handle         // IAK key handle in TPM persistent storage
	ekRootCA             *x509.Certificate      // Manufacturer root CA from EK cert
	attestMode           string                 // "iak" = manufacturer IAK, "ak" = NewAK with OpenBao-issued IAK, "" = auto-detect
	akAuthValue          string                 // Auth value for created AK (AK mode only, empty for PoC)
	manufacturerCA       string                 // Manufacturer name (e.g., "intel", "amd", "infineon", "swtpm-manufacturer")
	caBasePath           string                 // Base path to CA certificates directory
	tpmDevice            string                 // TPM device path for low-level access
	certKeyHandle        tpmutil.Handle         // Certificate key handle in TPM (persistent 0x81010002)
	certKeyPublic        tpm2.Public            // Certificate key public portion (for CSR and pubArea)
	certKeyPrivate       tpm2.Private           // Certificate key private blob (for reloading if needed)
}

// NewTPMClient creates a new TPM client
// attestMode: "iak" = use manufacturer IAK, "ak" = use NewAK with OpenBao-issued IAK, "" = auto-detect
func NewTPMClient(tpmPath string, caBasePath string, attestMode string) (*TPMClient, error) {
	log.Printf("Attempting to open TPM")
	log.Printf("CA certificates base path: %s", caBasePath)
	if attestMode != "" {
		log.Printf("Attestation mode: %s", attestMode)
	}

	// Open TPM with auto-detection
	// go-attestation will try /dev/tpmrm0, /dev/tpm0, and Windows TPM automatically
	// For swtpm, the entrypoint script creates a symlink at /dev/tpmrm0
	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}

	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w\n\nHint: Ensure TPM is available via:\n  - Hardware TPM: /dev/tpmrm0 or /dev/tpm0\n  - SWTPM: Set TPM_SWTPM_HOST and TPM_SWTPM_PORT environment variables", err)
	}

	log.Printf("✓ TPM detected and opened successfully")

	client := &TPMClient{
		tpm:        tpm,
		caBasePath: caBasePath,
		tpmDevice:  tpmPath,
		attestMode: attestMode,
	}

	// Get EK certificates from TPM
	eks, err := tpm.EKs()
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to get EKs from TPM: %w", err)
	}

	if len(eks) > 0 {
		log.Printf("Found %d EK(s) from TPM", len(eks))

		// Use the first EK (typically RSA EK)
		ek := eks[0]

		if ek.Certificate != nil {
			log.Printf("✓ EK certificate found in TPM NVRAM")
			client.ekCert = ek.Certificate

			// Extract manufacturer root CA from EK certificate chain
			if err := client.extractManufacturerCA(); err != nil {
				tpm.Close()
				return nil, fmt.Errorf("failed to extract manufacturer CA: %w", err)
			}
			log.Printf("✓ Manufacturer root CA loaded: %s", client.manufacturerCA)
		} else {
			tpm.Close()
			return nil, fmt.Errorf("EK found but no certificate in NVRAM - TPM requires EK certificate")
		}
	} else {
		tpm.Close()
		return nil, fmt.Errorf("no EKs found in TPM")
	}

	// Decide attestation mode: manufacturer IAK or NewAK with OpenBao-issued IAK
	if attestMode == "iak" || (attestMode == "" && client.hasManufacturerIAK()) {
		// IAK Mode: Use manufacturer-provisioned IAK certificate
		log.Println("  → Using manufacturer-provisioned IAK certificate...")
		err = client.readManufacturerIAKCertificate()
		if err != nil {
			tpm.Close()
			if attestMode == "iak" {
				return nil, fmt.Errorf("IAK mode requires manufacturer-provisioned IAK certificate but not found: %w", err)
			}
			// Auto-detect mode - fallback to AK mode
			log.Printf("⚠  Manufacturer IAK not available, falling back to AK mode")
		} else {
			log.Printf("✓ Manufacturer-provisioned IAK certificate found")

			// Find the IAK key handle in persistent storage
			iakHandle, err := client.findIAKHandle()
			if err != nil {
				tpm.Close()
				return nil, fmt.Errorf("IAK certificate found but key handle not accessible: %w", err)
			}

			client.iakHandle = iakHandle
			log.Printf("✓ Manufacturer IAK ready for attestation (handle: 0x%X)", iakHandle)

			// Extract permanent ID from EK
			if err := client.extractPermanentID(); err != nil {
				tpm.Close()
				return nil, fmt.Errorf("failed to extract permanent ID: %w", err)
			}

			// Create TPM-protected certificate key under IAK parent
			log.Println("  → Creating TPM-protected certificate signing key...")
			err = client.createPersistentCertificateKey(iakHandle)
			if err != nil {
				tpm.Close()
				return nil, fmt.Errorf("failed to create TPM certificate key: %w", err)
			}

			return client, nil
		}
	}

	// AK Mode: Create persistent AK with known handle for TPM2_Certify
	log.Println("  → Using persistent AK with OpenBao-issued IAK certificate...")
	if attestMode == "" {
		log.Println("  (auto-detected: no manufacturer IAK available)")
		client.attestMode = "ak" // Set attestMode so NeedsIAKProvisioning() works
	}

	// Create persistent AK for production use
	// This gives us a known handle for TPM2_Certify operations
	log.Println("Creating persistent Attestation Key (AK) in TPM...")

	// Use persistent handle 0x81010002 for the AK (EK is at 0x81010001)
	persistentAKHandle := tpmutil.Handle(0x81010002)

	err = client.createPersistentAK(persistentAKHandle)
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to create persistent AK: %w", err)
	}

	client.iakHandle = persistentAKHandle // Reuse iakHandle field for the AK handle
	log.Printf("✓ Persistent AK created successfully (handle: 0x%X)", persistentAKHandle)
	log.Println("  Note: AK private key is sealed inside TPM (never exported)")
	log.Println("  Note: AK is stored persistently for production use")

	// Extract permanent identifier from EK certificate
	if err := client.extractPermanentID(); err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to extract permanent ID: %w", err)
	}

	// Create TPM-protected certificate key under AK parent
	log.Println("  → Creating TPM-protected certificate signing key...")
	err = client.createPersistentCertificateKey(persistentAKHandle)
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to create TPM certificate key: %w", err)
	}

	return client, nil
}

// openTPMDevice opens the TPM device, supporting both device files and Unix sockets
func (c *TPMClient) openTPMDevice() (io.ReadWriteCloser, error) {
	// Use tpmutil.OpenTPM which handles both /dev/tpmrm0 device files and Unix sockets
	return tpmutil.OpenTPM(c.tpmDevice)
}

// hasManufacturerIAK checks if the TPM has a manufacturer-provisioned IAK certificate
func (c *TPMClient) hasManufacturerIAK() bool {
	// Try to read IAK from NVRAM (lightweight check)
	const nvIndexIAKRSA tpmutil.Handle = 0x01C00012

	rwc, err := c.openTPMDevice()
	if err != nil {
		return false
	}
	defer rwc.Close()

	_, err = tpm2.NVReadPublic(rwc, nvIndexIAKRSA)
	return err == nil
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

// readManufacturerIAKCertificate reads the manufacturer pre-provisioned IAK certificate from TPM NVRAM
// This function enforces that a manufacturer-provisioned IAK certificate MUST exist
func (c *TPMClient) readManufacturerIAKCertificate() error {
	// TCG-defined NVRAM indices for manufacturer-provisioned certificates
	// See TCG TPM 2.0 Keys for Device Identity and Attestation specification
	const (
		// IAK RSA certificate index
		nvIndexIAKRSA tpmutil.Handle = 0x01C00012
		// IAK ECC certificate index
		nvIndexIAKECC tpmutil.Handle = 0x01C0001A
	)

	// Try to open TPM device for low-level access
	var rwc *os.File
	var err error

	// Try /dev/tpmrm0 first (resource manager), then /dev/tpm0
	tpmDevices := []string{c.tpmDevice, "/dev/tpmrm0", "/dev/tpm0"}
	for _, device := range tpmDevices {
		rwc, err = os.OpenFile(device, os.O_RDWR, 0)
		if err == nil {
			log.Printf("✓ Opened TPM device for NVRAM access: %s", device)
			break
		}
	}

	if err != nil {
		return fmt.Errorf("failed to open TPM device for NVRAM access: %w\n"+
			"Manufacturer pre-provisioned IAK certificate is REQUIRED for this PoC.\n"+
			"This TPM does not appear to support low-level NVRAM access.", err)
	}
	defer rwc.Close()

	// Try to read IAK certificate from NVRAM indices
	nvIndices := []struct {
		handle tpmutil.Handle
		name   string
	}{
		{nvIndexIAKRSA, "IAK RSA"},
		{nvIndexIAKECC, "IAK ECC"},
	}

	for _, idx := range nvIndices {
		log.Printf("Attempting to read %s certificate from NVRAM index 0x%X...", idx.name, idx.handle)

		certData, err := c.readTPMNVRAM(rwc, idx.handle)
		if err != nil {
			log.Printf("  %s certificate not found at 0x%X: %v", idx.name, idx.handle, err)
			continue
		}

		// Try to parse as X.509 certificate (DER format)
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			log.Printf("  Failed to parse %s certificate from NVRAM: %v", idx.name, err)
			continue
		}

		// Validate this is an attestation key certificate
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			log.Printf("  Warning: Certificate at 0x%X does not have DigitalSignature key usage", idx.handle)
		}

		c.iakCert = cert
		log.Printf("✓ Found manufacturer-provisioned %s certificate", idx.name)
		log.Printf("  Subject: %s", cert.Subject.String())
		log.Printf("  Issuer: %s", cert.Issuer.String())
		log.Printf("  Serial: %s", cert.SerialNumber.String())
		log.Printf("  Valid: %s to %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		return nil
	}

	// No IAK certificate found at any expected index
	return fmt.Errorf("manufacturer pre-provisioned IAK certificate NOT FOUND in TPM NVRAM\n"+
		"This PoC requires a manufacturer pre-provisioned IAK certificate.\n"+
		"Tried NVRAM indices: 0x%X (IAK RSA), 0x%X (IAK ECC)\n\n"+
		"IMPORTANT: This TPM does not appear to have a manufacturer-provisioned IAK certificate.\n"+
		"Production TPM devices from major manufacturers (Intel, AMD, STMicroelectronics, etc.)\n"+
		"typically include pre-provisioned IDevID and IAK certificates in NVRAM.\n\n"+
		"Possible reasons:\n"+
		"1. This is a discrete TPM chip without pre-provisioned certificates\n"+
		"2. The TPM was cleared/reset and lost the provisioned certificates\n"+
		"3. The manufacturer did not provision IAK certificates for this TPM model\n"+
		"4. The certificates are at non-standard NVRAM indices\n\n"+
		"For production deployment, contact your TPM manufacturer for proper certificate provisioning.",
		nvIndexIAKRSA, nvIndexIAKECC)
}

// readTPMNVRAM reads data from a TPM NVRAM index using legacy tpm2 API
func (c *TPMClient) readTPMNVRAM(rwc *os.File, nvIndex tpmutil.Handle) ([]byte, error) {
	// Read public area to get the data size
	pub, err := tpm2.NVReadPublic(rwc, nvIndex)
	if err != nil {
		return nil, fmt.Errorf("NV index does not exist or cannot be read: %w", err)
	}

	dataSize := pub.DataSize

	if dataSize == 0 {
		return nil, fmt.Errorf("NV index exists but contains no data")
	}

	log.Printf("  NVRAM index 0x%X contains %d bytes", nvIndex, dataSize)

	// Read the entire data
	// The TPM may have read size limits, so we use NVRead with proper auth
	data, err := tpm2.NVReadEx(rwc, nvIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from NVRAM: %w", err)
	}

	log.Printf("  Successfully read %d bytes from NVRAM", len(data))
	return data, nil
}

// GetIAKProvisioningData returns the data needed to request IAK certificate from OpenBao
// This is used in AK mode when manufacturer IAK is not available
func (c *TPMClient) GetIAKProvisioningData() (akPublicDER []byte, ekCertPEM string, err error) {
	if c.iakHandle == 0 {
		return nil, "", fmt.Errorf("persistent AK not created - cannot get provisioning data")
	}

	// Open TPM to read AK public key
	rwc, err := c.openTPMDevice()
	if err != nil {
		return nil, "", fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	// Read AK public key from persistent handle
	akPub, _, _, err := tpm2.ReadPublic(rwc, c.iakHandle)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read AK public: %w", err)
	}

	// Extract RSA public key
	if akPub.Type != tpm2.AlgRSA {
		return nil, "", fmt.Errorf("unsupported AK type: %v (expected RSA)", akPub.Type)
	}

	// Create standard RSA public key
	akRSAPub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(akPub.RSAParameters.ModulusRaw),
		E: int(akPub.RSAParameters.Exponent()),
	}

	log.Printf("Preparing IAK provisioning data:")
	log.Printf("  AK Public Key: bits=%d", akRSAPub.N.BitLen())
	log.Printf("  AK Modulus (first 32 bytes): %x", akRSAPub.N.Bytes()[:32])

	// Marshal AK public key to DER format (PKIX/SPKI)
	akPublicDER, err = x509.MarshalPKIXPublicKey(akRSAPub)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal AK public key: %w", err)
	}

	// Encode EK certificate to PEM
	ekCertPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.ekCert.Raw,
	})

	return akPublicDER, string(ekCertPEMBytes), nil
}

// SetIAKCertificate stores the OpenBao-issued IAK certificate
func (c *TPMClient) SetIAKCertificate(iakCertPEM string) error {
	block, _ := pem.Decode([]byte(iakCertPEM))
	if block == nil {
		return fmt.Errorf("failed to decode IAK certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse IAK certificate: %w", err)
	}

	c.iakCert = cert
	log.Printf("✓ IAK certificate stored successfully")
	log.Printf("  Subject: %s", cert.Subject.String())
	log.Printf("  Issuer: %s", cert.Issuer.String())
	log.Printf("  Valid: %s to %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

	return nil
}

// NeedsIAKProvisioning returns true if IAK certificate needs to be provisioned from OpenBao
// This is true for AK mode when the IAK certificate hasn't been provisioned yet
func (c *TPMClient) NeedsIAKProvisioning() bool {
	return c.attestMode == "ak" && c.iakCert == nil
}

// findIAKHandle finds the persistent TPM handle for the manufacturer-provisioned IAK
// by matching the public key in the IAK certificate with persistent handle public keys
func (c *TPMClient) findIAKHandle() (tpmutil.Handle, error) {
	if c.iakCert == nil {
		return 0, fmt.Errorf("IAK certificate not loaded")
	}

	// Open TPM device for handle enumeration
	rwc, err := c.openTPMDevice()
	if err != nil {
		return 0, fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	log.Printf("Searching for IAK key handle in persistent storage...")

	// Get IAK certificate public key for comparison
	iakCertPubKey, ok := c.iakCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("IAK certificate public key is not RSA (type: %T)", c.iakCert.PublicKey)
	}

	// Try known IAK persistent handles first (TCG-defined locations)
	knownHandles := []tpmutil.Handle{
		0x81010012, // Common IAK RSA handle
		0x81010013, // Common IAK ECC handle
		0x81010002, // Alternative location
		0x81010003, // Alternative location
	}

	for _, handle := range knownHandles {
		log.Printf("  Checking known handle 0x%X...", handle)

		pub, _, _, err := tpm2.ReadPublic(rwc, handle)
		if err != nil {
			// Handle doesn't exist or can't be read
			continue
		}

		// Extract public key from handle
		handlePubKey, err := pub.Key()
		if err != nil {
			log.Printf("    Failed to extract key: %v", err)
			continue
		}

		// Compare with IAK certificate public key
		rsaHandleKey, ok := handlePubKey.(*rsa.PublicKey)
		if !ok {
			// Not an RSA key, skip
			continue
		}

		if rsaHandleKey.N.Cmp(iakCertPubKey.N) == 0 && rsaHandleKey.E == iakCertPubKey.E {
			log.Printf("✓ Found IAK key handle at known location: 0x%X", handle)
			return handle, nil
		}
	}

	log.Printf("  IAK not found at known handles, enumerating all persistent handles...")

	// Enumerate all persistent handles
	// TPM persistent handles are in range 0x81000000 - 0x81FFFFFF
	const (
		persistentFirst = 0x81000000
		persistentLast  = 0x81FFFFFF
	)

	handles, moreData, err := tpm2.GetCapability(rwc, tpm2.CapabilityHandles, 1, persistentFirst)
	if err != nil {
		return 0, fmt.Errorf("failed to enumerate persistent handles: %w", err)
	}

	log.Printf("  Found %d persistent handles to check", len(handles))

	// Check each persistent handle
	for _, h := range handles {
		handle := tpmutil.Handle(h.(uint32))

		pub, _, _, err := tpm2.ReadPublic(rwc, handle)
		if err != nil {
			continue
		}

		// Extract public key
		handlePubKey, err := pub.Key()
		if err != nil {
			continue
		}

		// Compare with IAK certificate public key
		rsaHandleKey, ok := handlePubKey.(*rsa.PublicKey)
		if !ok {
			// Not an RSA key, skip
			continue
		}

		if rsaHandleKey.N.Cmp(iakCertPubKey.N) == 0 && rsaHandleKey.E == iakCertPubKey.E {
			log.Printf("✓ Found IAK key handle: 0x%X", handle)
			return handle, nil
		}
	}

	// If there's more data, continue searching
	if moreData {
		log.Printf("  Warning: More persistent handles available but not checked (implementation limitation)")
	}

	return 0, fmt.Errorf("IAK key handle not found in persistent storage\n"+
		"The IAK certificate exists in NVRAM but the corresponding key handle is not accessible.\n"+
		"This could mean:\n"+
		"  1. The IAK key was cleared but the certificate was not\n"+
		"  2. The IAK key is at a non-standard persistent handle location\n"+
		"  3. Permission issues accessing the IAK key handle\n\n"+
		"Try running: sudo tpm2_getcap handles-persistent\n"+
		"Then compare with certificate public key modulus.")
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
	case contains(issuerOrg, "SWTPM") || contains(issuerCN, "SWTPM"):
		c.manufacturerCA = "swtpm-manufacturer"
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

	// Load the real manufacturer root CA from the ca directory
	log.Printf("Note: EK certificate issued by: %s", c.ekCert.Issuer.String())

	if err := c.loadManufacturerRootCA(); err != nil {
		log.Printf("Warning: Failed to load manufacturer root CA: %v", err)
		log.Printf("⚠️  This will cause enrollment to fail")
		return fmt.Errorf("failed to load manufacturer root CA: %w", err)
	}

	log.Printf("✓ Manufacturer root CA loaded successfully: %s", c.ekRootCA.Subject.CommonName)
	return nil
}

// loadManufacturerRootCA loads the real manufacturer root CA certificate from the ca directory
func (c *TPMClient) loadManufacturerRootCA() error {
	// Map of manufacturer to their root CA certificate filenames
	rootCAFiles := map[string][]string{
		"swtpm-manufacturer": {"SWTPM Manufacturer Root CA.crt"},
		"stmicro":            {"ST TPM Root Certificate.crt", "GlobalSign Trusted Computing CA.crt"},
		"intel":              {"Intel TPM Root Certificate Authority 2013.crt", "Intel TPM EK intermediate for TPM_EK_ID.crt"},
		"infineon":           {"Infineon OPTIGA(TM) TPM 2.0 ECC CA 012.crt", "Infineon OPTIGA(TM) RSA CA 012.crt"},
		"nuvoton":            {"Nuvoton TPM Root CA 2111.cer", "Nuvoton TPM Root CA 1110.cer"},
		"amd":                {"AMD fTPM EK Certificate Signing Root CA.crt"},
	}

	// Get the list of possible root CA files for this manufacturer
	caFiles, ok := rootCAFiles[c.manufacturerCA]
	if !ok {
		return fmt.Errorf("no root CA mapping for manufacturer: %s", c.manufacturerCA)
	}

	// Try to load each potential root CA file
	for _, caFile := range caFiles {
		caPath := filepath.Join(c.caBasePath, c.manufacturerCA, "RootCA", caFile)

		// Try to read the certificate file
		certPEM, err := os.ReadFile(caPath)
		if err != nil {
			// File doesn't exist, try next one
			continue
		}

		// Decode PEM
		block, _ := pem.Decode(certPEM)
		if block == nil {
			// Try DER format
			cert, err := x509.ParseCertificate(certPEM)
			if err != nil {
				continue
			}
			if cert.IsCA {
				c.ekRootCA = cert
				log.Printf("✓ Loaded root CA from: %s (DER format)", caPath)
				return nil
			}
		} else {
			// Parse PEM certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			if cert.IsCA {
				c.ekRootCA = cert
				log.Printf("✓ Loaded root CA from: %s", caPath)
				return nil
			}
		}
	}

	return fmt.Errorf("no valid root CA certificate found for manufacturer: %s", c.manufacturerCA)
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
	if c.ekCert == nil {
		return fmt.Errorf("EK certificate not available")
	}

	// Extract permanent ID from EK certificate
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

// TPMSigner implements crypto.Signer using a TPM-protected key
type TPMSigner struct {
	tpmDevice  string
	keyHandle  tpmutil.Handle
	publicKey  *rsa.PublicKey
}

// Public returns the public key
func (s *TPMSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the TPM
func (s *TPMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rwc, err := tpmutil.OpenTPM(s.tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	// TPM2_Sign
	sig, err := tpm2.Sign(
		rwc,
		s.keyHandle,     // Certificate key handle
		"",              // No auth for PoC
		digest,          // Data to sign (already hashed by x509)
		nil,             // Validation (unused)
		&tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Sign failed: %w", err)
	}

	// Extract signature bytes from RSASSA signature
	if sig.RSA == nil {
		return nil, fmt.Errorf("expected RSA signature")
	}

	return sig.RSA.Signature, nil
}

// GenerateCSR generates a Certificate Signing Request for the TPM-protected certificate key
func (c *TPMClient) GenerateCSR(commonName string, sanDNS []string, sanIPs []string) (string, error) {
	log.Printf("Generating CSR for CN=%s", commonName)
	log.Printf("  Using TPM-protected key for signing (handle: 0x%X)", c.certKeyHandle)

	// Extract public key from TPM public structure
	rsaParams := c.certKeyPublic.RSAParameters
	if rsaParams == nil {
		return "", fmt.Errorf("certificate key is not RSA")
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaParams.ModulusRaw),
		E: 65537, // F4
	}

	// Create TPM signer
	signer := &TPMSigner{
		tpmDevice: c.tpmDevice,
		keyHandle: c.certKeyHandle,
		publicKey: pubKey,
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: sanDNS,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	log.Printf("✓ CSR signed by TPM (private key never exported)")

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

	if c.tpm == nil {
		return "", fmt.Errorf("TPM not available")
	}

	// Use real TPM attestation
	return c.generateHardwareAttestation(keyAuthorization, qualifyingData[:])
}

// quoteWithIAKHandle generates a TPM Quote using the manufacturer-provisioned IAK handle
// certifyWithAK uses TPM2_Certify to certify the certificate key (WebAuthn format)
// This generates TPM_ST_ATTEST_CERTIFY (0x8017) instead of TPM_ST_ATTEST_QUOTE (0x8018)
func (c *TPMClient) certifyWithAK(qualifyingData []byte, akHandle tpmutil.Handle) (*attest.Quote, error) {
	// Open TPM device for certify operation
	rwc, err := c.openTPMDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	log.Printf("Generating TPM2_Certify for certificate key with AK (handle: 0x%X)...", akHandle)

	// Use the TPM-protected certificate key (already loaded at persistent handle)
	// This key was created inside the TPM with FixedTPM|FixedParent attributes
	// It has a sensitive area, so TPM2_Certify will work!
	certKeyHandle := c.certKeyHandle
	log.Printf("✓ Using TPM-protected certificate key (persistent handle: 0x%X)", certKeyHandle)

	// AK created without FlagUserWithAuth, so no password needed (PoC only)
	akAuth := ""
	log.Printf("Using no auth for AK (PoC - no FlagUserWithAuth set)")

	// TPM2_Certify: Certify that the certificate key is loaded in the TPM
	// Parameters:
	// - objectHandle: The key being certified (the certificate key)
	// - signHandle: The key used to sign the certification (the AK)
	// - qualifyingData: The key authorization hash
	// Returns: attestation data (TPMS_ATTEST), signature bytes, error
	attestation, sigBytes, err := tpm2.Certify(
		rwc,
		"",                 // password for object being certified (cert key - no auth)
		akAuth,             // password for signing key (AK)
		certKeyHandle,      // Object being certified (the certificate key)
		akHandle,           // Signing key (the AK)
		qualifyingData,     // The key authorization hash
	)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Certify failed: %w", err)
	}

	log.Printf("✓ TPM2_Certify successful (WebAuthn TPM attestation format)")
	log.Printf("  Attestation (certInfo) size: %d bytes", len(attestation))
	log.Printf("  Signature structure size: %d bytes", len(sigBytes))
	if len(sigBytes) >= 32 {
		log.Printf("  Signature (first 32 bytes): %x", sigBytes[:32])
	}
	if len(attestation) >= 32 {
		log.Printf("  CertInfo (first 32 bytes): %x", attestation[:32])
	}

	// Extract raw signature bytes from TPMT_SIGNATURE structure
	// TPMT_SIGNATURE for RSASSA:
	//   uint16 sigAlg (0x0014 = TPM_ALG_RSASSA)
	//   uint16 hash (0x000B = TPM_ALG_SHA256)
	//   uint16 size (signature length in bytes)
	//   byte[] signature (raw signature bytes)
	if len(sigBytes) < 6 {
		return nil, fmt.Errorf("signature too short: %d bytes", len(sigBytes))
	}

	// Parse TPMT_SIGNATURE header
	sigAlg := binary.BigEndian.Uint16(sigBytes[0:2])
	hashAlg := binary.BigEndian.Uint16(sigBytes[2:4])
	sigSize := binary.BigEndian.Uint16(sigBytes[4:6])

	log.Printf("  TPMT_SIGNATURE header: alg=0x%04x hash=0x%04x size=%d", sigAlg, hashAlg, sigSize)

	if sigAlg != 0x0014 { // TPM_ALG_RSASSA
		return nil, fmt.Errorf("unexpected signature algorithm: 0x%04x (expected RSASSA 0x0014)", sigAlg)
	}

	if len(sigBytes) < 6+int(sigSize) {
		return nil, fmt.Errorf("signature buffer too short: have %d, need %d", len(sigBytes), 6+int(sigSize))
	}

	// Extract raw signature bytes (skip the 6-byte header)
	rawSignature := sigBytes[6 : 6+int(sigSize)]
	log.Printf("  Extracted raw signature: %d bytes", len(rawSignature))
	if len(rawSignature) >= 32 {
		log.Printf("  Raw signature (first 32 bytes): %x", rawSignature[:32])
	}

	// Convert to attest.Quote format for compatibility with existing code
	quote := &attest.Quote{
		Quote:     attestation,    // TPMS_ATTEST structure with type CERTIFY (0x8017)
		Signature: rawSignature,   // Raw signature bytes (extracted from TPMT_SIGNATURE)
	}

	return quote, nil
}

// createPersistentAK creates an Attestation Key and stores it persistently in TPM
// This is the production-ready approach for AK mode
func (c *TPMClient) createPersistentAK(persistentHandle tpmutil.Handle) error {
	rwc, err := c.openTPMDevice()
	if err != nil {
		return fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	// Check if AK already exists at this handle
	_, _, _, err = tpm2.ReadPublic(rwc, persistentHandle)
	if err == nil {
		log.Printf("AK already exists at handle 0x%X, using existing key", persistentHandle)
		// Set the auth value for the existing AK (same as we would use for new AK)
		c.akAuthValue = ""  // Empty auth for PoC
		return nil
	}

	// Create Attestation Key (AK) directly using CreatePrimary
	// Using CreatePrimary instead of CreateKey avoids auth complications
	// CreatePrimary creates a key directly under the Owner hierarchy
	log.Println("Creating Attestation Key (AK)...")
	akTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		// AK attributes: TPM-protected, signing key with user authorization
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagSign | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	// Create the AK as a primary key under Owner hierarchy (no auth for PoC)
	// This avoids the auth complications of creating a child key under SRK
	transientAK, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", akTemplate)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	// Store empty auth value for later use in TPM2_Certify
	c.akAuthValue = ""

	// Make AK persistent
	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, transientAK, persistentHandle)
	if err != nil {
		tpm2.FlushContext(rwc, transientAK)
		return fmt.Errorf("failed to persist AK: %w", err)
	}

	// Flush the transient handle now that it's persisted
	tpm2.FlushContext(rwc, transientAK)

	log.Printf("✓ AK created and persisted (handle: 0x%X)", persistentHandle)
	return nil
}

// createPersistentCertificateKey creates a persistent certificate signing key inside the TPM
// The key is created as a PRIMARY key directly under the Owner hierarchy
// Key attributes: FixedTPM | FixedParent | SensitiveDataOrigin (non-exportable, TPM-generated)
func (c *TPMClient) createPersistentCertificateKey(akHandle tpmutil.Handle) error {
	persistentHandle := tpmutil.Handle(0x81010003) // Persistent handle for certificate key

	// Open TPM device for low-level operations
	rwc, err := c.openTPMDevice()
	if err != nil {
		return fmt.Errorf("failed to open TPM device: %w", err)
	}
	defer rwc.Close()

	// Check if certificate key already exists
	pub, _, _, err := tpm2.ReadPublic(rwc, persistentHandle)
	if err == nil {
		log.Printf("Certificate key already exists at handle 0x%X, using existing key", persistentHandle)
		c.certKeyHandle = persistentHandle
		c.certKeyPublic = pub
		return nil
	}

	log.Println("Creating certificate signing key inside TPM...")
	log.Println("  This key will be TPM-protected (FixedTPM|FixedParent)")
	log.Println("  Private key will NEVER leave the TPM")

	// Define certificate key template (NON-EXPORTABLE, TPM-GENERATED)
	certKeyTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |           // Key bound to this TPM (can't be exported)
			tpm2.FlagFixedParent |         // Key bound to parent hierarchy (can't be moved)
			tpm2.FlagSensitiveDataOrigin | // Key generated inside TPM
			tpm2.FlagUserWithAuth |        // Key has auth value (empty for PoC)
			tpm2.FlagSign,                 // Key can sign data
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	// Create the certificate key as a PRIMARY key under Owner hierarchy
	// This avoids parent-child relationship issues (AK is not a storage key)
	transientHandle, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleOwner,    // Create directly under Owner hierarchy
		tpm2.PCRSelection{}, // No PCR binding
		"",                  // Owner auth (empty for PoC)
		"",                  // Cert key auth (no auth for PoC)
		certKeyTemplate,
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate key: %w", err)
	}

	log.Printf("✓ Certificate key created inside TPM as primary key")

	// Make certificate key persistent
	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, transientHandle, persistentHandle)
	if err != nil {
		tpm2.FlushContext(rwc, transientHandle)
		return fmt.Errorf("failed to persist certificate key: %w", err)
	}

	// Flush the transient handle now that it's persisted
	tpm2.FlushContext(rwc, transientHandle)

	log.Printf("✓ Certificate key persisted (handle: 0x%X)", persistentHandle)
	log.Printf("  Attributes: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Sign")
	log.Printf("  Security: Private key NEVER leaves TPM, cannot be exported")

	// Read back the actual public key from TPM (contains the generated modulus)
	actualPub, _, _, err := tpm2.ReadPublic(rwc, persistentHandle)
	if err != nil {
		return fmt.Errorf("failed to read back public key: %w", err)
	}

	// Store in client struct
	c.certKeyHandle = persistentHandle
	c.certKeyPublic = actualPub  // Store the actual public key from TPM

	return nil
}

// getAKHandle gets the TPM handle for the AK - now just returns the persistent handle
// This is simplified since we use persistent AK storage in AK mode
func (c *TPMClient) getAKHandle() (tpmutil.Handle, error) {
	// In AK mode, we store the persistent AK handle in c.iakHandle
	if c.iakHandle == 0 {
		return 0, fmt.Errorf("persistent AK not created")
	}
	return c.iakHandle, nil
}

// generateHardwareAttestation generates attestation using real TPM hardware
func (c *TPMClient) generateHardwareAttestation(keyAuthorization string, qualifyingData []byte) (string, error) {
	log.Printf("✓ Using hardware TPM for attestation")

	var quote *attest.Quote
	var err error
	var akHandle tpmutil.Handle

	if c.attestMode == "iak" {
		// IAK Mode: Use manufacturer-provisioned IAK
		log.Printf("IAK Mode: Using manufacturer-provisioned IAK for TPM2_Certify")
		akHandle = c.iakHandle
	} else {
		// AK Mode: Get handle for NewAK created by go-attestation
		log.Printf("AK Mode: Using NewAK for TPM2_Certify")
		// Get the AK handle from go-attestation's internal state
		// The AK is already loaded in the TPM by go-attestation
		akHandle, err = c.getAKHandle()
		if err != nil {
			return "", fmt.Errorf("failed to get AK handle: %w", err)
		}
		log.Printf("Found NewAK handle: 0x%X", akHandle)
	}

	// Use TPM2_Certify (WebAuthn format) instead of TPM2_Quote
	quote, err = c.certifyWithAK(qualifyingData, akHandle)
	if err != nil {
		return "", fmt.Errorf("TPM2_Certify failed: %w", err)
	}

	log.Printf("✓ Hardware TPM Certify successful")

	// Get AIK certificate (contains the AK's public key)
	aikCert, err := c.createAIKCertificateHardware()
	if err != nil {
		return "", fmt.Errorf("failed to create AIK certificate: %w", err)
	}

	// Create pubArea for the certificate key (the key that was certified by TPM2_Certify)
	// This matches what OpenBao expects: pubArea describes the certificate signing key
	// Now using the TPM public structure directly
	rsaParams := c.certKeyPublic.RSAParameters
	if rsaParams == nil {
		return "", fmt.Errorf("certificate key is not RSA")
	}

	// Encode the ACTUAL TPM public structure (not a reconstructed one)
	// This ensures the NAME hash matches what's in the certInfo
	pubArea, err := c.certKeyPublic.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode certificate key public area: %w", err)
	}
	log.Printf("✓ Encoded pubArea from TPM public structure (%d bytes)", len(pubArea))

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

// GetPermanentID returns the TPM permanent identifier
func (c *TPMClient) GetPermanentID() string {
	return c.permanentID
}

// Close closes the TPM connection
func (c *TPMClient) Close() error {
	if c.tpm != nil {
		if c.ak != nil {
			c.ak.Close(c.tpm)
		}
		return c.tpm.Close()
	}
	return nil
}

// createAIKCertificateHardware returns the manufacturer pre-provisioned IAK certificate or OpenBao-issued IAK
func (c *TPMClient) createAIKCertificateHardware() (*x509.Certificate, error) {
	// In hardware mode, we use the manufacturer pre-provisioned IAK certificate
	// that was read from TPM NVRAM during initialization
	if c.iakCert == nil {
		return nil, fmt.Errorf("manufacturer pre-provisioned IAK certificate is not available\n"+
			"This should have been loaded during TPM initialization.\n"+
			"The IAK certificate MUST be present in TPM NVRAM at index 0x01C00012 (RSA) or 0x01C0001A (ECC)")
	}

	log.Printf("✓ Using manufacturer pre-provisioned IAK certificate")
	log.Printf("  Subject: %s", c.iakCert.Subject.String())
	log.Printf("  Issuer: %s", c.iakCert.Issuer.String())

	return c.iakCert, nil
}

// GetEnrollmentData returns TPM enrollment information (EK root CA and permanent ID)
func (c *TPMClient) GetEnrollmentData() (ekRootCAPEM, ekRootCAName, description string, err error) {
	if c.ekRootCA == nil {
		return "", "", "", fmt.Errorf("manufacturer root CA not available")
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.ekRootCA.Raw,
	})

	ekRootCAPEM = string(rootPEM)
	ekRootCAName = c.manufacturerCA
	description = fmt.Sprintf("TPM (%s) with permanent ID: %s", c.manufacturerCA, c.permanentID)

	log.Printf("✓ Using TPM enrollment data (manufacturer: %s)", c.manufacturerCA)
	return ekRootCAPEM, ekRootCAName, description, nil
}
