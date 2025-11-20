// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/x509"
	"fmt"
)

// validateAIKCertificateChain validates the AIK certificate chain
// against trusted AK CA root certificates
//
// The x5c parameter contains the certificate chain from the attestation statement:
//   - x5c[0]: AIK certificate (leaf)
//   - x5c[1..n-1]: Intermediate certificates
//   - x5c[n]: Root certificate (optional, usually not included)
//
// The chain is validated against trustedRoots to ensure the AIK certificate
// was issued by a trusted AK CA.
func validateAIKCertificateChain(x5c [][]byte, trustedRoots []*x509.Certificate) error {
	// If no trusted roots are configured, skip validation
	if len(trustedRoots) == 0 {
		return fmt.Errorf("AIK certificate validation is enabled but no trusted AK CA roots are configured")
	}

	if len(x5c) == 0 {
		return fmt.Errorf("no certificates in x5c chain")
	}

	// Parse the AIK certificate (first in chain)
	aikCert, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return fmt.Errorf("failed to parse AIK certificate: %w", err)
	}

	// Build a certificate pool from trusted roots
	rootPool := x509.NewCertPool()
	for _, root := range trustedRoots {
		rootPool.AddCert(root)
	}

	// Build intermediate certificate pool from remaining x5c entries
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(x5c); i++ {
		cert, err := x509.ParseCertificate(x5c[i])
		if err != nil {
			return fmt.Errorf("failed to parse intermediate certificate %d: %w", i, err)
		}
		intermediatePool.AddCert(cert)
	}

	// Verify the AIK certificate chain
	// The AIK certificate should chain to one of the trusted AK CA root certificates
	// through zero or more intermediate certificates
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := aikCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify AIK certificate chain: %w", err)
	}

	// Verify at least one valid chain was found
	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found to trusted roots")
	}

	return nil
}

// KnownTPMManufacturers lists well-known TPM manufacturer OIDs
var KnownTPMManufacturers = map[string]string{
	"2.23.133.2.1": "Intel",
	"2.23.133.2.2": "Infineon",
	"2.23.133.2.3": "STMicroelectronics",
	"2.23.133.2.4": "AMD",
	"2.23.133.2.5": "Qualcomm",
	"2.23.133.2.6": "Nuvoton",
}

// extractTPMManufacturer extracts the TPM manufacturer from a certificate
func extractTPMManufacturer(cert *x509.Certificate) (string, error) {
	// TPM manufacturer is typically in the certificate's Subject or Issuer
	// Look for TCG-specific OIDs in the certificate
	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if manufacturer, ok := KnownTPMManufacturers[oidStr]; ok {
			return manufacturer, nil
		}
	}

	return "", fmt.Errorf("TPM manufacturer OID not found in certificate")
}

// AK CA Root Certificate Management
//
// AK CA root certificates are managed via the config/acme/ak-ca-roots/ API endpoint.
// Administrators should configure trusted AK CA root certificates using:
//
//	bao write pki/config/acme/ak-ca-roots/<ca-name> \
//	  name=<ca-name> \
//	  certificate=@<path-to-root-ca.pem>
//
// For the dual PKI architecture:
// - The /pki-ak mount issues AIK certificates to devices
// - The /pki-vpn mount validates AIK certificates against AK CA roots
//
// Example setup:
//
//	# Export AK CA root certificate from /pki-ak mount
//	bao read -field=certificate pki-ak/cert/ca > ak-ca-root.pem
//
//	# Configure /pki-vpn to trust the AK CA
//	bao write pki-vpn/config/acme/ak-ca-roots/openbao-ak \
//	  name=openbao-ak \
//	  certificate=@ak-ca-root.pem
//
// Important Notes:
// 1. AK CA roots establish trust for AIK certificates
// 2. Device authorization (allow/blocklist) is handled outside OpenBao
// 3. Each certificate must be a valid X.509 CA certificate (IsCA=true)
// 4. Certificates are stored in OpenBao's encrypted storage backend
// 5. Multiple AK CAs can be configured for different device populations
