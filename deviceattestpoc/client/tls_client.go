// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc/credentials"
)

// NewTLSCredentials creates TLS credentials for server verification only (no client cert)
func NewTLSCredentials(serverCACertPath string) (credentials.TransportCredentials, error) {
	caCert, err := os.ReadFile(serverCACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse server CA cert")
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}), nil
}

// NewMTLSCredentials creates mTLS credentials using agent cert and TPM-backed key
// This is a simplified version that loads the key from PEM (for keys that have been exported)
// For TPM-backed keys, use NewMTLSCredentialsWithTPM instead
func NewMTLSCredentials(serverCACertPath, clientCertPEM, clientKeyPEM string) (credentials.TransportCredentials, error) {
	// Load server CA
	caCert, err := os.ReadFile(serverCACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse server CA cert")
	}

	// Load client certificate and key
	cert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// MTLSConfig holds configuration for mTLS with TPM-backed key
type MTLSConfig struct {
	ServerCAPath   string
	AgentCertPEM   string
	AgentKeyPriv   []byte
	AgentKeyPub    []byte
	TPMClient      *TPMClient
}

// NewMTLSCredentialsWithTPM creates mTLS credentials using TPM-backed agent key
// The key operations are performed through the TPM
func NewMTLSCredentialsWithTPM(cfg *MTLSConfig) (credentials.TransportCredentials, *CertKey, error) {
	// Load server CA
	caCert, err := os.ReadFile(cfg.ServerCAPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read server CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, nil, fmt.Errorf("failed to parse server CA cert")
	}

	// Load agent key from TPM
	agentKey, err := cfg.TPMClient.LoadCertKey(cfg.AgentKeyPriv, cfg.AgentKeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load agent key from TPM: %w", err)
	}

	// Parse agent certificate
	block, _ := pem.Decode([]byte(cfg.AgentCertPEM))
	if block == nil {
		cfg.TPMClient.CloseCertKey(agentKey)
		return nil, nil, fmt.Errorf("failed to decode agent certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		cfg.TPMClient.CloseCertKey(agentKey)
		return nil, nil, fmt.Errorf("failed to parse agent certificate: %w", err)
	}

	// Create TLS certificate with TPM-backed signer
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  &tpmCertSigner{tpmClient: cfg.TPMClient, certKey: agentKey},
		Leaf:        cert,
	}

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})

	return creds, agentKey, nil
}

// tpmCertSigner implements crypto.Signer for TPM-backed CertKey
type tpmCertSigner struct {
	tpmClient *TPMClient
	certKey   *CertKey
}

func (s *tpmCertSigner) Public() crypto.PublicKey {
	return s.certKey.pubKey
}

func (s *tpmCertSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.tpmClient.SignWithCertKey(s.certKey, digest, opts)
}

// GetServerCAPath returns the default server CA path
func GetServerCAPath() string {
	if path := os.Getenv("SERVER_CA_PATH"); path != "" {
		return path
	}
	return "/openbao-data/grpc-ca.pem"
}

// TOFUResult holds the result of a TOFU (Trust On First Use) TLS connection
type TOFUResult struct {
	CAPem   string // CA certificate chain in PEM format
	SPKIPin string // Verified SPKI pin
}

// NewTLSCredentialsFromPEM creates TLS credentials from a PEM-encoded CA certificate
func NewTLSCredentialsFromPEM(caPEM string) (credentials.TransportCredentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("failed to parse server CA cert from PEM")
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}), nil
}

// NewTLSCredentialsWithTOFU creates TLS credentials for TOFU bootstrap.
// It connects without verifying the server certificate against a CA, but instead
// verifies that the server's certificate chain contains a certificate matching
// the expected SPKI pin. On success, it returns the CA chain for persistence.
//
// The returned credentials include a custom VerifyPeerCertificate callback that:
// 1. Parses all certificates in the chain
// 2. Verifies at least one matches the expected SPKI pin
// 3. Stores the CA chain for later retrieval via GetTOFUResult
func NewTLSCredentialsWithTOFU(expectedPin string) (credentials.TransportCredentials, func() *TOFUResult, error) {
	// Validate pin format
	if _, err := ParseSPKIPin(expectedPin); err != nil {
		return nil, nil, err
	}

	var tofuResult *TOFUResult

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // We verify manually via VerifyPeerCertificate
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates received from server")
			}

			// Parse all certificates
			var certs []*x509.Certificate
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}
				certs = append(certs, cert)
			}

			// Verify SPKI pin matches at least one certificate
			if err := VerifyChainSPKI(certs, expectedPin); err != nil {
				return err
			}

			// Extract CA chain for persistence
			caPEM := ExtractCAChainPEM(certs)
			if caPEM == "" {
				// If single cert, use it as CA
				caPEM = certToPEM(certs[0])
			}

			// Store result for retrieval
			tofuResult = &TOFUResult{
				CAPem:   caPEM,
				SPKIPin: expectedPin,
			}

			return nil
		},
	}

	getResult := func() *TOFUResult {
		return tofuResult
	}

	return credentials.NewTLS(tlsConfig), getResult, nil
}

// certToPEM encodes a certificate as PEM
func certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// NewMTLSCredentialsWithTPMFromPEM creates mTLS credentials using TPM-backed agent key
// This version loads the CA from a PEM string instead of a file path
func NewMTLSCredentialsWithTPMFromPEM(caPEM, agentCertPEM string, agentKeyPriv, agentKeyPub []byte, tpmClient *TPMClient) (credentials.TransportCredentials, *CertKey, error) {
	// Load server CA from PEM
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, nil, fmt.Errorf("failed to parse server CA cert from PEM")
	}

	// Load agent key from TPM
	agentKey, err := tpmClient.LoadCertKey(agentKeyPriv, agentKeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load agent key from TPM: %w", err)
	}

	// Parse agent certificate
	block, _ := pem.Decode([]byte(agentCertPEM))
	if block == nil {
		tpmClient.CloseCertKey(agentKey)
		return nil, nil, fmt.Errorf("failed to decode agent certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tpmClient.CloseCertKey(agentKey)
		return nil, nil, fmt.Errorf("failed to parse agent certificate: %w", err)
	}

	// Create TLS certificate with TPM-backed signer
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  &tpmCertSigner{tpmClient: tpmClient, certKey: agentKey},
		Leaf:        cert,
	}

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})

	return creds, agentKey, nil
}
