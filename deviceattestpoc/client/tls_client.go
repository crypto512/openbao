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
