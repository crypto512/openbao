// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
)

// ServerCertManager manages server certificate persistence using the database
type ServerCertManager struct {
	db     *db.DB
	client *OpenBaoClient
}

// NewServerCertManager creates a new server certificate manager
func NewServerCertManager(database *db.DB, client *OpenBaoClient) *ServerCertManager {
	return &ServerCertManager{
		db:     database,
		client: client,
	}
}

// GetOrCreateCertificate returns the cached certificate if valid, or requests a new one
func (m *ServerCertManager) GetOrCreateCertificate(ctx context.Context, name, cn string, sans []string) (certPEM, keyPEM string, err error) {
	// Try to load existing certificate from database
	certPEM, keyPEM, valid := m.loadCertificate(name)
	if valid {
		return certPEM, keyPEM, nil
	}

	// Request new certificate from OpenBao
	certPEM, keyPEM, err = m.client.RequestServerCertificate(ctx, cn, sans)
	if err != nil {
		return "", "", err
	}

	// Persist the new certificate to database
	if err := m.saveCertificate(name, certPEM, keyPEM); err != nil {
		log.Printf("Warning: failed to persist server certificate: %v", err)
	}

	return certPEM, keyPEM, nil
}

// loadCertificate loads the cached certificate from database if it exists and is still valid
func (m *ServerCertManager) loadCertificate(name string) (certPEM, keyPEM string, valid bool) {
	cachedCert, err := m.db.GetServerCertificate(name)
	if err != nil {
		log.Printf("Error loading cached certificate: %v", err)
		return "", "", false
	}
	if cachedCert == nil {
		return "", "", false
	}

	// Parse the certificate to check validity
	block, _ := pem.Decode([]byte(cachedCert.CertPEM))
	if block == nil {
		return "", "", false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", false
	}

	// Check if certificate is still valid with some buffer time (1 hour before expiry)
	now := time.Now()
	bufferTime := time.Hour
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter.Add(-bufferTime)) {
		log.Printf("Server certificate expired or expiring soon, requesting new one")
		return "", "", false
	}

	log.Printf("Loaded cached server certificate (expires: %s)", cert.NotAfter.Format(time.RFC3339))
	return cachedCert.CertPEM, cachedCert.KeyPEM, true
}

// saveCertificate saves the certificate to database
func (m *ServerCertManager) saveCertificate(name, certPEM, keyPEM string) error {
	// Parse cert to get validity dates
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	serverCert := &db.ServerCertificate{
		Name:      name,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
	}

	if err := m.db.SaveServerCertificate(serverCert); err != nil {
		return fmt.Errorf("failed to save certificate to database: %w", err)
	}

	log.Printf("Server certificate cached (expires: %s)", cert.NotAfter.Format(time.RFC3339))
	return nil
}
