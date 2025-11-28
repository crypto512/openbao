// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// LoadCACertPool loads a CA certificate pool from a PEM file
func LoadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return pool, nil
}

// NewServerTLSCredentials creates gRPC TLS credentials for the server
// with optional mTLS client verification using the agent CA pool.
func NewServerTLSCredentials(certPEM, keyPEM string, clientCAPool *x509.CertPool) (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS key pair: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven, // Optional mTLS - verify if provided
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(config), nil
}
