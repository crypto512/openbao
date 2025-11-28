// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Context key for client certificate
type clientCertKey struct{}

// RPCs that require mTLS authentication with agent certificate
var mTLSRequiredRPCs = map[string]bool{
	"/certservice.CertificateService/IssueCertificate": true,
}

// ExtractClientCert extracts the client certificate from the gRPC context
func ExtractClientCert(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer information in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("no TLS info in peer")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	return tlsInfo.State.PeerCertificates[0], nil
}

// ValidateAgentCert validates that the client cert is from the agent PKI
func (s *Server) ValidateAgentCert(cert *x509.Certificate) error {
	if s.agentCACertPool == nil {
		return fmt.Errorf("agent CA not configured")
	}

	opts := x509.VerifyOptions{
		Roots:     s.agentCACertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate not from agent PKI: %w", err)
	}

	return nil
}

// ExtractPermanentIDFromCert extracts the permanent identifier from cert SAN URIs
func ExtractPermanentIDFromCert(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "urn:permanent-identifier:") {
			return strings.TrimPrefix(uri.String(), "urn:permanent-identifier:")
		}
	}
	// Fallback to CN if no URI SAN
	return cert.Subject.CommonName
}

// MTLSUnaryInterceptor enforces mTLS for specific RPCs
func (s *Server) MTLSUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Check if this RPC requires mTLS
	if !mTLSRequiredRPCs[info.FullMethod] {
		return handler(ctx, req)
	}

	// Extract client certificate
	cert, err := ExtractClientCert(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated,
			"mTLS required for %s: %v", info.FullMethod, err)
	}

	// Validate certificate is from agent PKI
	if err := s.ValidateAgentCert(cert); err != nil {
		return nil, status.Errorf(codes.PermissionDenied,
			"invalid agent certificate: %v", err)
	}

	// Add cert to context for handler use
	ctx = context.WithValue(ctx, clientCertKey{}, cert)

	return handler(ctx, req)
}

// GetClientCert retrieves the client certificate from context (set by interceptor)
func GetClientCert(ctx context.Context) *x509.Certificate {
	cert, _ := ctx.Value(clientCertKey{}).(*x509.Certificate)
	return cert
}
