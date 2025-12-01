// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Context key for client certificate
type clientCertKey struct{}

// Context key for permanent ID
type permanentIDKey struct{}

// RPCSecurityConfig defines security requirements for each RPC
type RPCSecurityConfig struct {
	RequireMTLS      bool             // Requires valid agent certificate
	MinDeviceStatus  db.DeviceStatus  // Minimum device status required (empty = no check)
	ValidateDevice   bool             // Whether to validate device exists and is active
}

// Security configuration for each RPC endpoint
var rpcSecurityConfig = map[string]RPCSecurityConfig{
	// Entry point - EK validation happens in handler
	"/certservice.CertificateService/EnrollTPM": {
		RequireMTLS:     false,
		ValidateDevice:  false,
	},
	// LAK provisioning - device must be provisioned (approved)
	"/certservice.CertificateService/ProvisionLAK": {
		RequireMTLS:      false,
		MinDeviceStatus:  db.StatusProvisioned,
		ValidateDevice:   true,
	},
	// Credential activation - session-based, device validated via session
	"/certservice.CertificateService/ActivateCredential": {
		RequireMTLS:     false,
		ValidateDevice:  false, // Session contains permanent ID, validated in handler
	},
	// ACME agent certificate flow - device must have LAK (enrolled status)
	"/certservice.CertificateService/RequestCertificate": {
		RequireMTLS:      false,
		MinDeviceStatus:  db.StatusEnrolled,
		ValidateDevice:   true,
	},
	"/certservice.CertificateService/SubmitAttestation": {
		RequireMTLS:      false,
		MinDeviceStatus:  db.StatusEnrolled,
		ValidateDevice:   true,
	},
	"/certservice.CertificateService/FinalizeOrder": {
		RequireMTLS:      false,
		MinDeviceStatus:  db.StatusEnrolled,
		ValidateDevice:   true,
	},
	"/certservice.CertificateService/GetCertificate": {
		RequireMTLS:      false,
		MinDeviceStatus:  db.StatusEnrolled,
		ValidateDevice:   true,
	},
	// Usage certificate issuance - requires mTLS with valid agent cert, device must be trusted
	"/certservice.CertificateService/IssueCertificate": {
		RequireMTLS:      true,
		MinDeviceStatus:  db.StatusTrusted,
		ValidateDevice:   true,
	},
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

// ValidateAgentCert validates that the client cert is from the agent PKI and is currently valid
func (s *Server) ValidateAgentCert(cert *x509.Certificate) error {
	if s.agentCACertPool == nil {
		return fmt.Errorf("agent CA not configured")
	}

	// Check certificate validity period explicitly
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (notBefore: %s)", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (notAfter: %s)", cert.NotAfter.Format(time.RFC3339))
	}

	// Verify certificate chain and usage
	opts := x509.VerifyOptions{
		Roots:       s.agentCACertPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
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
	// Fallback to CN if no URI SAN, strip "agent-" prefix if present
	cn := cert.Subject.CommonName
	if strings.HasPrefix(cn, "agent-") {
		return strings.TrimPrefix(cn, "agent-")
	}
	return cn
}

// deviceStatusOrder defines the hierarchy of device statuses
var deviceStatusOrder = map[db.DeviceStatus]int{
	db.StatusRegistered:  1,
	db.StatusProvisioned: 2,
	db.StatusEnrolled:    3,
	db.StatusTrusted:     4,
}

// isStatusAtLeast checks if actual status meets or exceeds required status
func isStatusAtLeast(actual, required db.DeviceStatus) bool {
	return deviceStatusOrder[actual] >= deviceStatusOrder[required]
}

// extractPermanentIDFromRequest attempts to extract permanent ID from various request types
func extractPermanentIDFromRequest(req interface{}) string {
	// Use type assertion to extract permanent_identifier from known request types
	switch r := req.(type) {
	case interface{ GetPermanentIdentifier() string }:
		return r.GetPermanentIdentifier()
	case interface{ GetOrderId() string }:
		// For order-based requests, we need to look up the order
		// This will be handled separately in the interceptor
		return ""
	default:
		return ""
	}
}

// SecurityUnaryInterceptor enforces security requirements for all RPCs
func (s *Server) MTLSUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	config, exists := rpcSecurityConfig[info.FullMethod]
	if !exists {
		// Unknown RPC - deny by default
		log.Printf("Security: Unknown RPC %s - denying", info.FullMethod)
		return nil, status.Errorf(codes.PermissionDenied, "unknown RPC method")
	}

	var permanentID string

	// Step 1: mTLS validation (if required)
	if config.RequireMTLS {
		cert, err := ExtractClientCert(ctx)
		if err != nil {
			log.Printf("Security: mTLS required for %s but no cert: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.Unauthenticated,
				"mTLS required for %s: %v", info.FullMethod, err)
		}

		if err := s.ValidateAgentCert(cert); err != nil {
			log.Printf("Security: Invalid agent cert for %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.PermissionDenied,
				"invalid agent certificate: %v", err)
		}

		permanentID = ExtractPermanentIDFromCert(cert)
		ctx = context.WithValue(ctx, clientCertKey{}, cert)
	}

	// Step 2: Device validation (if required)
	if config.ValidateDevice {
		// Get permanent ID from request if not from mTLS cert
		if permanentID == "" {
			permanentID = extractPermanentIDFromRequest(req)
		}

		// For order-based requests, look up the order to get permanent ID
		if permanentID == "" {
			if orderReq, ok := req.(interface{ GetOrderId() string }); ok && orderReq.GetOrderId() != "" {
				orderInfo, err := s.db.GetOrder(orderReq.GetOrderId())
				if err == nil && orderInfo != nil {
					// Extract permanent ID from order's CommonName (agent-<permanentID>)
					cn := orderInfo.CommonName
					if strings.HasPrefix(cn, "agent-") {
						permanentID = strings.TrimPrefix(cn, "agent-")
					}
				}
			}
		}

		if permanentID == "" {
			log.Printf("Security: Cannot determine device for %s", info.FullMethod)
			return nil, status.Errorf(codes.InvalidArgument,
				"cannot determine device identity")
		}

		// Look up device in database
		device, err := s.db.GetDeviceByEKHash(permanentID)
		if err != nil || device == nil {
			log.Printf("Security: Device not found for %s: %s", info.FullMethod, permanentID)
			return nil, status.Errorf(codes.NotFound,
				"device not registered: %s", permanentID)
		}

		// Check minimum status requirement
		if config.MinDeviceStatus != "" {
			if !isStatusAtLeast(device.Status, config.MinDeviceStatus) {
				log.Printf("Security: Device %s status %s < required %s for %s",
					permanentID, device.Status, config.MinDeviceStatus, info.FullMethod)
				return nil, status.Errorf(codes.PermissionDenied,
					"device status '%s' insufficient, requires '%s'",
					device.Status, config.MinDeviceStatus)
			}
		}

		// Store permanent ID in context for handlers
		ctx = context.WithValue(ctx, permanentIDKey{}, permanentID)
		log.Printf("Security: Authorized %s for device %s (status: %s)",
			info.FullMethod, permanentID[:16]+"...", device.Status)
	}

	return handler(ctx, req)
}

// GetPermanentID retrieves the permanent ID from context (set by interceptor)
func GetPermanentID(ctx context.Context) string {
	id, _ := ctx.Value(permanentIDKey{}).(string)
	return id
}

// GetClientCert retrieves the client certificate from context (set by interceptor)
func GetClientCert(ctx context.Context) *x509.Certificate {
	cert, _ := ctx.Value(clientCertKey{}).(*x509.Certificate)
	return cert
}
