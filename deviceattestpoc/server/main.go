
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
)

// Server implements the CertificateService gRPC server
type Server struct {
	pb.UnimplementedCertificateServiceServer
	openbaoClient *OpenBaoClient
	orders        map[string]*OrderInfo // orderID -> order info with CSR
}

// OrderInfo stores information about an ACME order including the CSR
type OrderInfo struct {
	Order      *ACMEOrder
	CSR        string
	CommonName string
}

// RequestCertificate initiates a certificate request and returns the device attestation challenge
func (s *Server) RequestCertificate(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	log.Printf("Received certificate request for CN=%s, permanentID=%s",
		req.CommonName, req.PermanentIdentifier)

	// Create ACME order with device attestation
	order, err := s.openbaoClient.CreateACMEOrder(ctx, req)
	if err != nil {
		return &pb.CertResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to create ACME order: %v", err),
		}, nil
	}

	log.Printf("Created ACME order: %s, authorization: %s",
		order.OrderID, order.AuthorizationURL)

	// Store order with CSR for later finalization
	s.orders[order.OrderID] = &OrderInfo{
		Order:      order,
		CSR:        req.CsrPem,
		CommonName: req.CommonName,
	}

	// Return challenge information to client
	return &pb.CertResponse{
		Status:             "pending",
		OrderId:            order.OrderID,
		AuthorizationUrl:   order.AuthorizationURL,
		ChallengeUrl:       order.ChallengeURL,
		ChallengeToken:     order.ChallengeToken,
		AccountThumbprint:  order.AccountThumbprint,
		Details:            "Device attestation challenge created. Submit attestation object to continue.",
	}, nil
}

// SubmitAttestation submits the TPM attestation response for validation
func (s *Server) SubmitAttestation(ctx context.Context, req *pb.AttestationSubmit) (*pb.CertResponse, error) {
	log.Printf("Received attestation submission for order: %s", req.OrderId)

	// Submit attestation to ACME challenge
	err := s.openbaoClient.SubmitAttestation(ctx, req.ChallengeUrl, req.AttestationObject)
	if err != nil {
		return &pb.CertResponse{
			Status:  "error",
			OrderId: req.OrderId,
			Error:   fmt.Sprintf("Failed to submit attestation: %v", err),
		}, nil
	}

	log.Printf("Attestation submitted successfully for order: %s", req.OrderId)

	// Check order status
	status, err := s.openbaoClient.GetOrderStatus(ctx, req.OrderId)
	if err != nil {
		return &pb.CertResponse{
			Status:  "error",
			OrderId: req.OrderId,
			Error:   fmt.Sprintf("Failed to get order status: %v", err),
		}, nil
	}

	log.Printf("Order status: %s", status)

	// If order is ready, finalize it with the CSR
	if status == "ready" {
		orderInfo, ok := s.orders[req.OrderId]
		if !ok {
			return &pb.CertResponse{
				Status:  "error",
				OrderId: req.OrderId,
				Error:   "Order not found in server cache",
			}, nil
		}

		log.Printf("Order is ready, finalizing with CSR...")
		err := s.openbaoClient.FinalizeOrder(ctx, orderInfo.Order.FinalizeURL, orderInfo.CSR)
		if err != nil {
			return &pb.CertResponse{
				Status:  "error",
				OrderId: req.OrderId,
				Error:   fmt.Sprintf("Failed to finalize order: %v", err),
			}, nil
		}

		log.Printf("Order finalized successfully")

		// Wait a moment for certificate to be issued
		// In production, would poll the order status until it becomes "valid"
		// For now, just return that finalization succeeded
		return &pb.CertResponse{
			Status:  "processing",
			OrderId: req.OrderId,
			Details: "Order finalized with CSR. Certificate is being issued.",
		}, nil
	}

	return &pb.CertResponse{
		Status:  status,
		OrderId: req.OrderId,
		Details: fmt.Sprintf("Attestation validated. Order status: %s", status),
	}, nil
}

// GetCertificate retrieves the issued certificate if ready
func (s *Server) GetCertificate(ctx context.Context, req *pb.GetCertRequest) (*pb.CertResponse, error) {
	log.Printf("Received get certificate request for order: %s", req.OrderId)

	// Poll order status until it becomes "valid" or times out
	// After finalization, OpenBao needs time to issue the certificate
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		status, err := s.openbaoClient.GetOrderStatus(ctx, req.OrderId)
		if err != nil {
			return &pb.CertResponse{
				Status:  "error",
				OrderId: req.OrderId,
				Error:   fmt.Sprintf("Failed to check order status: %v", err),
			}, nil
		}

		log.Printf("Order status check %d/%d: %s", i+1, maxAttempts, status)

		if status == "valid" {
			// Order is valid, certificate is ready
			break
		} else if status == "invalid" {
			return &pb.CertResponse{
				Status:  "error",
				OrderId: req.OrderId,
				Error:   "Order became invalid",
			}, nil
		}

		// Still processing, wait a bit
		if i < maxAttempts-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Get certificate from OpenBao
	cert, chain, err := s.openbaoClient.GetCertificate(ctx, req.OrderId)
	if err != nil {
		return &pb.CertResponse{
			Status:  "error",
			OrderId: req.OrderId,
			Error:   fmt.Sprintf("Failed to get certificate: %v", err),
		}, nil
	}

	log.Printf("✓ Certificate retrieved successfully for order: %s", req.OrderId)

	return &pb.CertResponse{
		Status:         "valid",
		OrderId:        req.OrderId,
		CertificatePem: cert,
		ChainPem:       chain,
		Details:        "Certificate issued successfully",
	}, nil
}

// EnrollTPM enrolls a TPM device by configuring its root CA and allowlisting its identifier
// WARNING: This is a PoC-only endpoint. In production, enrollment MUST be performed by
// administrators through secure out-of-band channels, NOT by clients.
func (s *Server) EnrollTPM(ctx context.Context, req *pb.TPMEnrollmentRequest) (*pb.EnrollmentResponse, error) {
	log.Printf("========================================")
	log.Printf("⚠️  WARNING: TPM ENROLLMENT REQUEST")
	log.Printf("========================================")
	log.Printf("Permanent ID: %s", req.PermanentIdentifier)
	log.Printf("EK Root CA Name: %s", req.EkRootCaName)
	log.Printf("Description: %s", req.DeviceDescription)
	log.Printf("")
	log.Printf("⚠️  SECURITY NOTICE:")
	log.Printf("   In a production environment, TPM enrollment MUST be performed")
	log.Printf("   by administrators through secure out-of-band channels.")
	log.Printf("   This PoC allows client-initiated enrollment for demonstration")
	log.Printf("   purposes ONLY. DO NOT use this pattern in production!")
	log.Printf("========================================")
	log.Printf("")

	// Validate inputs
	if req.PermanentIdentifier == "" {
		return &pb.EnrollmentResponse{
			Status: "error",
			Error:  "permanent_identifier is required",
		}, nil
	}

	if req.EkRootCaPem == "" {
		return &pb.EnrollmentResponse{
			Status: "error",
			Error:  "ek_root_ca_pem is required",
		}, nil
	}

	if req.EkRootCaName == "" {
		return &pb.EnrollmentResponse{
			Status: "error",
			Error:  "ek_root_ca_name is required",
		}, nil
	}

	// Enroll the TPM device
	err := s.openbaoClient.EnrollTPMDevice(ctx, req.PermanentIdentifier, req.EkRootCaPem, req.EkRootCaName)
	if err != nil {
		log.Printf("❌ Failed to enroll TPM device: %v", err)
		return &pb.EnrollmentResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to enroll TPM: %v", err),
		}, nil
	}

	log.Printf("✓ TPM device enrolled successfully!")
	log.Printf("  - Permanent ID allowlisted: %s", req.PermanentIdentifier)
	log.Printf("  - EK Root CA configured: %s", req.EkRootCaName)
	log.Printf("  - EK validation enabled")
	log.Printf("")

	return &pb.EnrollmentResponse{
		Status:              "success",
		Details:             "TPM device enrolled successfully. EK validation enabled and permanent identifier allowlisted.",
		PermanentIdentifier: req.PermanentIdentifier,
		EkRootCaName:        req.EkRootCaName,
	}, nil
}

// ProvisionAIK issues an IAK certificate for a TPM attestation key (AK mode)
// This endpoint acts as a Privacy CA, issuing AIK certificates for TPMs that lack
// manufacturer-provisioned IAK certificates.
func (s *Server) ProvisionAIK(ctx context.Context, req *pb.ProvisionAIKRequest) (*pb.ProvisionAIKResponse, error) {
	log.Printf("========================================")
	log.Printf("📋 IAK CERTIFICATE PROVISIONING REQUEST (AK Mode)")
	log.Printf("========================================")
	log.Printf("Permanent ID: %s", req.PermanentIdentifier)
	log.Printf("AK CSR Size: %d bytes", len(req.AkCsrPem))
	log.Printf("")
	log.Printf("ℹ️  OpenBao acting as Privacy CA:")
	log.Printf("   Signing CSR via /pki-ak mount to issue AIK certificate")
	log.Printf("========================================")
	log.Printf("")

	// Validate inputs
	if req.PermanentIdentifier == "" {
		return &pb.ProvisionAIKResponse{
			Status: "error",
			Error:  "permanent_identifier is required",
		}, nil
	}

	if req.AkCsrPem == "" {
		return &pb.ProvisionAIKResponse{
			Status: "error",
			Error:  "ak_csr_pem is required",
		}, nil
	}

	if req.EkCertificatePem == "" {
		return &pb.ProvisionAIKResponse{
			Status: "error",
			Error:  "ek_certificate_pem is required",
		}, nil
	}

	// Provision IAK certificate via OpenBao /pki-ak mount
	iakCertPEM, iakRootCAPEM, notBefore, notAfter, err := s.openbaoClient.ProvisionIAKCertificate(
		ctx,
		req.PermanentIdentifier,
		req.AkCsrPem,
		req.EkCertificatePem,
	)
	if err != nil {
		log.Printf("❌ Failed to provision IAK certificate: %v", err)
		return &pb.ProvisionAIKResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to provision AIK: %v", err),
		}, nil
	}

	log.Printf("✓ AIK certificate provisioned successfully via /pki-ak!")
	log.Printf("  - Permanent ID: %s", req.PermanentIdentifier)
	log.Printf("  - Issuer: OpenBao /pki-ak CA")
	log.Printf("  - Valid from: %s", notBefore)
	log.Printf("  - Valid until: %s", notAfter)
	log.Printf("")

	return &pb.ProvisionAIKResponse{
		Status:             "success",
		IakCertificatePem:  iakCertPEM,
		IakRootCaPem:       iakRootCAPEM,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}, nil
}

func main() {
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	baoAddr := os.Getenv("BAO_ADDR")
	if baoAddr == "" {
		log.Fatal("BAO_ADDR environment variable not set")
	}

	baoToken := os.Getenv("BAO_TOKEN")
	if baoToken == "" {
		log.Fatal("BAO_TOKEN environment variable not set")
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	log.Printf("Starting Certificate Service gRPC server on port %s", port)
	log.Printf("OpenBao address: %s", baoAddr)

	// Create OpenBao client
	openbaoClient, err := NewOpenBaoClient(baoAddr, baoToken)
	if err != nil {
		log.Fatalf("Failed to create OpenBao client: %v", err)
	}

	// Create gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterCertificateServiceServer(grpcServer, &Server{
		openbaoClient: openbaoClient,
		orders:        make(map[string]*OrderInfo),
	})

	log.Printf("gRPC server listening on port %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
