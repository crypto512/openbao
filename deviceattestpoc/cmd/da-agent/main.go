// da-agent provisions an agent certificate via ACME device-attest-01
// This is the bootstrap phase that creates a hardware-bound identity certificate.
// Prerequisites: da-init and da-lak must be run first.
//
// Usage: da-agent [--tpm /dev/tpmrm0] [--clear]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	tpmDevice := flag.String("tpm", "", "TPM device path")
	clear := flag.Bool("clear", false, "Clear existing agent cert and re-provision")
	flag.Parse()

	finalTPMDevice := GetConfigString(*tpmDevice, "TPM_DEVICE", "/dev/tpmrm0")

	// Load server config from da.json
	serverAddr, serverCAPEM, _, exists, err := LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}
	if !exists {
		return fmt.Errorf("server not configured. Run da-init first")
	}

	log.Printf("da-agent: Agent Certificate Provisioning (ACME device-attest-01)")
	log.Printf("Server: %s", serverAddr)
	log.Printf("TPM: %s", finalTPMDevice)

	// Initialize TPM client
	tpmClient, err := NewTPMClient(finalTPMDevice)
	if err != nil {
		return fmt.Errorf("failed to initialize TPM: %w", err)
	}
	defer tpmClient.Close()

	// Check LAK is provisioned
	if tpmClient.NeedsLAKProvisioning() {
		return fmt.Errorf("LAK not provisioned. Run da-lak first")
	}

	// Check if agent already exists (unless --clear)
	if *clear {
		if err := ClearAgentBlobs(); err != nil {
			log.Printf("Warning: failed to clear agent blobs: %v", err)
		}
		log.Printf("Agent state cleared")
	}

	if !tpmClient.NeedsAgentProvisioning() {
		log.Printf("Agent certificate already exists in %s", GetBlobPath())
		log.Printf("Use --clear to re-provision")
		return nil
	}

	permanentID := tpmClient.GetPermanentID()
	log.Printf("Permanent ID: %s", permanentID)

	// Create TPM-bound signing key for agent cert
	log.Printf("Creating TPM-bound signing key...")
	certKey, err := tpmClient.CreateCertKey()
	if err != nil {
		return fmt.Errorf("failed to create TPM key: %w", err)
	}
	defer tpmClient.CloseCertKey(certKey)

	// Connect to server via TLS using stored CA
	creds, err := NewTLSCredentialsFromPEM(serverCAPEM)
	if err != nil {
		return fmt.Errorf("failed to create TLS credentials: %w", err)
	}

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Common name includes "agent" prefix
	commonName := fmt.Sprintf("agent-%s", permanentID)

	// Create ACME order with usage="agent"
	log.Printf("Creating ACME order for agent certificate...")
	resp, err := client.RequestCertificate(ctx, &pb.CertRequest{
		CommonName:          commonName,
		SanDns:              []string{},
		SanIps:              []string{},
		PermanentIdentifier: permanentID,
		Usage:               "agent",
	})
	if err != nil {
		return fmt.Errorf("failed to create order: %w", err)
	}
	if resp.Status == "error" {
		return fmt.Errorf("order creation failed: %s", resp.Error)
	}
	log.Printf("ACME order created: %s", resp.OrderId)

	// Generate attestation using TPM2_Certify
	log.Printf("Generating TPM attestation...")
	keyAuthorization := fmt.Sprintf("%s.%s", resp.ChallengeToken, resp.AccountThumbprint)
	attestationObject, err := tpmClient.GenerateAttestation(certKey, keyAuthorization)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %w", err)
	}

	// Submit attestation
	log.Printf("Submitting attestation...")
	attResp, err := client.SubmitAttestation(ctx, &pb.AttestationSubmit{
		OrderId:           resp.OrderId,
		AuthorizationUrl:  resp.AuthorizationUrl,
		ChallengeUrl:      resp.ChallengeUrl,
		AttestationObject: attestationObject,
	})
	if err != nil {
		return fmt.Errorf("failed to submit attestation: %w", err)
	}
	if attResp.Status == "error" {
		return fmt.Errorf("attestation failed: %s", attResp.Error)
	}

	// Wait for order to become ready
	log.Printf("Waiting for order to become ready...")
	var lastStatus string
	for attempt := 1; attempt <= 10; attempt++ {
		orderResp, err := client.GetCertificate(ctx, &pb.GetCertRequest{OrderId: resp.OrderId})
		if err != nil {
			log.Printf("Attempt %d: error checking order: %v", attempt, err)
			time.Sleep(1 * time.Second)
			continue
		}
		lastStatus = orderResp.Status
		if lastStatus == "ready" || lastStatus == "valid" {
			log.Printf("Order is ready")
			break
		}
		if attempt == 10 {
			return fmt.Errorf("order not ready after 10 attempts, last status: %s", lastStatus)
		}
		time.Sleep(1 * time.Second)
	}

	// Generate CSR signed by TPM key
	log.Printf("Generating CSR (TPM-signed)...")
	csrPEM, err := tpmClient.SignCSR(certKey, commonName, nil)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Finalize order
	log.Printf("Finalizing order...")
	finalizeResp, err := client.FinalizeOrder(ctx, &pb.FinalizeRequest{
		OrderId: resp.OrderId,
		CsrPem:  csrPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to finalize order: %w", err)
	}
	if finalizeResp.Status == "error" {
		return fmt.Errorf("order finalization failed: %s", finalizeResp.Error)
	}

	// Retrieve certificate
	log.Printf("Retrieving certificate...")
	var certResp *pb.CertResponse
	for attempt := 1; attempt <= 30; attempt++ {
		certResp, err = client.GetCertificate(ctx, &pb.GetCertRequest{OrderId: resp.OrderId})
		if err == nil && certResp.Status == "valid" {
			break
		}
		if attempt == 30 {
			return fmt.Errorf("certificate not ready after 30 attempts")
		}
		time.Sleep(2 * time.Second)
	}

	// Store agent cert and key blobs in da.json
	privBlob, pubBlob := certKey.GetBlobs()
	chainPEM := ""
	if len(certResp.ChainPem) > 0 {
		chainPEM = certResp.ChainPem[0]
	}
	if err := SaveAgentBlobs(certResp.CertificatePem, privBlob, pubBlob, chainPEM); err != nil {
		return fmt.Errorf("failed to save agent certificate: %w", err)
	}

	log.Printf("Agent certificate provisioned successfully!")
	log.Printf("  CN: %s", commonName)
	log.Printf("  Saved to: %s", GetBlobPath())
	return nil
}
