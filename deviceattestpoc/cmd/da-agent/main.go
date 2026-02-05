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
	"os"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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

	fmt.Fprintf(os.Stderr, "── Phase 2: ACME device-attest-01 (Agent Cert) ─────────────\n")
	log.Printf("Server: %s, TPM: %s", serverAddr, finalTPMDevice)

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
		fmt.Fprintf(os.Stderr, "  Agent certificate already exists (use --clear to re-provision)\n")
		return nil
	}

	permanentID := tpmClient.GetPermanentID()

	// Create TPM-bound signing key for agent cert
	fmt.Fprintf(os.Stderr, "  Creating TPM-bound signing key...\n")
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

	conn, err := grpc.NewClient("passthrough:///"+serverAddr, grpc.WithTransportCredentials(creds))
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
	fmt.Fprintf(os.Stderr, "  ACME newOrder (permanent-identifier)...\n")
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
	log.Printf("ACME order: %s", resp.OrderId)

	// Generate attestation using TPM2_Certify
	fmt.Fprintf(os.Stderr, "  TPM2_Certify + submit attestation...\n")
	keyAuthorization := fmt.Sprintf("%s.%s", resp.ChallengeToken, resp.AccountThumbprint)
	attestationObject, err := tpmClient.GenerateAttestation(certKey, keyAuthorization)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %w", err)
	}

	// Submit attestation
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

	// Wait for challenge verification
	fmt.Fprintf(os.Stderr, "  Waiting for challenge verification...\n")
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
			break
		}
		if attempt == 10 {
			return fmt.Errorf("order not ready after 10 attempts, last status: %s", lastStatus)
		}
		time.Sleep(1 * time.Second)
	}

	// Finalize: CSR signed by TPM key
	fmt.Fprintf(os.Stderr, "  Finalize (TPM-signed CSR)...\n")
	csrPEM, err := tpmClient.SignCSR(certKey, commonName, nil)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

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

	fmt.Fprintf(os.Stderr, "  Agent certificate issued (CN: %s)\n", commonName)
	return nil
}
