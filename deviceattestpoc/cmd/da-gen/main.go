// da-gen generates an attested certificate for a specific usage (e.g., VPN)
// Uses TPM-bound keys following draft-acme-device-attest-07.
//
// Usage: da-gen --usage vpn [--server localhost:50051] [--tpm /dev/tpmrm0] [--output /certs]
//
// Output files:
//   - <usage>-key.blob: TPM key blobs (encrypted, can only be used with this TPM)
//   - <usage>-cert.pem: Certificate with full CA chain
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CertKeyBlobs stores the TPM key blobs for persistence
type CertKeyBlobs struct {
	PrivBlob []byte `json:"priv_blob"`
	PubBlob  []byte `json:"pub_blob"`
}

func main() {
	usage := flag.String("usage", "", "Certificate usage (e.g., vpn)")
	serverAddr := flag.String("server", "", "gRPC server address")
	tpmDevice := flag.String("tpm", "", "TPM device path")
	outputDir := flag.String("output", "", "Output directory for certificate and key")
	flag.Parse()

	if *usage == "" {
		log.Fatalf("--usage is required (e.g., --usage vpn)")
	}

	finalServerAddr := GetConfigString(*serverAddr, "GRPC_SERVER", "localhost:50051")
	finalTPMDevice := GetConfigString(*tpmDevice, "TPM_DEVICE", "/dev/tpmrm0")
	finalOutputDir := GetConfigString(*outputDir, "DA_OUTPUT_DIR", "/certs")

	log.Printf("da-gen: Attested Certificate Generation (TPM-bound)")
	log.Printf("Usage: %s", *usage)
	log.Printf("Server: %s", finalServerAddr)
	log.Printf("TPM: %s", finalTPMDevice)
	log.Printf("Output: %s", finalOutputDir)

	// Initialize TPM client (loads AK + LAK from da.json)
	tpmClient, err := NewTPMClient(finalTPMDevice)
	if err != nil {
		log.Fatalf("Failed to initialize TPM: %v", err)
	}
	defer tpmClient.Close()

	if tpmClient.NeedsLAKProvisioning() {
		log.Fatalf("LAK not provisioned. Run da-lak first.")
	}

	permanentID := tpmClient.GetPermanentID()
	log.Printf("Permanent ID: %s", permanentID)

	// Create TPM-bound signing key
	log.Printf("Creating TPM-bound signing key...")
	certKey, err := tpmClient.CreateCertKey()
	if err != nil {
		log.Fatalf("Failed to create TPM key: %v", err)
	}
	defer tpmClient.CloseCertKey(certKey)

	// Build common name with usage prefix
	commonName := fmt.Sprintf("%s-%s", *usage, permanentID)

	// Connect to server
	conn, err := grpc.NewClient(finalServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create ACME order
	log.Printf("Creating ACME order...")
	resp, err := client.RequestCertificate(ctx, &pb.CertRequest{
		CommonName:          commonName,
		SanDns:              []string{},
		SanIps:              []string{},
		PermanentIdentifier: permanentID,
		Usage:               *usage,
	})
	if err != nil {
		log.Fatalf("Failed to create order: %v", err)
	}
	if resp.Status == "error" {
		log.Fatalf("Order creation failed: %s", resp.Error)
	}
	log.Printf("ACME order created: %s", resp.OrderId)

	// Generate attestation using TPM2_Certify
	log.Printf("Generating TPM attestation...")
	keyAuthorization := fmt.Sprintf("%s.%s", resp.ChallengeToken, resp.AccountThumbprint)
	attestationObject, err := tpmClient.GenerateAttestation(certKey, keyAuthorization)
	if err != nil {
		log.Fatalf("Failed to generate attestation: %v", err)
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
		log.Fatalf("Failed to submit attestation: %v", err)
	}
	if attResp.Status == "error" {
		log.Fatalf("Attestation failed: %s", attResp.Error)
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
			log.Fatalf("Order not ready after 10 attempts, last status: %s", lastStatus)
		}
		time.Sleep(1 * time.Second)
	}

	// Generate CSR signed by TPM key
	log.Printf("Generating CSR (TPM-signed)...")
	csrPEM, err := tpmClient.SignCSR(certKey, commonName, nil)
	if err != nil {
		log.Fatalf("Failed to generate CSR: %v", err)
	}

	// Finalize order
	log.Printf("Finalizing order...")
	finalizeResp, err := client.FinalizeOrder(ctx, &pb.FinalizeRequest{
		OrderId: resp.OrderId,
		CsrPem:  csrPEM,
	})
	if err != nil {
		log.Fatalf("Failed to finalize order: %v", err)
	}
	if finalizeResp.Status == "error" {
		log.Fatalf("Order finalization failed: %s", finalizeResp.Error)
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
			log.Fatalf("Certificate not ready after 30 attempts")
		}
		time.Sleep(2 * time.Second)
	}

	// Write output files
	if err := os.MkdirAll(finalOutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	blobPath := filepath.Join(finalOutputDir, fmt.Sprintf("%s-key.blob", *usage))
	certPath := filepath.Join(finalOutputDir, fmt.Sprintf("%s-cert.pem", *usage))

	// Save TPM key blobs (encrypted, TPM-bound)
	privBlob, pubBlob := certKey.GetBlobs()
	keyBlobs := CertKeyBlobs{
		PrivBlob: privBlob,
		PubBlob:  pubBlob,
	}
	blobData, err := json.Marshal(keyBlobs)
	if err != nil {
		log.Fatalf("Failed to marshal key blobs: %v", err)
	}
	if err := os.WriteFile(blobPath, blobData, 0600); err != nil {
		log.Fatalf("Failed to write key blobs: %v", err)
	}

	// Write certificate with full chain
	if err := os.WriteFile(certPath, []byte(certResp.CertificatePem), 0644); err != nil {
		log.Fatalf("Failed to write certificate: %v", err)
	}

	log.Printf("Certificate generated successfully!")
	log.Printf("  Key blobs: %s (TPM-bound, use with this device only)", blobPath)
	log.Printf("  Cert: %s", certPath)
	log.Printf("  CN: %s", commonName)
}
