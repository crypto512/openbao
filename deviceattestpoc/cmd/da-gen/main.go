// da-gen generates certificates using mTLS authentication with agent cert
// This requires agent certificate to be provisioned first via da-agent.
//
// Usage: da-gen --usage vpn [--server localhost:50051] [--tpm /dev/tpmrm0] [--output ./certs]
//
// Output files:
//   - <usage>-key.pem: Private key in standard PEM format (unencrypted)
//   - <usage>-cert.pem: Certificate with full CA chain (leaf + intermediate + root)
//
// Note: Usage keys are ephemeral - generated on demand, not stored in device config.
// The mTLS authentication still uses the TPM-bound agent certificate.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	usage := flag.String("usage", "", "Certificate usage (e.g., vpn, wifi, tls)")
	serverAddr := flag.String("server", "", "gRPC server address")
	tpmDevice := flag.String("tpm", "", "TPM device path")
	outputDir := flag.String("output", "", "Output directory for certificate and key")
	serverCA := flag.String("server-ca", "", "Server CA certificate for TLS")
	flag.Parse()

	if *usage == "" {
		return fmt.Errorf("--usage is required (e.g., --usage vpn)")
	}

	finalServerAddr := GetConfigString(*serverAddr, "GRPC_SERVER", "localhost:50051")
	finalTPMDevice := GetConfigString(*tpmDevice, "TPM_DEVICE", "/dev/tpmrm0")
	finalOutputDir := GetConfigString(*outputDir, "DA_OUTPUT_DIR", ".")
	finalServerCA := GetConfigString(*serverCA, "SERVER_CA_PATH", "/openbao-data/grpc-ca.pem")

	log.Printf("da-gen: Certificate Generation (mTLS)")
	log.Printf("Usage: %s", *usage)
	log.Printf("Server: %s", finalServerAddr)
	log.Printf("TPM: %s", finalTPMDevice)
	log.Printf("Output: %s", finalOutputDir)

	// Initialize TPM client
	tpmClient, err := NewTPMClient(finalTPMDevice)
	if err != nil {
		return fmt.Errorf("failed to initialize TPM: %w", err)
	}
	defer tpmClient.Close()

	// Check prerequisites
	if tpmClient.NeedsLAKProvisioning() {
		return fmt.Errorf("LAK not provisioned. Run da-lak first")
	}
	if tpmClient.NeedsAgentProvisioning() {
		return fmt.Errorf("Agent not provisioned. Run da-agent first")
	}

	// Close AK to free TPM object slots - we don't need it for mTLS
	tpmClient.CloseAK()

	permanentID := tpmClient.GetPermanentID()
	log.Printf("Permanent ID: %s", permanentID)

	// Generate standard RSA key (not TPM-bound)
	log.Printf("Generating RSA key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Build common name with usage prefix
	commonName := fmt.Sprintf("%s-%s", *usage, permanentID)

	// Generate CSR signed by the RSA key
	log.Printf("Generating CSR...")
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// Load agent certificate and key for mTLS
	agentCertPEM := GetAgentCertPEM()
	agentKeyPriv, agentKeyPub, agentExists := GetAgentKeyBlobs()
	if !agentExists || agentCertPEM == "" {
		return fmt.Errorf("agent certificate not found")
	}

	// Connect to server via mTLS using agent cert
	log.Printf("Connecting to server with mTLS...")
	creds, agentKey, err := NewMTLSCredentialsWithTPM(&MTLSConfig{
		ServerCAPath: finalServerCA,
		AgentCertPEM: agentCertPEM,
		AgentKeyPriv: agentKeyPriv,
		AgentKeyPub:  agentKeyPub,
		TPMClient:    tpmClient,
	})
	if err != nil {
		return fmt.Errorf("failed to create mTLS credentials: %w", err)
	}
	defer tpmClient.CloseCertKey(agentKey)

	conn, err := grpc.NewClient(finalServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Call IssueCertificate RPC (mTLS-protected, no ACME)
	log.Printf("Requesting certificate via mTLS...")
	resp, err := client.IssueCertificate(ctx, &pb.IssueCertRequest{
		Usage:      *usage,
		CsrPem:     csrPEM,
		CommonName: commonName,
	})
	if err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}
	if resp.Status != "success" {
		return fmt.Errorf("certificate issuance failed: %s", resp.Error)
	}

	// Write output files
	if err := os.MkdirAll(finalOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	keyPath := filepath.Join(finalOutputDir, fmt.Sprintf("%s-key.pem", *usage))
	certPath := filepath.Join(finalOutputDir, fmt.Sprintf("%s-cert.pem", *usage))

	// Save private key in PEM format
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write certificate with chain
	certData := resp.CertificatePem
	if resp.ChainPem != "" {
		certData += "\n" + resp.ChainPem
	}
	if err := os.WriteFile(certPath, []byte(certData), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	log.Printf("Certificate generated successfully!")
	log.Printf("  Key: %s", keyPath)
	log.Printf("  Cert: %s", certPath)
	log.Printf("  CN: %s", commonName)
	if resp.NotBefore != "" && resp.NotAfter != "" {
		log.Printf("  Valid: %s to %s", resp.NotBefore, resp.NotAfter)
	}
	return nil
}
