// da-gen generates certificates using mTLS authentication with agent cert
// Prerequisites: da-init, da-lak, and da-agent must be run first.
//
// Usage: da-gen --usage vpn [--tpm /dev/tpmrm0] [--output ./certs]
//
// Output files:
//   - <usage>-key.pem: Private key in standard PEM format (unencrypted)
//   - <usage>-cert.pem: Certificate with full CA chain (leaf + intermediate + root)
//
// Note: Usage keys are ephemeral - generated on demand, not stored in device config.
// The mTLS authentication uses the TPM-bound agent certificate.
//
// Self-healing: If LAK or agent certificates are expired, they will be
// automatically refreshed before generating the usage certificate.
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	usage := flag.String("usage", "", "Certificate usage (e.g., vpn, wifi, tls)")
	tpmDevice := flag.String("tpm", "", "TPM device path")
	outputDir := flag.String("output", "", "Output directory for certificate and key")
	flag.Parse()

	if *usage == "" {
		return fmt.Errorf("--usage is required (e.g., --usage vpn)")
	}

	finalTPMDevice := GetConfigString(*tpmDevice, "TPM_DEVICE", "/dev/tpmrm0")
	finalOutputDir := GetConfigString(*outputDir, "DA_OUTPUT_DIR", ".")

	// Load server config from da.json
	serverAddr, serverCAPEM, _, exists, err := LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}
	if !exists {
		return fmt.Errorf("server not configured. Run da-init first")
	}

	fmt.Fprintf(os.Stderr, "── Phase 3: mTLS Certificate Issuance ───────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Usage: %s\n", *usage)
	log.Printf("Server: %s, TPM: %s, Output: %s", serverAddr, finalTPMDevice, finalOutputDir)

	// Self-healing: check and refresh LAK/agent if needed
	if !IsLAKValid() {
		fmt.Fprintf(os.Stderr, "  LAK expired, refreshing...\n")
		if err := RunTool("da-lak"); err != nil {
			return fmt.Errorf("failed to refresh LAK: %w", err)
		}
	}
	if !IsAgentValid() {
		fmt.Fprintf(os.Stderr, "  Agent cert expired, refreshing...\n")
		if err := RunTool("da-agent"); err != nil {
			return fmt.Errorf("failed to refresh agent: %w", err)
		}
	}

	// Initialize TPM client
	tpmClient, err := NewTPMClient(finalTPMDevice)
	if err != nil {
		return fmt.Errorf("failed to initialize TPM: %w", err)
	}
	defer tpmClient.Close()

	// Close AK to free TPM object slots - we don't need it for mTLS
	tpmClient.CloseAK()

	permanentID := tpmClient.GetPermanentID()
	log.Printf("Permanent ID: %s", permanentID)

	// Generate standard RSA key (not TPM-bound)
	fmt.Fprintf(os.Stderr, "  Generating RSA key + CSR...\n")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Build common name with usage prefix
	commonName := fmt.Sprintf("%s-%s", *usage, permanentID)

	// Generate CSR signed by the RSA key
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

	// Connect to server via mTLS using agent cert and stored CA
	fmt.Fprintf(os.Stderr, "  Authenticating via mTLS (TPM-bound agent cert)...\n")
	creds, agentKey, err := NewMTLSCredentialsWithTPMFromPEM(serverCAPEM, agentCertPEM, agentKeyPriv, agentKeyPub, tpmClient)
	if err != nil {
		return fmt.Errorf("failed to create mTLS credentials: %w", err)
	}
	defer tpmClient.CloseCertKey(agentKey)

	conn, err := grpc.NewClient("passthrough:///"+serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Call IssueCertificate RPC (mTLS-protected, no ACME)
	fmt.Fprintf(os.Stderr, "  Requesting certificate...\n")
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

	fmt.Fprintf(os.Stderr, "  Certificate issued:\n")
	fmt.Fprintf(os.Stderr, "    Key:  %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "    Cert: %s\n", certPath)
	fmt.Fprintf(os.Stderr, "    CN:   %s\n", commonName)
	if resp.NotBefore != "" && resp.NotAfter != "" {
		fmt.Fprintf(os.Stderr, "    Valid: %s to %s\n", resp.NotBefore, resp.NotAfter)
	}
	return nil
}
