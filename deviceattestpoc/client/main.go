// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Command-line flags
	simulateTPM := flag.Bool("simulate", false, "Force simulation mode (no hardware TPM)")
	attestMode := flag.String("attest-mode", "", "Attestation mode: 'iak' (use manufacturer IAK cert) or 'ak' (create NewAK with OpenBao-issued IAK cert)")
	serverAddr := flag.String("server", "", "Server address (default: localhost:50051 or SERVER_ADDR env)")
	tpmDevice := flag.String("tpm", "", "TPM device path (default: /dev/tpmrm0 or TPM_DEVICE env)")
	commonName := flag.String("cn", "", "Certificate common name (default: vpn-client-001.example.com or CERT_COMMON_NAME env)")
	certOutput := flag.String("cert-output", "", "Certificate output file path (default: ./vpn-client.pem or CERT_OUTPUT env)")
	showHelp := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *showHelp {
		fmt.Println("ACME Device Attestation Client")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  tpm-acme-client [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  -simulate           Force simulation mode (no hardware TPM)")
		fmt.Println("  -attest-mode <mode> Attestation mode:")
		fmt.Println("                        'iak' = Use manufacturer-provisioned IAK certificate")
		fmt.Println("                        'ak'  = Create NewAK and get OpenBao-issued IAK certificate")
		fmt.Println("  -server <addr>      Server address (default: localhost:50051)")
		fmt.Println("  -tpm <device>       TPM device path (default: /dev/tpmrm0)")
		fmt.Println("  -cn <name>          Certificate common name (default: vpn-client-001.example.com)")
		fmt.Println("  -cert-output <path> Certificate output file (default: ./vpn-client.pem)")
		fmt.Println("  -help               Show this help message")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("  SERVER_ADDR         Server address (overridden by -server)")
		fmt.Println("  TPM_DEVICE          TPM device path (overridden by -tpm)")
		fmt.Println("  CERT_COMMON_NAME    Certificate common name (overridden by -cn)")
		fmt.Println("  CERT_OUTPUT         Certificate output file (overridden by -cert-output)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  # IAK mode with hardware TPM (requires sudo for /dev/tpm access):")
		fmt.Println("  sudo ./tpm-acme-client -attest-mode iak")
		fmt.Println("")
		fmt.Println("  # AK mode with hardware TPM:")
		fmt.Println("  sudo ./tpm-acme-client -attest-mode ak")
		fmt.Println("")
		fmt.Println("  # Force simulation mode:")
		fmt.Println("  ./tpm-acme-client -simulate")
		fmt.Println("")
		fmt.Println("  # Use custom server with IAK mode:")
		fmt.Println("  sudo ./tpm-acme-client -attest-mode iak -server server.example.com:50051")
		os.Exit(0)
	}

	// Get configuration from flags or environment
	finalServerAddr := *serverAddr
	if finalServerAddr == "" {
		finalServerAddr = os.Getenv("SERVER_ADDR")
	}
	if finalServerAddr == "" {
		finalServerAddr = "localhost:50051"
	}

	finalTPMDevice := *tpmDevice
	if finalTPMDevice == "" {
		finalTPMDevice = os.Getenv("TPM_DEVICE")
	}
	if finalTPMDevice == "" {
		finalTPMDevice = "/dev/tpmrm0"
	}

	finalCommonName := *commonName
	if finalCommonName == "" {
		finalCommonName = os.Getenv("CERT_COMMON_NAME")
	}
	if finalCommonName == "" {
		finalCommonName = "vpn-client-001.example.com"
	}

	finalCertOutput := *certOutput
	if finalCertOutput == "" {
		finalCertOutput = os.Getenv("CERT_OUTPUT")
	}
	if finalCertOutput == "" {
		// Default to /certs/vpn-client.pem in Docker, ./vpn-client.pem otherwise
		if _, err := os.Stat("/certs"); err == nil {
			finalCertOutput = "/certs/vpn-client.pem"
		} else {
			finalCertOutput = "./vpn-client.pem"
		}
	}

	// Validate attestation mode
	if *attestMode != "" && *attestMode != "iak" && *attestMode != "ak" {
		log.Fatalf("Invalid -attest-mode value: %s. Must be 'iak' or 'ak'", *attestMode)
	}

	log.Printf("==============================================")
	log.Printf("ACME Device Attestation Client")
	log.Printf("==============================================")
	log.Printf("Server: %s", finalServerAddr)
	if *simulateTPM {
		log.Printf("Mode: SIMULATION (forced)")
		finalTPMDevice = "simulate"
	} else {
		log.Printf("TPM Device: %s", finalTPMDevice)
		log.Printf("Mode: HARDWARE TPM")
		if *attestMode != "" {
			log.Printf("Attestation Mode: %s", strings.ToUpper(*attestMode))
			if *attestMode == "iak" {
				log.Printf("  → Using manufacturer-provisioned IAK certificate")
			} else {
				log.Printf("  → Using NewAK with OpenBao-issued IAK certificate")
			}
		}
	}
	log.Printf("Certificate CN: %s", finalCommonName)
	log.Printf("")

	// Determine CA certificates base path
	// Try to find ca/ directory relative to executable
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// Try multiple potential locations for CA certificates
	potentialCAPaths := []string{
		filepath.Join(exeDir, "..", "ca"),           // bin/../ca (when running from bin/)
		filepath.Join(exeDir, "ca"),                 // ./ca (when running from project root)
		filepath.Join(exeDir, "deviceattestpoc", "ca"), // Special case
	}

	var caBasePath string
	for _, path := range potentialCAPaths {
		if stat, err := os.Stat(path); err == nil && stat.IsDir() {
			caBasePath = path
			break
		}
	}

	if caBasePath == "" {
		log.Fatalf("Failed to find CA certificates directory. Tried: %v", potentialCAPaths)
	}

	log.Printf("Using CA certificates from: %s", caBasePath)

	// Initialize TPM client
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Initializing TPM...")
	log.Println("═══════════════════════════════════════════════")
	tpmClient, err := NewTPMClient(finalTPMDevice, caBasePath, *attestMode)
	if err != nil {
		log.Fatalf("Failed to initialize TPM client: %v", err)
	}
	defer tpmClient.Close()

	permanentID := tpmClient.GetPermanentID()
	log.Printf("✓ TPM initialized. Permanent ID: %s", permanentID)
	log.Println("")

	// Generate CSR
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Generating Certificate Signing Request...")
	log.Println("═══════════════════════════════════════════════")
	csrPEM, err := tpmClient.GenerateCSR(finalCommonName, []string{finalCommonName}, nil)
	if err != nil {
		log.Fatalf("Failed to generate CSR: %v", err)
	}
	log.Printf("✓ CSR generated")
	log.Println("")

	// Connect to gRPC server
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Connecting to server...")
	log.Println("═══════════════════════════════════════════════")
	conn, err := grpc.Dial(finalServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	log.Printf("✓ Connected to server")
	log.Println("")

	// Create context for all gRPC calls
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Enroll TPM device (PoC only - normally done by admin)
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Enrolling TPM device (PoC demonstration only)...")
	log.Println("═══════════════════════════════════════════════")
	log.Println("")
	log.Println("⚠️  IMPORTANT SECURITY NOTICE:")
	log.Println("   In production, TPM enrollment MUST be performed by administrators")
	log.Println("   through secure out-of-band channels. This PoC allows client-initiated")
	log.Println("   enrollment for demonstration purposes ONLY.")
	log.Println("")

	ekRootCA, ekRootCAName, description, err := tpmClient.GetEnrollmentData()
	if err != nil {
		log.Fatalf("Failed to get enrollment data: %v", err)
	}

	enrollReq := &pb.TPMEnrollmentRequest{
		PermanentIdentifier: permanentID,
		EkRootCaPem:         ekRootCA,
		EkRootCaName:        ekRootCAName,
		DeviceDescription:   description,
	}

	enrollResp, err := client.EnrollTPM(ctx, enrollReq)
	if err != nil {
		log.Fatalf("Failed to enroll TPM: %v", err)
	}

	if enrollResp.Status == "error" {
		log.Fatalf("TPM enrollment failed: %s", enrollResp.Error)
	}

	log.Printf("✓ TPM enrolled successfully")
	log.Printf("  Permanent ID: %s", enrollResp.PermanentIdentifier)
	log.Printf("  EK Root CA: %s", enrollResp.EkRootCaName)
	log.Println("")

	// Provision IAK certificate if needed (AK mode only)
	if tpmClient.NeedsIAKProvisioning() {
		log.Println("")
		log.Println("═══════════════════════════════════════════════")
		log.Println("Provisioning IAK certificate from OpenBao...")
		log.Println("═══════════════════════════════════════════════")
		log.Println("")
		log.Println("ℹ️  AK MODE:")
		log.Println("   This TPM lacks manufacturer-provisioned IAK certificate.")
		log.Println("   OpenBao will act as a Privacy CA and issue an IAK certificate")
		log.Println("   for the newly created Attestation Key (AK).")
		log.Println("")

		// Get provisioning data from TPM client
		akPublicDER, ekCertPEM, err := tpmClient.GetIAKProvisioningData()
		if err != nil {
			log.Fatalf("Failed to get IAK provisioning data: %v", err)
		}

		provisionReq := &pb.ProvisionAIKRequest{
			PermanentIdentifier: permanentID,
			AkPublicKey:         akPublicDER,
			EkCertificatePem:    ekCertPEM,
		}

		provisionResp, err := client.ProvisionAIK(ctx, provisionReq)
		if err != nil {
			log.Fatalf("Failed to provision IAK certificate: %v", err)
		}

		if provisionResp.Status == "error" {
			log.Fatalf("IAK provisioning failed: %s", provisionResp.Error)
		}

		// Store the IAK certificate
		err = tpmClient.SetIAKCertificate(provisionResp.IakCertificatePem)
		if err != nil {
			log.Fatalf("Failed to store IAK certificate: %v", err)
		}

		log.Printf("✓ IAK certificate provisioned successfully by OpenBao")
		log.Printf("  Issuer: OpenBao PKI-IAK CA")
		log.Printf("  Valid from: %s", provisionResp.NotBefore)
		log.Printf("  Valid until: %s", provisionResp.NotAfter)
		log.Println("")
	}

	// Request certificate with device attestation
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Requesting certificate with device attestation...")
	log.Println("═══════════════════════════════════════════════")

	certReq := &pb.CertRequest{
		CommonName:          finalCommonName,
		SanDns:              []string{finalCommonName},
		SanIps:              []string{},
		CsrPem:              csrPEM,
		PermanentIdentifier: permanentID,
	}

	resp, err := client.RequestCertificate(ctx, certReq)
	if err != nil {
		log.Fatalf("Failed to request certificate: %v", err)
	}

	if resp.Status == "error" {
		log.Fatalf("Certificate request failed: %s", resp.Error)
	}

	log.Printf("✓ Certificate request initiated")
	log.Printf("  Order ID: %s", resp.OrderId)
	log.Printf("  Challenge URL: %s", resp.ChallengeUrl)
	log.Printf("  Challenge Token: %s", resp.ChallengeToken[:20])
	log.Println("")

	// Generate TPM attestation
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Generating TPM attestation...")
	log.Println("═══════════════════════════════════════════════")
	keyAuthorization := fmt.Sprintf("%s.%s", resp.ChallengeToken, resp.AccountThumbprint)
	attestationObject, err := tpmClient.GenerateAttestation(keyAuthorization)
	if err != nil {
		log.Fatalf("Failed to generate attestation: %v", err)
	}
	log.Printf("✓ TPM attestation generated (%d bytes)", len(attestationObject))
	log.Println("")

	// Submit attestation
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Submitting attestation to server...")
	log.Println("═══════════════════════════════════════════════")
	attReq := &pb.AttestationSubmit{
		OrderId:           resp.OrderId,
		AuthorizationUrl:  resp.AuthorizationUrl,
		ChallengeUrl:      resp.ChallengeUrl,
		AttestationObject: attestationObject,
	}

	attResp, err := client.SubmitAttestation(ctx, attReq)
	if err != nil {
		log.Fatalf("Failed to submit attestation: %v", err)
	}

	if attResp.Status == "error" {
		log.Fatalf("Attestation submission failed: %s", attResp.Error)
	}

	log.Printf("✓ Attestation submitted successfully")
	log.Printf("  Status: %s", attResp.Status)
	log.Println("")

	// Get certificate - poll until ready
	log.Println("")
	log.Println("═══════════════════════════════════════════════")
	log.Println("Retrieving certificate...")
	log.Println("═══════════════════════════════════════════════")

	certGetReq := &pb.GetCertRequest{
		OrderId: resp.OrderId,
	}

	var certResp *pb.CertResponse
	maxAttempts := 30
	pollInterval := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("  Polling for certificate... (attempt %d/%d)", attempt, maxAttempts)
		}

		certResp, err = client.GetCertificate(ctx, certGetReq)
		if err == nil && certResp.Status == "valid" {
			break
		}

		if attempt == maxAttempts {
			if err != nil {
				log.Fatalf("Failed to retrieve certificate after %d attempts: %v", maxAttempts, err)
			} else {
				log.Fatalf("Certificate not ready after %d attempts. Status: %s", maxAttempts, certResp.Status)
			}
		}

		time.Sleep(pollInterval)
	}

	log.Printf("✓ Certificate issued successfully!")

	// Save certificate to file
	if err := os.WriteFile(finalCertOutput, []byte(certResp.CertificatePem), 0644); err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}
	log.Printf("✓ Certificate saved to: %s", finalCertOutput)

	// Save private key in simulated mode
	var keyPath string
	if tpmClient.IsSimulated() {
		privKey := tpmClient.GetPrivateKey()
		if privKey != nil {
			keyPath = strings.TrimSuffix(finalCertOutput, filepath.Ext(finalCertOutput)) + "-key.pem"
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privKey),
			})
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				log.Fatalf("Failed to save private key: %v", err)
			}
			log.Printf("✓ Private key saved to: %s", keyPath)
		}
	}

	log.Println("")
	log.Printf("==============================================")
	log.Printf("✓ Certificate Generated and Ready for Use")
	log.Printf("==============================================")
	log.Println("")
	log.Printf("Summary:")
	log.Printf("  • TPM Permanent ID: %s", permanentID)
	log.Printf("  • Certificate CN: %s", finalCommonName)
	log.Printf("  • Order ID: %s", resp.OrderId)
	log.Println("")

	if tpmClient.IsSimulated() {
		log.Printf("Certificate Files (Simulated TPM):")
		log.Printf("  • Certificate: %s", finalCertOutput)
		log.Printf("  • Private Key: %s", keyPath)
		log.Println("")
		log.Printf("Inspect the certificate:")
		log.Printf("  openssl x509 -in %s -text -noout", finalCertOutput)
		log.Println("")
		log.Printf("Verify certificate and key match:")
		log.Printf("  openssl x509 -in %s -noout -modulus | openssl md5", finalCertOutput)
		log.Printf("  openssl rsa -in %s -noout -modulus | openssl md5", keyPath)
		log.Println("")
		log.Printf("Note: Private key saved because TPM is simulated.")
		log.Printf("      In hardware mode, the key stays protected inside the TPM.")
	} else {
		log.Printf("Certificate Files (Hardware TPM):")
		log.Printf("  • Certificate: %s", finalCertOutput)
		log.Printf("  • Private Key: Protected inside TPM (not exported)")
		log.Println("")
		log.Printf("Inspect the certificate:")
		log.Printf("  openssl x509 -in %s -text -noout", finalCertOutput)
		log.Println("")
		log.Printf("Note: The private key is sealed inside the TPM hardware.")
		log.Printf("      The TPM will perform signing operations for VPN use.")
	}
	log.Println("")
}
