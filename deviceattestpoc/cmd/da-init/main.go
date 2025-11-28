// da-init bootstraps device attestation trust anchor via TOFU
// This is the entry point for device initialization.
//
// Usage:
//   da-init <server-address> <spki-pin>  - First-time TOFU setup with SPKI verification
//   da-init --force <server-address>     - First-time setup without SPKI verification (insecure)
//   da-init                              - Full reinit (clears LAK/agent, re-provisions)
//
// The SPKI pin is displayed by the server on startup and should be provided
// out-of-band (e.g., printed documentation, QR code, secure email).
//
// On successful setup:
// 1. Server CA is verified against the SPKI pin (unless --force is used)
// 2. Server address and CA chain are persisted to da.json
// 3. da-lak is executed to provision LAK certificate
// 4. da-agent is executed to provision agent certificate
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	// Check for --force flag
	if len(os.Args) >= 2 && os.Args[1] == "--force" {
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "Usage: da-init --force <server-address>\n")
			os.Exit(1)
		}
		serverAddr := os.Args[2]
		return runForce(serverAddr)
	}

	switch len(os.Args) {
	case 1:
		// Reinit mode: no arguments
		return runReinit()
	case 3:
		// TOFU mode: server-address and spki-pin
		serverAddr := os.Args[1]
		spkiPin := os.Args[2]
		return runTOFU(serverAddr, spkiPin)
	default:
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  da-init <server-address> <spki-pin>  - First-time TOFU setup\n")
		fmt.Fprintf(os.Stderr, "  da-init --force <server-address>     - Setup without SPKI verification (insecure)\n")
		fmt.Fprintf(os.Stderr, "  da-init                              - Full reinit\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  da-init grpc-server:50051 sha256//abc123...\n")
		fmt.Fprintf(os.Stderr, "  da-init --force grpc-server:50051\n")
		fmt.Fprintf(os.Stderr, "  da-init\n")
		os.Exit(1)
		return nil
	}
}

// runTOFU performs Trust-On-First-Use setup
func runTOFU(serverAddr, spkiPin string) error {
	log.Printf("da-init: TOFU Setup")
	log.Printf("Server: %s", serverAddr)
	log.Printf("SPKI Pin: %s", spkiPin)

	// Create TOFU TLS credentials
	creds, getResult, err := NewTLSCredentialsWithTOFU(spkiPin)
	if err != nil {
		return fmt.Errorf("invalid SPKI pin: %w", err)
	}

	log.Printf("Connecting to %s...", serverAddr)

	// Connect using TOFU credentials - TLS handshake triggers pin verification
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(), // Wait for connection to be established
	)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Make a simple call to ensure connection is working
	// We use EnrollTPM with empty request - it will fail but proves connectivity
	client := pb.NewCertificateServiceClient(conn)
	_, _ = client.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{})

	// Get TOFU result (CA chain extracted during TLS handshake)
	result := getResult()
	if result == nil {
		return fmt.Errorf("TOFU verification failed: no result captured")
	}

	log.Printf("SPKI pin verified")

	// Clear existing LAK/agent certificates
	log.Printf("Clearing existing certificates...")
	if err := ClearLAKBlobs(); err != nil {
		return fmt.Errorf("failed to clear LAK blobs: %w", err)
	}
	if err := ClearAgentBlobs(); err != nil {
		return fmt.Errorf("failed to clear agent blobs: %w", err)
	}

	// Save server config to da.json
	if err := SaveServerConfig(serverAddr, result.CAPem, result.SPKIPin); err != nil {
		return fmt.Errorf("failed to save server config: %w", err)
	}
	log.Printf("Server CA saved to %s", GetBlobPath())

	conn.Close() // Close TOFU connection before chaining to other tools

	// Chain to da-lak
	log.Printf("")
	log.Printf("Running da-lak...")
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent
	log.Printf("")
	log.Printf("Running da-agent...")
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	log.Printf("")
	log.Printf("Device initialized successfully!")
	return nil
}

// runReinit performs a full reinitialization using existing server config
func runReinit() error {
	log.Printf("da-init: Full Reinit")

	// Load existing server config
	serverAddr, _, _, exists, err := LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}
	if !exists {
		return fmt.Errorf("not configured. Run: da-init <server-address> <spki-pin>")
	}

	log.Printf("Server: %s", serverAddr)

	// Clear existing LAK/agent certificates
	log.Printf("Clearing LAK and agent certificates...")
	if err := ClearLAKBlobs(); err != nil {
		return fmt.Errorf("failed to clear LAK blobs: %w", err)
	}
	if err := ClearAgentBlobs(); err != nil {
		return fmt.Errorf("failed to clear agent blobs: %w", err)
	}

	// Chain to da-lak
	log.Printf("")
	log.Printf("Running da-lak...")
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent
	log.Printf("")
	log.Printf("Running da-agent...")
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	log.Printf("")
	log.Printf("Device reinitialized successfully!")
	return nil
}

// runForce performs setup without SPKI verification (insecure, for development/testing)
func runForce(serverAddr string) error {
	log.Printf("da-init: Force Setup (no SPKI verification)")
	log.Printf("WARNING: Skipping SPKI verification - use only for development/testing!")
	log.Printf("Server: %s", serverAddr)

	// Create insecure TLS credentials that accept any certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	creds := credentials.NewTLS(tlsConfig)

	log.Printf("Connecting to %s...", serverAddr)

	// Connect to server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Get the server's certificate chain
	state := conn.GetState()
	log.Printf("Connection state: %v", state)

	// Make a call to trigger TLS handshake and get peer certificates
	client := pb.NewCertificateServiceClient(conn)
	_, _ = client.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{})

	// Extract CA from connection - we need to reconnect with a callback
	var caPEM string
	var spkiPin string

	// Reconnect with a custom verifier to capture the certificate chain
	tlsConfigCapture := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates received")
			}
			var chain []*x509.Certificate
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				chain = append(chain, cert)
			}
			caPEM = ExtractCAChainPEM(chain)
			if len(chain) > 0 {
				spkiPin = ComputeSPKIPin(chain[0])
			}
			return nil
		},
	}
	credsCapture := credentials.NewTLS(tlsConfigCapture)

	conn2, err := grpc.DialContext(ctx, serverAddr,
		grpc.WithTransportCredentials(credsCapture),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect for cert capture: %w", err)
	}
	client2 := pb.NewCertificateServiceClient(conn2)
	_, _ = client2.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{})
	conn2.Close()

	if caPEM == "" {
		return fmt.Errorf("failed to capture server CA")
	}

	log.Printf("Server SPKI Pin: %s", spkiPin)
	log.Printf("Captured server CA")

	// Clear existing LAK/agent certificates
	log.Printf("Clearing existing certificates...")
	if err := ClearLAKBlobs(); err != nil {
		return fmt.Errorf("failed to clear LAK blobs: %w", err)
	}
	if err := ClearAgentBlobs(); err != nil {
		return fmt.Errorf("failed to clear agent blobs: %w", err)
	}

	// Save server config to da.json
	if err := SaveServerConfig(serverAddr, caPEM, spkiPin); err != nil {
		return fmt.Errorf("failed to save server config: %w", err)
	}
	log.Printf("Server CA saved to %s", GetBlobPath())

	conn.Close() // Close connection before chaining to other tools

	// Chain to da-lak
	log.Printf("")
	log.Printf("Running da-lak...")
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent
	log.Printf("")
	log.Printf("Running da-agent...")
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	log.Printf("")
	log.Printf("Device initialized successfully!")
	return nil
}
