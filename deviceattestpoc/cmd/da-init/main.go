// da-init bootstraps device attestation trust anchor via TOFU
// This is the entry point for device initialization.
//
// Usage:
//   da-init <server-address> <spki-pin>            - First-time TOFU setup with SPKI verification
//   da-init --force <server-address>               - First-time setup without SPKI verification (insecure)
//   da-init                                        - Full reinit (clears LAK/agent, re-provisions)
//   da-init --manual <server-address> <spki-pin>   - TOFU setup only (no auto da-lak/da-agent)
//   da-init --manual --force <server-address>      - Force setup only (no auto da-lak/da-agent)
//   da-init --manual                               - Reinit setup only (no auto da-lak/da-agent)
//
// The --manual flag configures the trust anchor but skips automatic chaining
// to da-lak and da-agent, letting you run them separately.
//
// The SPKI pin is displayed by the server on startup and should be provided
// out-of-band (e.g., printed documentation, QR code, secure email).
//
// On successful setup:
// 1. Server CA is verified against the SPKI pin (unless --force is used)
// 2. Server address and CA chain are persisted to da.json
// 3. da-lak is executed to provision LAK certificate (unless --manual)
// 4. da-agent is executed to provision agent certificate (unless --manual)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Strip --manual flag from args
	manual := false
	var args []string
	for _, a := range os.Args[1:] {
		if a == "--manual" {
			manual = true
		} else {
			args = append(args, a)
		}
	}

	// Check for --force flag
	if len(args) >= 1 && args[0] == "--force" {
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: da-init [--manual] --force <server-address>\n")
			os.Exit(1)
		}
		return runForce(args[1], manual)
	}

	switch len(args) {
	case 0:
		// Reinit mode: no arguments
		return runReinit(manual)
	case 2:
		// TOFU mode: server-address and spki-pin
		return runTOFU(args[0], args[1], manual)
	default:
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  da-init <server-address> <spki-pin>  - First-time TOFU setup\n")
		fmt.Fprintf(os.Stderr, "  da-init --force <server-address>     - Setup without SPKI verification (insecure)\n")
		fmt.Fprintf(os.Stderr, "  da-init                              - Full reinit\n")
		fmt.Fprintf(os.Stderr, "\nAdd --manual to skip automatic da-lak/da-agent chaining.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  da-init grpc-server:50051 sha256//abc123...\n")
		fmt.Fprintf(os.Stderr, "  da-init --force grpc-server:50051\n")
		fmt.Fprintf(os.Stderr, "  da-init --manual --force grpc-server:50051\n")
		fmt.Fprintf(os.Stderr, "  da-init\n")
		os.Exit(1)
		return nil
	}
}

// runTOFU performs Trust-On-First-Use setup
func runTOFU(serverAddr, spkiPin string, manual bool) error {
	fmt.Fprintf(os.Stderr, "── da-init: TOFU Bootstrap ──────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Server:   %s\n", serverAddr)
	fmt.Fprintf(os.Stderr, "  SPKI Pin: %s\n", spkiPin)

	// Create TOFU TLS credentials
	creds, getResult, err := NewTLSCredentialsWithTOFU(spkiPin)
	if err != nil {
		return fmt.Errorf("invalid SPKI pin: %w", err)
	}

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
	client := pb.NewCertificateServiceClient(conn)
	_, _ = client.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{})

	// Get TOFU result (CA chain extracted during TLS handshake)
	result := getResult()
	if result == nil {
		return fmt.Errorf("TOFU verification failed: no result captured")
	}

	fmt.Fprintf(os.Stderr, "  SPKI pin verified\n")

	// Clear existing LAK/agent certificates
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
	fmt.Fprintf(os.Stderr, "  Server CA saved to %s\n", GetBlobPath())

	conn.Close() // Close TOFU connection before chaining to other tools

	if manual {
		fmt.Fprintf(os.Stderr, "  Trust anchor configured (manual mode)\n")
		fmt.Fprintf(os.Stderr, "  Next: run da-lak, then da-agent\n")
		return nil
	}

	// Chain to da-lak (Phase 1: TCG Credential Activation)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent (Phase 2: ACME device-attest-01)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "── Device initialized successfully! ─────────────────────────\n")
	return nil
}

// runReinit performs a full reinitialization using existing server config
func runReinit(manual bool) error {
	// Load existing server config
	serverAddr, _, _, exists, err := LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}
	if !exists {
		return fmt.Errorf("not configured. Run: da-init <server-address> <spki-pin>")
	}

	fmt.Fprintf(os.Stderr, "── da-init: Reinitialize ────────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Server: %s\n", serverAddr)

	// Clear existing LAK/agent certificates
	if err := ClearLAKBlobs(); err != nil {
		return fmt.Errorf("failed to clear LAK blobs: %w", err)
	}
	if err := ClearAgentBlobs(); err != nil {
		return fmt.Errorf("failed to clear agent blobs: %w", err)
	}

	if manual {
		fmt.Fprintf(os.Stderr, "  Trust anchor configured (manual mode)\n")
		fmt.Fprintf(os.Stderr, "  Next: run da-lak, then da-agent\n")
		return nil
	}

	// Chain to da-lak (Phase 1: TCG Credential Activation)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent (Phase 2: ACME device-attest-01)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "── Device reinitialized successfully! ───────────────────────\n")
	return nil
}

// runForce performs setup without SPKI verification (insecure, for development/testing)
func runForce(serverAddr string, manual bool) error {
	fmt.Fprintf(os.Stderr, "── da-init: Force Bootstrap (no SPKI) ──────────────────────\n")
	fmt.Fprintf(os.Stderr, "  WARNING: Skipping SPKI verification - dev/testing only!\n")
	fmt.Fprintf(os.Stderr, "  Server: %s\n", serverAddr)

	// Create insecure TLS credentials that accept any certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	creds := credentials.NewTLS(tlsConfig)

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

	// Debug: connection state visible with LOG_LEVEL=debug via common.go init()

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

	fmt.Fprintf(os.Stderr, "  SPKI Pin: %s\n", spkiPin)
	fmt.Fprintf(os.Stderr, "  Server CA saved to %s\n", GetBlobPath())

	// Clear existing LAK/agent certificates
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

	conn.Close() // Close connection before chaining to other tools

	if manual {
		fmt.Fprintf(os.Stderr, "  Trust anchor configured (manual mode)\n")
		fmt.Fprintf(os.Stderr, "  Next: run da-lak, then da-agent\n")
		return nil
	}

	// Chain to da-lak (Phase 1: TCG Credential Activation)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-lak"); err != nil {
		return fmt.Errorf("da-lak failed: %w", err)
	}

	// Chain to da-agent (Phase 2: ACME device-attest-01)
	fmt.Fprintln(os.Stderr)
	if err := RunTool("da-agent"); err != nil {
		return fmt.Errorf("da-agent failed: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "── Device initialized successfully! ─────────────────────────\n")
	return nil
}
