// da-lak provisions a Local Attestation Key (LAK) certificate
// This is a one-time setup that stores AK blobs and LAK certificate to /etc/da.json
//
// Usage: da-lak [--tpm /dev/tpmrm0] [--clear]
//
// Prerequisites: da-init must be run first to configure server trust.
//
// The LAK certificate binds the AK public key to the device identity and is
// issued by the Privacy CA after successful credential activation.
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
	clear := flag.Bool("clear", false, "Clear existing LAK and re-provision")
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

	fmt.Fprintf(os.Stderr, "── Phase 1: TCG Credential Activation (LAK) ────────────────\n")
	log.Printf("Server: %s, TPM: %s", serverAddr, finalTPMDevice)

	if *clear {
		if err := ClearLAKBlobs(); err != nil {
			return fmt.Errorf("failed to clear LAK blobs: %w", err)
		}
		log.Printf("LAK data cleared")
	}

	// Initialize TPM for enrollment only (no AK creation yet)
	// This allows us to check approval status before heavy TPM operations
	tpmClient, err := NewTPMClientForEnrollment(finalTPMDevice)
	if err != nil {
		return fmt.Errorf("failed to initialize TPM: %w", err)
	}
	defer tpmClient.Close()

	permanentID := tpmClient.GetPermanentID()
	fmt.Fprintf(os.Stderr, "  Device ID: %s\n", permanentID)

	if !tpmClient.NeedsLAKProvisioning() {
		fmt.Fprintf(os.Stderr, "  LAK certificate already exists (use --clear to re-provision)\n")
		return nil
	}

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

	// Check enrollment/approval status with server BEFORE creating AK
	fmt.Fprintf(os.Stderr, "  Enrolling device...\n")
	enrollResp, err := client.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{
		EkCertificatePem:  tpmClient.GetEKCertificatePEM(),
		DeviceDescription: fmt.Sprintf("Device %s", permanentID[:8]),
	})
	if err != nil {
		return fmt.Errorf("failed to enroll TPM: %w", err)
	}
	if enrollResp.Status == "error" {
		return fmt.Errorf("TPM enrollment failed: %s", enrollResp.Error)
	}

	// Check if device needs approval - exit BEFORE any AK operations
	if enrollResp.PendingApproval {
		tpmClient.Close()
		conn.Close()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr, "  DEVICE PENDING APPROVAL")
		fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  This device has been registered but requires admin approval")
		fmt.Fprintln(os.Stderr, "  before it can proceed with provisioning.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "  Permanent ID: %s\n", enrollResp.PermanentIdentifier)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Next steps:")
		fmt.Fprintln(os.Stderr, "  1. Ask your administrator to approve this device")
		fmt.Fprintln(os.Stderr, "  2. Run 'da-init' again after approval")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════")
		os.Exit(2) // Exit code 2 indicates pending approval
	}

	// Device is approved - now initialize AK (create or load)
	fmt.Fprintf(os.Stderr, "  Creating Attestation Key (AK)...\n")
	if err := tpmClient.InitializeAK(); err != nil {
		return fmt.Errorf("failed to initialize AK: %w", err)
	}

	// Get AK activation data for credential challenge
	fmt.Fprintf(os.Stderr, "  MakeCredential challenge...\n")
	akParams, ekPublic, err := tpmClient.GetAKActivationData()
	if err != nil {
		return fmt.Errorf("failed to get AK activation data: %w", err)
	}

	provisionResp, err := client.ProvisionLAK(ctx, &pb.ProvisionLAKRequest{
		PermanentIdentifier: permanentID,
		AkParameters:        akParams,
		EkPublic:            ekPublic,
		EkCertPem:           tpmClient.GetEKCertificatePEM(),
	})
	if err != nil {
		return fmt.Errorf("failed to request credential challenge: %w", err)
	}
	if provisionResp.Status != "challenge" {
		return fmt.Errorf("credential challenge failed: %s", provisionResp.Error)
	}

	// Activate credential - proves AK and EK are in the same TPM
	fmt.Fprintf(os.Stderr, "  ActivateCredential (proving AK-EK binding)...\n")
	decryptedSecret, err := tpmClient.ActivateCredentialChallenge(provisionResp.EncryptedCredential)
	if err != nil {
		return fmt.Errorf("TPM ActivateCredential failed: %w", err)
	}

	activateResp, err := client.ActivateCredential(ctx, &pb.ActivateCredentialRequest{
		SessionId:       provisionResp.SessionId,
		DecryptedSecret: decryptedSecret,
	})
	if err != nil {
		return fmt.Errorf("failed to activate credential: %w", err)
	}
	if activateResp.Status != "success" {
		return fmt.Errorf("credential activation failed: %s", activateResp.Error)
	}

	// Store LAK certificate
	if err := tpmClient.SetLAKCertificate(activateResp.LakCertificatePem, activateResp.LakRootCaPem); err != nil {
		return fmt.Errorf("failed to store LAK certificate: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  LAK certificate issued (valid: %s to %s)\n", activateResp.NotBefore, activateResp.NotAfter)
	return nil
}
