// da-lak provisions a Local Attestation Key (LAK) certificate
// This is a one-time setup that stores AK blobs and LAK certificate to /etc/da.json
//
// Usage: da-lak [--server localhost:50051] [--tpm /dev/tpmrm0] [--clear]
//
// The LAK certificate binds the AK public key to the device identity and is
// issued by the Privacy CA after successful credential activation.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	serverAddr := flag.String("server", "", "gRPC server address")
	tpmDevice := flag.String("tpm", "", "TPM device path")
	clear := flag.Bool("clear", false, "Clear existing da.json and re-provision")
	flag.Parse()

	finalServerAddr := GetConfigString(*serverAddr, "GRPC_SERVER", "localhost:50051")
	finalTPMDevice := GetConfigString(*tpmDevice, "TPM_DEVICE", "/dev/tpmrm0")

	log.Printf("da-lak: LAK Certificate Provisioning")
	log.Printf("Server: %s", finalServerAddr)
	log.Printf("TPM: %s", finalTPMDevice)

	if *clear {
		if err := ClearBlobs(); err != nil {
			log.Fatalf("Failed to clear da.json: %v", err)
		}
		log.Printf("da.json cleared")
	}

	tpmClient, err := NewTPMClient(finalTPMDevice)
	if err != nil {
		log.Fatalf("Failed to initialize TPM: %v", err)
	}
	defer tpmClient.Close()

	permanentID := tpmClient.GetPermanentID()
	log.Printf("Permanent ID: %s", permanentID)

	if !tpmClient.NeedsLAKProvisioning() {
		log.Printf("LAK certificate already exists in da.json")
		log.Printf("Use --clear to re-provision")
		return
	}

	conn, err := grpc.NewClient(finalServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	client := pb.NewCertificateServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Enroll TPM
	log.Printf("Enrolling TPM device...")
	enrollResp, err := client.EnrollTPM(ctx, &pb.TPMEnrollmentRequest{
		EkCertificatePem:  tpmClient.GetEKCertificatePEM(),
		DeviceDescription: fmt.Sprintf("Device %s", permanentID[:8]),
	})
	if err != nil {
		log.Fatalf("Failed to enroll TPM: %v", err)
	}
	if enrollResp.Status == "error" {
		log.Fatalf("TPM enrollment failed: %s", enrollResp.Error)
	}
	log.Printf("TPM enrolled: %s", enrollResp.PermanentIdentifier)

	// Get AK activation data
	log.Printf("Requesting credential challenge...")
	akParams, ekPublic, err := tpmClient.GetAKActivationData()
	if err != nil {
		log.Fatalf("Failed to get AK activation data: %v", err)
	}

	provisionResp, err := client.ProvisionLAK(ctx, &pb.ProvisionLAKRequest{
		PermanentIdentifier: permanentID,
		AkParameters:        akParams,
		EkPublic:            ekPublic,
		EkCertPem:           tpmClient.GetEKCertificatePEM(),
	})
	if err != nil {
		log.Fatalf("Failed to request credential challenge: %v", err)
	}
	if provisionResp.Status != "challenge" {
		log.Fatalf("Credential challenge failed: %s", provisionResp.Error)
	}

	// Activate credential
	log.Printf("Activating credential...")
	decryptedSecret, err := tpmClient.ActivateCredentialChallenge(provisionResp.EncryptedCredential)
	if err != nil {
		log.Fatalf("TPM ActivateCredential failed: %v", err)
	}

	activateResp, err := client.ActivateCredential(ctx, &pb.ActivateCredentialRequest{
		SessionId:       provisionResp.SessionId,
		DecryptedSecret: decryptedSecret,
	})
	if err != nil {
		log.Fatalf("Failed to activate credential: %v", err)
	}
	if activateResp.Status != "success" {
		log.Fatalf("Credential activation failed: %s", activateResp.Error)
	}

	// Store LAK certificate
	if err := tpmClient.SetLAKCertificate(activateResp.LakCertificatePem, activateResp.LakRootCaPem); err != nil {
		log.Fatalf("Failed to store LAK certificate: %v", err)
	}

	log.Printf("LAK certificate provisioned successfully")
	log.Printf("  Valid from: %s", activateResp.NotBefore)
	log.Printf("  Valid until: %s", activateResp.NotAfter)
	log.Printf("  Saved to: %s", GetDAConfigPath())
}
