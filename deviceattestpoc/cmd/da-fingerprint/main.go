// da-fingerprint displays the device permanent identifier (EK hash)
// This is used during provisioning to register the device with the server
//
// Usage: da-fingerprint [--tpm <device>]
//
// On Linux: default TPM device is /dev/tpmrm0
// On Windows: uses Windows TBS API automatically
//
// The permanent identifier is computed as: base64(SHA-256(EK public key))
// This value is stable and unique to the TPM/device.
package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func main() {
	log.SetFlags(0) // No timestamps for clean output
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	tpmDevice := flag.String("tpm", "", "TPM device path (default: platform-specific)")
	flag.Parse()

	finalTPMDevice := getConfig(*tpmDevice, "TPM_DEVICE", getDefaultTPMDevice())

	// Open TPM using platform-specific openTPM()
	rwc, err := openTPM(finalTPMDevice)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", finalTPMDevice, err)
	}
	defer rwc.Close()

	// Get EK
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return fmt.Errorf("failed to get EK: %w", err)
	}
	defer ek.Close()

	// Try to read EK certificate from NV index
	ekCert, err := getEKCertFromTPM(rwc)
	var pubKey crypto.PublicKey
	if err != nil {
		// No EK cert in NV - use EK public key directly
		pubKey = ek.PublicKey()
	} else {
		pubKey = ekCert.PublicKey
	}

	// Compute EK hash (permanent identifier)
	ekHash, err := computeEKHash(pubKey)
	if err != nil {
		return fmt.Errorf("failed to compute EK hash: %w", err)
	}

	// Output permanent identifier
	fmt.Println(ekHash)
	return nil
}

func getDefaultTPMDevice() string {
	if runtime.GOOS == "windows" {
		return "" // go-tpm uses Windows TBS API automatically when path is empty
	}
	return "/dev/tpmrm0"
}

func getConfig(flagValue, envVar, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return defaultValue
}

func getEKCertFromTPM(rwc io.ReadWriteCloser) (*x509.Certificate, error) {
	ekCertNVIndex := tpmutil.Handle(0x01C00002)
	certDER, err := tpm2.NVReadEx(rwc, ekCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK cert from NV: %w", err)
	}
	return x509.ParseCertificate(certDER)
}

func computeEKHash(pubKey crypto.PublicKey) (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal EK public key: %w", err)
	}
	hash := sha256.Sum256(pubKeyDER)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}
