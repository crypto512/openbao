package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// GetDAConfigPath returns the path to da.json configuration file
func GetDAConfigPath() string {
	if path := os.Getenv("DA_JSON_PATH"); path != "" {
		return path
	}
	return "/etc/da.json"
}

// ComputeEKHash computes SHA-256(EK public key) and returns base64 encoded string
// This is the permanent identifier for the device
func ComputeEKHash(pubKey crypto.PublicKey) (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal EK public key: %w", err)
	}
	hash := sha256.Sum256(pubKeyDER)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// GetEKCertFromTPM reads EK certificate from TPM NV index
// RSA EK cert is typically at NV index 0x01C00002
func GetEKCertFromTPM(rwc io.ReadWriteCloser) (*x509.Certificate, error) {
	ekCertNVIndex := tpmutil.Handle(0x01C00002)
	certDER, err := tpm2.NVReadEx(rwc, ekCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK cert from NV: %w", err)
	}
	return x509.ParseCertificate(certDER)
}

// InitTPMConnection opens a connection to the TPM device
func InitTPMConnection(tpmDevice string) (io.ReadWriteCloser, error) {
	if tpmDevice == "" {
		tpmDevice = "/dev/tpmrm0"
	}
	return tpm2.OpenTPM(tpmDevice)
}

// GetConfigString returns config value from flag, env var, or default (in order of priority)
func GetConfigString(flagValue, envVar, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return defaultValue
}
