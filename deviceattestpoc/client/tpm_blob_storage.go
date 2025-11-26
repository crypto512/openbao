package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// TPMBlobStorage stores AK blobs and LAK certificate for device attestation
// This is the persistent state saved to /etc/da.json
//
// Workflow:
// 1. da-lak: Create AK -> MakeCredential/ActivateCredential -> Get LAK cert -> Save to da.json
// 2. da-gen: Load AK + LAK cert from da.json -> Generate software key -> Attest -> Get certificate
type TPMBlobStorage struct {
	// AK (Attestation Key) blobs - TPM2B_PRIVATE and TPM2B_PUBLIC
	AKPrivate string `json:"ak_private"`
	AKPublic  string `json:"ak_public"`

	// LAK Certificate - X.509 cert for AK issued by Privacy CA
	LAKCertPEM string `json:"lak_cert_pem,omitempty"`

	// LAK CA Chain - CA certificate that signed the LAK certificate
	LAKCACertPEM string `json:"lak_ca_cert_pem,omitempty"`

	// Metadata
	Version     string `json:"version"`
	Description string `json:"description"`
}

const (
	blobStorageVersion = "2.0"
	defaultBlobPath    = "/etc/da.json"
)

// SaveBlobs saves AK blobs and LAK certificate to da.json
func SaveBlobs(akPriv, akPub []byte, lakCertPEM, lakCACertPEM string) error {
	blobPath := getBlobPath()
	log.Printf("Saving TPM blobs to: %s", blobPath)

	if err := os.MkdirAll(filepath.Dir(blobPath), 0755); err != nil {
		return fmt.Errorf("failed to create blob directory: %w", err)
	}

	storage := TPMBlobStorage{
		AKPrivate:    base64.StdEncoding.EncodeToString(akPriv),
		AKPublic:     base64.StdEncoding.EncodeToString(akPub),
		LAKCertPEM:   lakCertPEM,
		LAKCACertPEM: lakCACertPEM,
		Version:      blobStorageVersion,
		Description:  "Device attestation state",
	}

	jsonData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blob storage: %w", err)
	}

	if err := os.WriteFile(blobPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write blob file: %w", err)
	}

	log.Printf("TPM blobs saved")
	return nil
}

// LoadBlobs loads AK blobs and LAK certificate from da.json
func LoadBlobs() (akPriv, akPub []byte, lakCertPEM, lakCACertPEM string, exists bool, err error) {
	blobPath := getBlobPath()

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return nil, nil, "", "", false, nil
	}

	log.Printf("Loading TPM blobs from: %s", blobPath)

	jsonData, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, nil, "", "", false, fmt.Errorf("failed to read blob file: %w", err)
	}

	var storage TPMBlobStorage
	if err := json.Unmarshal(jsonData, &storage); err != nil {
		return nil, nil, "", "", false, fmt.Errorf("failed to unmarshal blob storage: %w", err)
	}

	if storage.Version != blobStorageVersion {
		log.Printf("Blob version mismatch (got %s, want %s), will recreate", storage.Version, blobStorageVersion)
		return nil, nil, "", "", false, nil
	}

	akPriv, err = base64.StdEncoding.DecodeString(storage.AKPrivate)
	if err != nil {
		return nil, nil, "", "", false, fmt.Errorf("failed to decode AK private: %w", err)
	}

	akPub, err = base64.StdEncoding.DecodeString(storage.AKPublic)
	if err != nil {
		return nil, nil, "", "", false, fmt.Errorf("failed to decode AK public: %w", err)
	}

	log.Printf("TPM blobs loaded")
	return akPriv, akPub, storage.LAKCertPEM, storage.LAKCACertPEM, true, nil
}

// ClearBlobs removes the da.json file
func ClearBlobs() error {
	blobPath := getBlobPath()
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(blobPath)
}

func getBlobPath() string {
	if path := os.Getenv("DA_JSON_PATH"); path != "" {
		return path
	}
	return defaultBlobPath
}

// BlobsExist returns true if da.json exists
func BlobsExist() bool {
	_, err := os.Stat(getBlobPath())
	return err == nil
}
