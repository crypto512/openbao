package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// TPMBlobStorage stores AK blobs, LAK certificate, and agent certificate for device attestation
// This is the persistent state saved to /etc/da.json
//
// Workflow:
// 1. da-lak: Create AK -> MakeCredential/ActivateCredential -> Get LAK cert -> Save to da.json
// 2. da-agent: Load AK + LAK cert -> ACME device-attest-01 -> Get agent cert -> Save to da.json
// 3. da-gen: Load agent cert -> mTLS -> Get usage certificate
type TPMBlobStorage struct {
	// AK (Attestation Key) blobs - TPM2B_PRIVATE and TPM2B_PUBLIC
	AKPrivate string `json:"ak_private"`
	AKPublic  string `json:"ak_public"`

	// LAK Certificate - X.509 cert for AK issued by Privacy CA
	LAKCertPEM string `json:"lak_cert_pem,omitempty"`

	// LAK CA Chain - CA certificate that signed the LAK certificate
	LAKCACertPEM string `json:"lak_ca_cert_pem,omitempty"`

	// Agent certificate and key - hardware-bound via ACME device-attest-01
	AgentCertPEM    string `json:"agent_cert_pem,omitempty"`
	AgentKeyPrivate string `json:"agent_key_private,omitempty"` // TPM blob (base64)
	AgentKeyPublic  string `json:"agent_key_public,omitempty"`  // TPM blob (base64)
	AgentCACertPEM  string `json:"agent_ca_cert_pem,omitempty"`

	// Server connection (set by da-init)
	ServerAddress string `json:"server_address,omitempty"` // e.g., "grpc-server:50051"

	// Server CA trust (persisted after TOFU)
	ServerCAPEM string `json:"server_ca_pem,omitempty"` // Full CA chain PEM
	ServerSPKI  string `json:"server_spki,omitempty"`   // SPKI pin for verification

	// Metadata
	Version     string `json:"version"`
	Description string `json:"description"`
}

const (
	blobStorageVersion = "3.0"
	defaultBlobPath    = "/etc/da/da.json"
)

// SaveBlobs saves AK blobs and LAK certificate to da.json (preserves agent data if present)
func SaveBlobs(akPriv, akPub []byte, lakCertPEM, lakCACertPEM string) error {
	blobPath := getBlobPath()
	log.Printf("Saving TPM blobs to: %s", blobPath)

	if err := os.MkdirAll(filepath.Dir(blobPath), 0755); err != nil {
		return fmt.Errorf("failed to create blob directory: %w", err)
	}

	// Load existing storage to preserve agent data
	storage := TPMBlobStorage{
		Version:     blobStorageVersion,
		Description: "Device attestation state",
	}
	if jsonData, err := os.ReadFile(blobPath); err == nil {
		json.Unmarshal(jsonData, &storage)
	}

	// Update AK and LAK data
	storage.AKPrivate = base64.StdEncoding.EncodeToString(akPriv)
	storage.AKPublic = base64.StdEncoding.EncodeToString(akPub)
	storage.LAKCertPEM = lakCertPEM
	storage.LAKCACertPEM = lakCACertPEM
	storage.Version = blobStorageVersion

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

// SaveAgentBlobs saves agent certificate and key blobs to da.json (preserves AK/LAK data)
func SaveAgentBlobs(agentCertPEM string, agentKeyPriv, agentKeyPub []byte, agentCACertPEM string) error {
	blobPath := getBlobPath()
	log.Printf("Saving agent blobs to: %s", blobPath)

	// Load existing storage to preserve AK/LAK data
	storage := TPMBlobStorage{
		Version:     blobStorageVersion,
		Description: "Device attestation state",
	}
	if jsonData, err := os.ReadFile(blobPath); err == nil {
		json.Unmarshal(jsonData, &storage)
	}

	// Update agent data
	storage.AgentCertPEM = agentCertPEM
	storage.AgentKeyPrivate = base64.StdEncoding.EncodeToString(agentKeyPriv)
	storage.AgentKeyPublic = base64.StdEncoding.EncodeToString(agentKeyPub)
	storage.AgentCACertPEM = agentCACertPEM
	storage.Version = blobStorageVersion

	jsonData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blob storage: %w", err)
	}

	if err := os.WriteFile(blobPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write blob file: %w", err)
	}

	log.Printf("Agent blobs saved")
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

	// Accept version 2.0 and 3.0 for AK/LAK data
	if storage.Version != blobStorageVersion && storage.Version != "2.0" {
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

// LoadAgentBlobs loads agent certificate and key blobs from da.json
func LoadAgentBlobs() (agentCertPEM string, agentKeyPriv, agentKeyPub []byte, agentCACertPEM string, exists bool, err error) {
	blobPath := getBlobPath()

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return "", nil, nil, "", false, nil
	}

	jsonData, err := os.ReadFile(blobPath)
	if err != nil {
		return "", nil, nil, "", false, fmt.Errorf("failed to read blob file: %w", err)
	}

	var storage TPMBlobStorage
	if err := json.Unmarshal(jsonData, &storage); err != nil {
		return "", nil, nil, "", false, fmt.Errorf("failed to unmarshal blob storage: %w", err)
	}

	// Agent blobs only exist in version 3.0
	if storage.AgentCertPEM == "" || storage.AgentKeyPrivate == "" {
		return "", nil, nil, "", false, nil
	}

	agentKeyPriv, err = base64.StdEncoding.DecodeString(storage.AgentKeyPrivate)
	if err != nil {
		return "", nil, nil, "", false, fmt.Errorf("failed to decode agent key private: %w", err)
	}

	agentKeyPub, err = base64.StdEncoding.DecodeString(storage.AgentKeyPublic)
	if err != nil {
		return "", nil, nil, "", false, fmt.Errorf("failed to decode agent key public: %w", err)
	}

	log.Printf("Agent blobs loaded")
	return storage.AgentCertPEM, agentKeyPriv, agentKeyPub, storage.AgentCACertPEM, true, nil
}

// ClearAgentBlobs clears only the agent certificate and key data from da.json
func ClearAgentBlobs() error {
	blobPath := getBlobPath()

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return nil
	}

	jsonData, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("failed to read blob file: %w", err)
	}

	var storage TPMBlobStorage
	if err := json.Unmarshal(jsonData, &storage); err != nil {
		return fmt.Errorf("failed to unmarshal blob storage: %w", err)
	}

	// Clear agent data
	storage.AgentCertPEM = ""
	storage.AgentKeyPrivate = ""
	storage.AgentKeyPublic = ""
	storage.AgentCACertPEM = ""

	newData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blob storage: %w", err)
	}

	if err := os.WriteFile(blobPath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write blob file: %w", err)
	}

	log.Printf("Agent blobs cleared")
	return nil
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

// AgentBlobsExist returns true if agent certificate and key are stored
func AgentBlobsExist() bool {
	_, _, _, _, exists, _ := LoadAgentBlobs()
	return exists
}

// GetBlobPath returns the current blob path (for logging)
func GetBlobPath() string {
	return getBlobPath()
}

// LoadServerConfig loads server address, CA PEM, and SPKI pin from da.json
func LoadServerConfig() (address, caPEM, spkiPin string, exists bool, err error) {
	blobPath := getBlobPath()

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return "", "", "", false, nil
	}

	jsonData, err := os.ReadFile(blobPath)
	if err != nil {
		return "", "", "", false, fmt.Errorf("failed to read blob file: %w", err)
	}

	var storage TPMBlobStorage
	if err := json.Unmarshal(jsonData, &storage); err != nil {
		return "", "", "", false, fmt.Errorf("failed to unmarshal blob storage: %w", err)
	}

	// Server config exists if address and CA are set
	if storage.ServerAddress == "" || storage.ServerCAPEM == "" {
		return "", "", "", false, nil
	}

	return storage.ServerAddress, storage.ServerCAPEM, storage.ServerSPKI, true, nil
}

// SaveServerConfig saves server address, CA PEM, and SPKI pin to da.json (preserves other data)
func SaveServerConfig(address, caPEM, spkiPin string) error {
	blobPath := getBlobPath()
	log.Printf("Saving server config to: %s", blobPath)

	if err := os.MkdirAll(filepath.Dir(blobPath), 0755); err != nil {
		return fmt.Errorf("failed to create blob directory: %w", err)
	}

	// Load existing storage to preserve other data
	storage := TPMBlobStorage{
		Version:     blobStorageVersion,
		Description: "Device attestation state",
	}
	if jsonData, err := os.ReadFile(blobPath); err == nil {
		json.Unmarshal(jsonData, &storage)
	}

	// Update server config
	storage.ServerAddress = address
	storage.ServerCAPEM = caPEM
	storage.ServerSPKI = spkiPin
	storage.Version = blobStorageVersion

	jsonData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blob storage: %w", err)
	}

	if err := os.WriteFile(blobPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write blob file: %w", err)
	}

	log.Printf("Server config saved")
	return nil
}

// ServerConfigExists returns true if server config is stored
func ServerConfigExists() bool {
	_, _, _, exists, _ := LoadServerConfig()
	return exists
}

// ClearLAKBlobs clears only the LAK certificate data from da.json (preserves AK, agent, and server config)
func ClearLAKBlobs() error {
	blobPath := getBlobPath()

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return nil
	}

	jsonData, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("failed to read blob file: %w", err)
	}

	var storage TPMBlobStorage
	if err := json.Unmarshal(jsonData, &storage); err != nil {
		return fmt.Errorf("failed to unmarshal blob storage: %w", err)
	}

	// Clear LAK and AK data (AK needs to be recreated with LAK)
	storage.AKPrivate = ""
	storage.AKPublic = ""
	storage.LAKCertPEM = ""
	storage.LAKCACertPEM = ""

	newData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blob storage: %w", err)
	}

	if err := os.WriteFile(blobPath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write blob file: %w", err)
	}

	log.Printf("LAK blobs cleared")
	return nil
}

// IsLAKValid checks if the LAK certificate exists and is not expired
func IsLAKValid() bool {
	_, _, lakCertPEM, _, exists, err := LoadBlobs()
	if err != nil || !exists || lakCertPEM == "" {
		return false
	}

	cert, err := parsePEMCertificate(lakCertPEM)
	if err != nil {
		log.Printf("Failed to parse LAK certificate: %v", err)
		return false
	}

	// Check expiry with some buffer (1 hour)
	if time.Now().Add(time.Hour).After(cert.NotAfter) {
		log.Printf("LAK certificate expired or expiring soon: %v", cert.NotAfter)
		return false
	}

	return true
}

// IsAgentValid checks if the agent certificate exists and is not expired
func IsAgentValid() bool {
	agentCertPEM, _, _, _, exists, err := LoadAgentBlobs()
	if err != nil || !exists || agentCertPEM == "" {
		return false
	}

	cert, err := parsePEMCertificate(agentCertPEM)
	if err != nil {
		log.Printf("Failed to parse agent certificate: %v", err)
		return false
	}

	// Check expiry with some buffer (1 hour)
	if time.Now().Add(time.Hour).After(cert.NotAfter) {
		log.Printf("Agent certificate expired or expiring soon: %v", cert.NotAfter)
		return false
	}

	return true
}

// parsePEMCertificate parses a PEM-encoded certificate
func parsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LAKBlobsExist returns true if LAK certificate is stored
func LAKBlobsExist() bool {
	_, _, lakCertPEM, _, exists, _ := LoadBlobs()
	return exists && lakCertPEM != ""
}
