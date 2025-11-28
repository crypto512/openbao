package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// ACMEAccountManager manages ACME accounts per PKI/role endpoint
// Accounts are persisted to disk to ensure stable thumbprints across restarts
type ACMEAccountManager struct {
	mu           sync.RWMutex
	accounts     map[string]*ACMEAccount // key: PKI path (e.g., "pki-agent/roles/agent")
	storagePath  string
}

// ACMEAccount represents a persisted ACME account
type ACMEAccount struct {
	PrivateKey  *ecdsa.PrivateKey `json:"-"`
	PrivateKeyPEM string          `json:"private_key_pem"`
	AccountURL  string            `json:"account_url"`
	Thumbprint  string            `json:"thumbprint"`
	PKIPath     string            `json:"pki_path"`
}

// UsageConfig maps a usage name to PKI configuration
type UsageConfig struct {
	PKIPath string // e.g., "pki-usage"
	Role    string // e.g., "vpn"
}

// Predefined usage mappings - all usages use pki-usage mount with usage-specific roles
var usageMappings = map[string]UsageConfig{
	"vpn":   {PKIPath: "pki-usage", Role: "vpn"},
	"wifi":  {PKIPath: "pki-usage", Role: "wifi"},
	"tls":   {PKIPath: "pki-usage", Role: "tls"},
	"agent": {PKIPath: "pki-agent", Role: "agent"},
}

// NewACMEAccountManager creates a new account manager with persistence
func NewACMEAccountManager(storagePath string) (*ACMEAccountManager, error) {
	if storagePath == "" {
		storagePath = "/data/acme-accounts"
	}

	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create account storage directory: %w", err)
	}

	mgr := &ACMEAccountManager{
		accounts:    make(map[string]*ACMEAccount),
		storagePath: storagePath,
	}

	// Load existing accounts from disk
	if err := mgr.loadAccounts(); err != nil {
		log.Printf("Warning: failed to load existing accounts: %v", err)
	}

	return mgr, nil
}

// GetUsageConfig returns the PKI configuration for a given usage
func GetUsageConfig(usage string) (*UsageConfig, error) {
	config, ok := usageMappings[usage]
	if !ok {
		return nil, fmt.Errorf("unknown usage: %s (supported: vpn, wifi, tls, agent)", usage)
	}
	return &config, nil
}

// GetACMEPath returns the full ACME directory path for a usage
func (cfg *UsageConfig) GetACMEPath() string {
	return fmt.Sprintf("%s/roles/%s", cfg.PKIPath, cfg.Role)
}

// GetOrCreateAccount gets an existing account or creates a new one for the PKI path
func (m *ACMEAccountManager) GetOrCreateAccount(pkiPath string) (*ACMEAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if account exists in memory
	if account, ok := m.accounts[pkiPath]; ok {
		return account, nil
	}

	// Try to load from disk
	account, err := m.loadAccount(pkiPath)
	if err == nil && account != nil {
		m.accounts[pkiPath] = account
		log.Printf("Loaded existing ACME account for %s (thumbprint: %s)", pkiPath, account.Thumbprint)
		return account, nil
	}

	// Create new account
	account, err = m.createAccount(pkiPath)
	if err != nil {
		return nil, err
	}

	m.accounts[pkiPath] = account
	log.Printf("Created new ACME account for %s (thumbprint: %s)", pkiPath, account.Thumbprint)

	// Persist to disk
	if err := m.saveAccount(account); err != nil {
		log.Printf("Warning: failed to persist account: %v", err)
	}

	return account, nil
}

// createAccount generates a new ECDSA key and computes the thumbprint
func (m *ACMEAccountManager) createAccount(pkiPath string) (*ACMEAccount, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	thumbprint, err := computeThumbprint(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &ACMEAccount{
		PrivateKey:    privateKey,
		PrivateKeyPEM: string(keyPEM),
		Thumbprint:    thumbprint,
		PKIPath:       pkiPath,
	}, nil
}

// computeThumbprint computes the JWK thumbprint for an ECDSA public key
func computeThumbprint(key *ecdsa.PrivateKey) (string, error) {
	pubKey := key.Public().(*ecdsa.PublicKey)

	// JWK thumbprint requires lexicographically sorted JSON with specific fields
	// For EC keys: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
	jwk := map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}

	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(jwkBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// SetAccountURL updates the account URL after registration
func (m *ACMEAccountManager) SetAccountURL(pkiPath, accountURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.accounts[pkiPath]
	if !ok {
		return fmt.Errorf("account not found for %s", pkiPath)
	}

	account.AccountURL = accountURL
	return m.saveAccount(account)
}

// accountFilePath returns the file path for an account
func (m *ACMEAccountManager) accountFilePath(pkiPath string) string {
	// Replace slashes with underscores for filename
	safeName := ""
	for _, c := range pkiPath {
		if c == '/' {
			safeName += "_"
		} else {
			safeName += string(c)
		}
	}
	return filepath.Join(m.storagePath, safeName+".json")
}

// saveAccount persists an account to disk
func (m *ACMEAccountManager) saveAccount(account *ACMEAccount) error {
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}

	filePath := m.accountFilePath(account.PKIPath)
	return os.WriteFile(filePath, data, 0600)
}

// loadAccount loads an account from disk
func (m *ACMEAccountManager) loadAccount(pkiPath string) (*ACMEAccount, error) {
	filePath := m.accountFilePath(pkiPath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var account ACMEAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}

	// Parse private key from PEM
	block, _ := pem.Decode([]byte(account.PrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	account.PrivateKey = privateKey
	return &account, nil
}

// loadAccounts loads all accounts from disk
func (m *ACMEAccountManager) loadAccounts() error {
	entries, err := os.ReadDir(m.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(m.storagePath, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Warning: failed to read account file %s: %v", filePath, err)
			continue
		}

		var account ACMEAccount
		if err := json.Unmarshal(data, &account); err != nil {
			log.Printf("Warning: failed to parse account file %s: %v", filePath, err)
			continue
		}

		// Parse private key
		block, _ := pem.Decode([]byte(account.PrivateKeyPEM))
		if block == nil {
			log.Printf("Warning: failed to decode private key in %s", filePath)
			continue
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Printf("Warning: failed to parse private key in %s: %v", filePath, err)
			continue
		}

		account.PrivateKey = privateKey
		m.accounts[account.PKIPath] = &account
		log.Printf("Loaded ACME account: %s (thumbprint: %s)", account.PKIPath, account.Thumbprint)
	}

	return nil
}

// ClearAccounts removes all cached accounts (for use when OpenBao restarts)
func (m *ACMEAccountManager) ClearAccounts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts = make(map[string]*ACMEAccount)
	log.Printf("ACME account cache cleared")
}

// ClearAccountURL clears the account URL for a PKI path (for re-registration)
func (m *ACMEAccountManager) ClearAccountURL(pkiPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.accounts[pkiPath]
	if !ok {
		return nil
	}

	account.AccountURL = ""
	log.Printf("Cleared account URL for %s (will re-register)", pkiPath)
	return m.saveAccount(account)
}
