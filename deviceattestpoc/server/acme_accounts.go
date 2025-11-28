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
	"sync"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
)

// ACMEAccountManager manages ACME accounts per PKI/role endpoint
// Accounts are persisted to the database to ensure stable thumbprints across restarts
type ACMEAccountManager struct {
	mu       sync.RWMutex
	accounts map[string]*ACMEAccount // in-memory cache, key: PKI path
	db       *db.DB
}

// ACMEAccount represents a persisted ACME account
type ACMEAccount struct {
	PrivateKey    *ecdsa.PrivateKey `json:"-"`
	PrivateKeyPEM string            `json:"private_key_pem"`
	AccountURL    string            `json:"account_url"`
	Thumbprint    string            `json:"thumbprint"`
	PKIPath       string            `json:"pki_path"`
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

// NewACMEAccountManager creates a new account manager with database persistence
func NewACMEAccountManager(database *db.DB) (*ACMEAccountManager, error) {
	mgr := &ACMEAccountManager{
		accounts: make(map[string]*ACMEAccount),
		db:       database,
	}

	// Load existing accounts from database
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

	// Check if account exists in memory cache
	if account, ok := m.accounts[pkiPath]; ok {
		return account, nil
	}

	// Try to load from database
	row, err := m.db.GetACMEAccount(pkiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to query database: %w", err)
	}

	if row != nil {
		account, err := m.rowToAccount(row)
		if err != nil {
			return nil, err
		}
		m.accounts[pkiPath] = account
		log.Printf("Loaded existing ACME account for %s (thumbprint: %s)", pkiPath, account.Thumbprint)
		return account, nil
	}

	// Create new account
	account, err := m.createAccount(pkiPath)
	if err != nil {
		return nil, err
	}

	m.accounts[pkiPath] = account
	log.Printf("Created new ACME account for %s (thumbprint: %s)", pkiPath, account.Thumbprint)

	// Persist to database
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

// saveAccount persists an account to the database
func (m *ACMEAccountManager) saveAccount(account *ACMEAccount) error {
	row := &db.ACMEAccountRow{
		PKIPath:       account.PKIPath,
		PrivateKeyPEM: account.PrivateKeyPEM,
		AccountURL:    account.AccountURL,
		Thumbprint:    account.Thumbprint,
	}
	return m.db.SaveACMEAccount(row)
}

// rowToAccount converts a database row to an ACMEAccount
func (m *ACMEAccountManager) rowToAccount(row *db.ACMEAccountRow) (*ACMEAccount, error) {
	// Parse private key from PEM
	block, _ := pem.Decode([]byte(row.PrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &ACMEAccount{
		PrivateKey:    privateKey,
		PrivateKeyPEM: row.PrivateKeyPEM,
		AccountURL:    row.AccountURL,
		Thumbprint:    row.Thumbprint,
		PKIPath:       row.PKIPath,
	}, nil
}

// loadAccounts loads all accounts from the database into memory
func (m *ACMEAccountManager) loadAccounts() error {
	rows, err := m.db.ListACMEAccounts()
	if err != nil {
		return err
	}

	for _, row := range rows {
		account, err := m.rowToAccount(row)
		if err != nil {
			log.Printf("Warning: failed to parse account for %s: %v", row.PKIPath, err)
			continue
		}
		m.accounts[account.PKIPath] = account
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
	return m.db.ClearACMEAccountURL(pkiPath)
}
