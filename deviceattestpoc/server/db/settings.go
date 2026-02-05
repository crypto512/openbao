package db

import (
	"database/sql"
	"fmt"
	"time"
)

// GetSetting retrieves a setting value by key
func (db *DB) GetSetting(key string) (string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var value string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get setting: %w", err)
	}

	return value, nil
}

// SetSetting updates or creates a setting
func (db *DB) SetSetting(key, value string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, now)

	return err
}

// GetAutoApprove returns whether auto-approve is enabled
func (db *DB) GetAutoApprove() (bool, error) {
	value, err := db.GetSetting("auto_approve")
	if err != nil {
		return false, err
	}
	return value == "true", nil
}

// SetAutoApprove sets the auto-approve setting
func (db *DB) SetAutoApprove(enabled bool) error {
	value := "false"
	if enabled {
		value = "true"
	}
	return db.SetSetting("auto_approve", value)
}

// GetServerSPKI returns the stored server SPKI pin
func (db *DB) GetServerSPKI() (string, error) {
	return db.GetSetting("server_spki")
}

// SetServerSPKI stores the server SPKI pin
func (db *DB) SetServerSPKI(spki string) error {
	return db.SetSetting("server_spki", spki)
}

// ServerCertificate represents a cached server certificate
type ServerCertificate struct {
	Name      string
	CertPEM   string
	KeyPEM    string
	NotBefore string
	NotAfter  string
	CreatedAt string
}

// GetServerCertificate retrieves a cached server certificate by name
func (db *DB) GetServerCertificate(name string) (*ServerCertificate, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var cert ServerCertificate
	err := db.QueryRow(`
		SELECT name, cert_pem, key_pem, not_before, not_after, created_at
		FROM server_certificates
		WHERE name = ?
	`, name).Scan(&cert.Name, &cert.CertPEM, &cert.KeyPEM, &cert.NotBefore, &cert.NotAfter, &cert.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get server certificate: %w", err)
	}

	return &cert, nil
}

// SaveServerCertificate saves or updates a server certificate
func (db *DB) SaveServerCertificate(cert *ServerCertificate) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO server_certificates (name, cert_pem, key_pem, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			cert_pem = excluded.cert_pem,
			key_pem = excluded.key_pem,
			not_before = excluded.not_before,
			not_after = excluded.not_after,
			created_at = excluded.created_at
	`, cert.Name, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, now)

	return err
}

// DeleteExpiredServerCertificates removes expired server certificates
func (db *DB) DeleteExpiredServerCertificates() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("DELETE FROM server_certificates WHERE not_after < ?", now)
	return err
}
