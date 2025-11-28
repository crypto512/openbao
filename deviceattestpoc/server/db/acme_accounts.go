package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ACMEAccountRow represents an ACME account stored in the database
type ACMEAccountRow struct {
	ID            int64
	PKIPath       string
	PrivateKeyPEM string
	AccountURL    string
	Thumbprint    string
	CreatedAt     string
	UpdatedAt     string
}

// GetACMEAccount retrieves an ACME account by PKI path
func (db *DB) GetACMEAccount(pkiPath string) (*ACMEAccountRow, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var account ACMEAccountRow
	err := db.QueryRow(`
		SELECT id, pki_path, private_key_pem, account_url, thumbprint, created_at, updated_at
		FROM acme_accounts
		WHERE pki_path = ?
	`, pkiPath).Scan(
		&account.ID,
		&account.PKIPath,
		&account.PrivateKeyPEM,
		&account.AccountURL,
		&account.Thumbprint,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME account: %w", err)
	}

	return &account, nil
}

// SaveACMEAccount saves or updates an ACME account
func (db *DB) SaveACMEAccount(account *ACMEAccountRow) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO acme_accounts (pki_path, private_key_pem, account_url, thumbprint, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(pki_path) DO UPDATE SET
			private_key_pem = excluded.private_key_pem,
			account_url = excluded.account_url,
			thumbprint = excluded.thumbprint,
			updated_at = excluded.updated_at
	`, account.PKIPath, account.PrivateKeyPEM, account.AccountURL, account.Thumbprint, now, now)

	return err
}

// UpdateACMEAccountURL updates the account URL for a PKI path
func (db *DB) UpdateACMEAccountURL(pkiPath, accountURL string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := db.Exec(`
		UPDATE acme_accounts
		SET account_url = ?, updated_at = ?
		WHERE pki_path = ?
	`, accountURL, now, pkiPath)
	if err != nil {
		return fmt.Errorf("failed to update ACME account URL: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("ACME account not found for %s", pkiPath)
	}

	return nil
}

// ClearACMEAccountURL clears the account URL for a PKI path (for re-registration)
func (db *DB) ClearACMEAccountURL(pkiPath string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		UPDATE acme_accounts
		SET account_url = '', updated_at = ?
		WHERE pki_path = ?
	`, now, pkiPath)

	return err
}

// ListACMEAccounts returns all ACME accounts
func (db *DB) ListACMEAccounts() ([]*ACMEAccountRow, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT id, pki_path, private_key_pem, account_url, thumbprint, created_at, updated_at
		FROM acme_accounts
		ORDER BY pki_path
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list ACME accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*ACMEAccountRow
	for rows.Next() {
		var account ACMEAccountRow
		if err := rows.Scan(
			&account.ID,
			&account.PKIPath,
			&account.PrivateKeyPEM,
			&account.AccountURL,
			&account.Thumbprint,
			&account.CreatedAt,
			&account.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ACME account: %w", err)
		}
		accounts = append(accounts, &account)
	}

	return accounts, rows.Err()
}
