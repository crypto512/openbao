package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ActivationSession stores MakeCredential challenge state
type ActivationSession struct {
	ID             int64
	SessionID      string
	PermanentID    string
	AKParameters   []byte
	EKCertPEM      string
	ExpectedSecret []byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

const sessionTTL = 5 * time.Minute

// CreateActivationSession creates a new activation session
func (db *DB) CreateActivationSession(sessionID, permanentID string, akParams []byte, ekCertPEM string, expectedSecret []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC()
	expiresAt := now.Add(sessionTTL)

	_, err := db.Exec(`
		INSERT INTO activation_sessions (session_id, permanent_id, ak_parameters, ek_cert_pem, expected_secret, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, sessionID, permanentID, akParams, ekCertPEM, expectedSecret, now.Format(time.RFC3339), expiresAt.Format(time.RFC3339))

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetActivationSession retrieves an activation session by ID
func (db *DB) GetActivationSession(sessionID string) (*ActivationSession, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	row := db.QueryRow(`
		SELECT id, session_id, permanent_id, ak_parameters, ek_cert_pem, expected_secret, created_at, expires_at
		FROM activation_sessions WHERE session_id = ?
	`, sessionID)

	session := &ActivationSession{}
	var createdAt, expiresAt string

	err := row.Scan(
		&session.ID, &session.SessionID, &session.PermanentID,
		&session.AKParameters, &session.EKCertPEM, &session.ExpectedSecret,
		&createdAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	session.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	session.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)

	return session, nil
}

// IsSessionExpired checks if the session has expired
func (s *ActivationSession) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// DeleteActivationSession removes an activation session by ID
func (db *DB) DeleteActivationSession(sessionID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.Exec("DELETE FROM activation_sessions WHERE session_id = ?", sessionID)
	return err
}
