package db

import (
	"fmt"
	"time"
)

// UsageCertificate represents a usage certificate issued to a device
type UsageCertificate struct {
	ID               int64
	DeviceID         int64
	Usage            string
	SerialNumber     string
	NotBefore        time.Time
	NotAfter         time.Time
	IssuedAt         time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

// CreateUsageCertificate records a new usage certificate
func (db *DB) CreateUsageCertificate(deviceID int64, usage, serialNumber string, notBefore, notAfter time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)

	_, err := db.Exec(`
		INSERT INTO usage_certificates (device_id, usage, serial_number, not_before, not_after, issued_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, deviceID, usage, serialNumber, notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), now)

	if err != nil {
		return fmt.Errorf("failed to create usage certificate: %w", err)
	}

	return nil
}

// GetUsageCertificatesForDevice retrieves all usage certificates for a device
func (db *DB) GetUsageCertificatesForDevice(deviceID int64) ([]*UsageCertificate, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT id, device_id, usage, COALESCE(serial_number, ''), not_before, not_after, issued_at, revoked_at, COALESCE(revocation_reason, '')
		FROM usage_certificates
		WHERE device_id = ?
		ORDER BY issued_at DESC
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage certificates: %w", err)
	}
	defer rows.Close()

	var certs []*UsageCertificate
	for rows.Next() {
		cert := &UsageCertificate{}
		var notBefore, notAfter, issuedAt string
		var revokedAt *string

		err := rows.Scan(
			&cert.ID, &cert.DeviceID, &cert.Usage, &cert.SerialNumber,
			&notBefore, &notAfter, &issuedAt, &revokedAt, &cert.RevocationReason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan usage certificate: %w", err)
		}

		cert.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		cert.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		cert.IssuedAt, _ = time.Parse(time.RFC3339, issuedAt)
		if revokedAt != nil {
			t, _ := time.Parse(time.RFC3339, *revokedAt)
			cert.RevokedAt = &t
		}

		certs = append(certs, cert)
	}

	return certs, rows.Err()
}

// GetUsageCertificateCounts returns counts of usage certificates by type
func (db *DB) GetUsageCertificateCounts() (map[string]int, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT usage, COUNT(*) FROM usage_certificates
		WHERE revoked_at IS NULL
		GROUP BY usage
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage cert counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var usage string
		var count int
		if err := rows.Scan(&usage, &count); err != nil {
			return nil, err
		}
		counts[usage] = count
	}

	return counts, rows.Err()
}
