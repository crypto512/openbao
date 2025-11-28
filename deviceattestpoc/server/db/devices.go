package db

import (
	"database/sql"
	"fmt"
	"time"
)

// DeviceStatus represents the state of a device in the enrollment lifecycle
type DeviceStatus string

const (
	StatusRegistered  DeviceStatus = "registered"  // Admin pre-registered fingerprint
	StatusProvisioned DeviceStatus = "provisioned" // Device connected via da-init
	StatusEnrolled    DeviceStatus = "enrolled"    // LAK issued
	StatusTrusted     DeviceStatus = "trusted"     // Agent cert issued
)

// Device represents an enrolled device
type Device struct {
	ID                  int64
	EKHash              string
	Fingerprint         string
	Description         string
	Status              DeviceStatus
	LAKNotBefore        *time.Time
	LAKNotAfter         *time.Time
	AgentCertNotBefore  *time.Time
	AgentCertNotAfter   *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	EnrolledAt          *time.Time
	LastSeenAt          *time.Time
}

// DeviceCounts holds summary statistics
type DeviceCounts struct {
	Total            int
	Registered       int // Admin pre-registered
	Provisioned      int // Device connected
	Enrolled         int // LAK issued
	Trusted          int // Agent cert issued
	ExpiringSoon     int // Certs expiring within 7 days
	Expired          int
	EnrollmentsToday int
	CertsIssuedToday int
	FailedToday      int
}

// CreateDevice creates a new device record
func (db *DB) CreateDevice(ekHash, fingerprint, description string, status DeviceStatus) (*Device, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	var enrolledAt *string
	if status == StatusProvisioned {
		enrolledAt = &now
	}

	result, err := db.Exec(`
		INSERT INTO devices (ek_hash, fingerprint, description, status, enrolled_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, ekHash, fingerprint, description, string(status), enrolledAt, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	return db.getDeviceByID(id)
}

// GetDeviceByEKHash retrieves a device by its EK hash
func (db *DB) GetDeviceByEKHash(ekHash string) (*Device, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.getDeviceByEKHashUnlocked(ekHash)
}

func (db *DB) getDeviceByEKHashUnlocked(ekHash string) (*Device, error) {
	row := db.QueryRow(`
		SELECT id, ek_hash, fingerprint, description, status,
			   lak_not_before, lak_not_after, agent_cert_not_before, agent_cert_not_after,
			   created_at, updated_at, enrolled_at, last_seen_at
		FROM devices WHERE ek_hash = ?
	`, ekHash)

	return scanDevice(row)
}

// GetDeviceByID retrieves a device by its ID
func (db *DB) GetDeviceByID(id int64) (*Device, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.getDeviceByID(id)
}

func (db *DB) getDeviceByID(id int64) (*Device, error) {
	row := db.QueryRow(`
		SELECT id, ek_hash, fingerprint, description, status,
			   lak_not_before, lak_not_after, agent_cert_not_before, agent_cert_not_after,
			   created_at, updated_at, enrolled_at, last_seen_at
		FROM devices WHERE id = ?
	`, id)

	return scanDevice(row)
}

// GetDeviceByFingerprint retrieves a device by its fingerprint prefix
func (db *DB) GetDeviceByFingerprint(fingerprint string) (*Device, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	row := db.QueryRow(`
		SELECT id, ek_hash, fingerprint, description, status,
			   lak_not_before, lak_not_after, agent_cert_not_before, agent_cert_not_after,
			   created_at, updated_at, enrolled_at, last_seen_at
		FROM devices WHERE fingerprint = ? OR ek_hash LIKE ?
	`, fingerprint, fingerprint+"%")

	return scanDevice(row)
}

// IsDeviceAllowed checks if a device with the given EK hash is provisioned or beyond
// Registered devices (pending approval) are NOT allowed to proceed with LAK provisioning
func (db *DB) IsDeviceAllowed(ekHash string) (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var status string
	err := db.QueryRow("SELECT status FROM devices WHERE ek_hash = ?", ekHash).Scan(&status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check device: %w", err)
	}

	// Device is allowed only if provisioned or beyond (not registered/pending approval)
	return status == string(StatusProvisioned) || status == string(StatusEnrolled) || status == string(StatusTrusted), nil
}

// ListDevices returns all devices ordered by creation date
func (db *DB) ListDevices() ([]*Device, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT id, ek_hash, fingerprint, description, status,
			   lak_not_before, lak_not_after, agent_cert_not_before, agent_cert_not_after,
			   created_at, updated_at, enrolled_at, last_seen_at
		FROM devices
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		device, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// UpdateDeviceStatus updates a device's status
func (db *DB) UpdateDeviceStatus(id int64, status DeviceStatus) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	var enrolledAt *string
	if status == StatusProvisioned {
		enrolledAt = &now
	}

	_, err := db.Exec(`
		UPDATE devices SET status = ?, updated_at = ?, enrolled_at = COALESCE(enrolled_at, ?)
		WHERE id = ?
	`, string(status), now, enrolledAt, id)

	return err
}

// UpdateDeviceStatusByEKHash updates a device's status by EK hash
func (db *DB) UpdateDeviceStatusByEKHash(ekHash string, status DeviceStatus) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	var enrolledAt *string
	if status == StatusProvisioned {
		enrolledAt = &now
	}

	_, err := db.Exec(`
		UPDATE devices SET status = ?, updated_at = ?, enrolled_at = COALESCE(enrolled_at, ?)
		WHERE ek_hash = ?
	`, string(status), now, enrolledAt, ekHash)

	return err
}

// UpdateLAKCertValidity updates a device's LAK certificate validity dates
func (db *DB) UpdateLAKCertValidity(ekHash string, notBefore, notAfter time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		UPDATE devices SET
			lak_not_before = ?, lak_not_after = ?,
			status = ?, updated_at = ?
		WHERE ek_hash = ?
	`, notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), string(StatusEnrolled), now, ekHash)

	return err
}

// UpdateAgentCertValidity updates a device's agent certificate validity dates
func (db *DB) UpdateAgentCertValidity(ekHash string, notBefore, notAfter time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		UPDATE devices SET
			agent_cert_not_before = ?, agent_cert_not_after = ?,
			status = ?, updated_at = ?
		WHERE ek_hash = ?
	`, notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), string(StatusTrusted), now, ekHash)

	return err
}

// UpdateLastSeen updates a device's last seen timestamp
func (db *DB) UpdateLastSeen(ekHash string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("UPDATE devices SET last_seen_at = ? WHERE ek_hash = ?", now, ekHash)
	return err
}

// DeleteDevice removes a device by ID
func (db *DB) DeleteDevice(id int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.Exec("DELETE FROM devices WHERE id = ?", id)
	return err
}

// GetDeviceCounts returns summary statistics for the dashboard
func (db *DB) GetDeviceCounts() (*DeviceCounts, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	counts := &DeviceCounts{}
	now := time.Now().UTC()
	sevenDaysFromNow := now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	// Total count
	db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&counts.Total)

	// Status counts
	db.QueryRow("SELECT COUNT(*) FROM devices WHERE status = ?", string(StatusRegistered)).Scan(&counts.Registered)
	db.QueryRow("SELECT COUNT(*) FROM devices WHERE status = ?", string(StatusProvisioned)).Scan(&counts.Provisioned)
	db.QueryRow("SELECT COUNT(*) FROM devices WHERE status = ?", string(StatusEnrolled)).Scan(&counts.Enrolled)
	db.QueryRow("SELECT COUNT(*) FROM devices WHERE status = ?", string(StatusTrusted)).Scan(&counts.Trusted)

	// Expiring soon (any cert expiring within 7 days)
	db.QueryRow(`
		SELECT COUNT(*) FROM devices
		WHERE (lak_not_after IS NOT NULL AND lak_not_after <= ? AND lak_not_after > ?)
		   OR (agent_cert_not_after IS NOT NULL AND agent_cert_not_after <= ? AND agent_cert_not_after > ?)
	`, sevenDaysFromNow, nowStr, sevenDaysFromNow, nowStr).Scan(&counts.ExpiringSoon)

	// Expired (any cert expired)
	db.QueryRow(`
		SELECT COUNT(*) FROM devices
		WHERE (lak_not_after IS NOT NULL AND lak_not_after <= ?)
		   OR (agent_cert_not_after IS NOT NULL AND agent_cert_not_after <= ?)
	`, nowStr, nowStr).Scan(&counts.Expired)

	// Today's activity from audit log
	db.QueryRow(`
		SELECT COUNT(*) FROM audit_log
		WHERE timestamp >= ? AND event_type = 'device_enrolled' AND success = 1
	`, todayStart).Scan(&counts.EnrollmentsToday)

	db.QueryRow(`
		SELECT COUNT(*) FROM audit_log
		WHERE timestamp >= ? AND event_type IN ('lak_issued', 'agent_cert_issued', 'usage_cert_issued') AND success = 1
	`, todayStart).Scan(&counts.CertsIssuedToday)

	db.QueryRow(`
		SELECT COUNT(*) FROM audit_log
		WHERE timestamp >= ? AND success = 0
	`, todayStart).Scan(&counts.FailedToday)

	return counts, nil
}

// Helper functions to scan device rows

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanDevice(row *sql.Row) (*Device, error) {
	device := &Device{}
	var lakNotBefore, lakNotAfter, agentNotBefore, agentNotAfter sql.NullString
	var createdAt, updatedAt string
	var enrolledAt, lastSeenAt sql.NullString
	var status string

	err := row.Scan(
		&device.ID, &device.EKHash, &device.Fingerprint, &device.Description, &status,
		&lakNotBefore, &lakNotAfter, &agentNotBefore, &agentNotAfter,
		&createdAt, &updatedAt, &enrolledAt, &lastSeenAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan device: %w", err)
	}

	device.Status = DeviceStatus(status)
	device.LAKNotBefore = parseNullTime(lakNotBefore)
	device.LAKNotAfter = parseNullTime(lakNotAfter)
	device.AgentCertNotBefore = parseNullTime(agentNotBefore)
	device.AgentCertNotAfter = parseNullTime(agentNotAfter)
	device.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	device.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	device.EnrolledAt = parseNullTime(enrolledAt)
	device.LastSeenAt = parseNullTime(lastSeenAt)

	return device, nil
}

func scanDeviceRow(rows *sql.Rows) (*Device, error) {
	device := &Device{}
	var lakNotBefore, lakNotAfter, agentNotBefore, agentNotAfter sql.NullString
	var createdAt, updatedAt string
	var enrolledAt, lastSeenAt sql.NullString
	var status string

	err := rows.Scan(
		&device.ID, &device.EKHash, &device.Fingerprint, &device.Description, &status,
		&lakNotBefore, &lakNotAfter, &agentNotBefore, &agentNotAfter,
		&createdAt, &updatedAt, &enrolledAt, &lastSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan device: %w", err)
	}

	device.Status = DeviceStatus(status)
	device.LAKNotBefore = parseNullTime(lakNotBefore)
	device.LAKNotAfter = parseNullTime(lakNotAfter)
	device.AgentCertNotBefore = parseNullTime(agentNotBefore)
	device.AgentCertNotAfter = parseNullTime(agentNotAfter)
	device.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	device.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	device.EnrolledAt = parseNullTime(enrolledAt)
	device.LastSeenAt = parseNullTime(lastSeenAt)

	return device, nil
}

func parseNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ns.String)
	if err != nil {
		return nil
	}
	return &t
}
