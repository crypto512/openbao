package db

import (
	"database/sql"
	"fmt"
	"time"
)

// AuditEventType represents the type of audited event
type AuditEventType string

const (
	EventDeviceAdded      AuditEventType = "device_added"
	EventDeviceEnrolled   AuditEventType = "device_enrolled"
	EventDeviceApproved   AuditEventType = "device_approved"
	EventDeviceDeleted    AuditEventType = "device_deleted"
	EventLAKIssued        AuditEventType = "lak_issued"
	EventAgentCertIssued  AuditEventType = "agent_cert_issued"
	EventUsageCertIssued  AuditEventType = "usage_cert_issued"
	EventEnrollmentFailed AuditEventType = "enrollment_failed"
	EventLAKFailed        AuditEventType = "lak_failed"
	EventCertRevoked      AuditEventType = "cert_revoked"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	EventType AuditEventType
	DeviceID  *int64
	EKHash    string
	Details   string
	ClientIP  string
	Success   bool
}

// CreateAuditEntry creates a new audit log entry
func (db *DB) CreateAuditEntry(eventType AuditEventType, deviceID *int64, ekHash, details, clientIP string, success bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	successInt := 0
	if success {
		successInt = 1
	}

	_, err := db.Exec(`
		INSERT INTO audit_log (timestamp, event_type, device_id, ek_hash, details, client_ip, success)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, now, string(eventType), deviceID, ekHash, details, clientIP, successInt)

	if err != nil {
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	return nil
}

// GetRecentAuditEntries retrieves the most recent audit entries
func (db *DB) GetRecentAuditEntries(limit int) ([]*AuditEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT id, timestamp, event_type, device_id, ek_hash, details, client_ip, success
		FROM audit_log
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit entries: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		entry := &AuditEntry{}
		var timestamp string
		var eventType string
		var deviceID sql.NullInt64
		var ekHash, details, clientIP sql.NullString
		var success int

		err := rows.Scan(&entry.ID, &timestamp, &eventType, &deviceID, &ekHash, &details, &clientIP, &success)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		entry.Timestamp, _ = time.Parse(time.RFC3339, timestamp)
		entry.EventType = AuditEventType(eventType)
		if deviceID.Valid {
			entry.DeviceID = &deviceID.Int64
		}
		entry.EKHash = ekHash.String
		entry.Details = details.String
		entry.ClientIP = clientIP.String
		entry.Success = success == 1

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetAuditEntriesForDevice retrieves audit entries for a specific device
func (db *DB) GetAuditEntriesForDevice(deviceID int64, limit int) ([]*AuditEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.Query(`
		SELECT id, timestamp, event_type, device_id, ek_hash, details, client_ip, success
		FROM audit_log
		WHERE device_id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit entries: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		entry := &AuditEntry{}
		var timestamp string
		var eventType string
		var deviceIDVal sql.NullInt64
		var ekHash, details, clientIP sql.NullString
		var success int

		err := rows.Scan(&entry.ID, &timestamp, &eventType, &deviceIDVal, &ekHash, &details, &clientIP, &success)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		entry.Timestamp, _ = time.Parse(time.RFC3339, timestamp)
		entry.EventType = AuditEventType(eventType)
		if deviceIDVal.Valid {
			entry.DeviceID = &deviceIDVal.Int64
		}
		entry.EKHash = ekHash.String
		entry.Details = details.String
		entry.ClientIP = clientIP.String
		entry.Success = success == 1

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}
