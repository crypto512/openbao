-- Device Attestation Server Database Schema
-- SQLite 3.x

-- Devices table: replaces in-memory allowedEKHashes map
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ek_hash TEXT UNIQUE NOT NULL,
    fingerprint TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending_approval',
    -- Status values: pending_approval, enrolled, lak_issued, agent_cert_issued
    lak_not_before TEXT,
    lak_not_after TEXT,
    agent_cert_not_before TEXT,
    agent_cert_not_after TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    enrolled_at TEXT,
    last_seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(fingerprint);
CREATE INDEX IF NOT EXISTS idx_devices_ek_hash ON devices(ek_hash);

-- ACME orders table: replaces in-memory orders map
CREATE TABLE IF NOT EXISTS acme_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE NOT NULL,
    common_name TEXT NOT NULL,
    order_json TEXT NOT NULL,
    csr_pem TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_order_id ON acme_orders(order_id);
CREATE INDEX IF NOT EXISTS idx_orders_expires ON acme_orders(expires_at);

-- Activation sessions table: replaces in-memory activationSessions map
CREATE TABLE IF NOT EXISTS activation_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    permanent_id TEXT NOT NULL,
    ak_parameters BLOB NOT NULL,
    ek_cert_pem TEXT NOT NULL,
    expected_secret BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON activation_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON activation_sessions(expires_at);

-- Usage certificates issued to devices
CREATE TABLE IF NOT EXISTS usage_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    usage TEXT NOT NULL,
    serial_number TEXT,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    issued_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_usage_certs_device ON usage_certificates(device_id);
CREATE INDEX IF NOT EXISTS idx_usage_certs_usage ON usage_certificates(usage);
CREATE INDEX IF NOT EXISTS idx_usage_certs_expires ON usage_certificates(not_after);

-- Audit log for all certificate operations
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    ek_hash TEXT,
    details TEXT,
    client_ip TEXT,
    success INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_log(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type);

-- Server settings (key-value store)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Server certificates table for persistence across restarts
CREATE TABLE IF NOT EXISTS server_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_server_certs_name ON server_certificates(name);
CREATE INDEX IF NOT EXISTS idx_server_certs_expires ON server_certificates(not_after);

-- Initialize default settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_approve', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('server_spki', '');
