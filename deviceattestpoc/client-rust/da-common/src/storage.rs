//! Storage persistence for device attestation state (da.json).
//!
//! This module provides functions to load and save TPM blobs, certificates,
//! and server configuration to `/etc/da/da.json`.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::{info, warn};
use x509_cert::Certificate;

use crate::config::get_da_config_path;

/// Current blob storage version
pub const BLOB_STORAGE_VERSION: &str = "3.0";

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("failed to read blob file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse blob storage: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("failed to decode base64: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("blob version mismatch: got {got}, want {want}")]
    VersionMismatch { got: String, want: String },

    #[error("failed to parse certificate: {0}")]
    CertParseError(String),
}

/// TPM blob storage structure - persisted to da.json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TpmBlobStorage {
    /// AK (Attestation Key) private blob - TPM2B_PRIVATE (base64)
    #[serde(default)]
    pub ak_private: String,

    /// AK (Attestation Key) public blob - TPM2B_PUBLIC (base64)
    #[serde(default)]
    pub ak_public: String,

    /// AK creation data - TPMS_CREATION_DATA (base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ak_creation_data: Option<String>,

    /// AK creation attestation - TPMS_ATTEST (base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ak_create_attestation: Option<String>,

    /// AK creation signature - TPMT_SIGNATURE (base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ak_create_signature: Option<String>,

    /// LAK Certificate - X.509 cert for AK issued by Privacy CA (PEM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lak_cert_pem: Option<String>,

    /// LAK CA Chain - CA certificate that signed the LAK certificate (PEM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lak_ca_cert_pem: Option<String>,

    /// Agent certificate - hardware-bound via ACME device-attest-01 (PEM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_cert_pem: Option<String>,

    /// Agent key private blob - TPM blob (base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_private: Option<String>,

    /// Agent key public blob - TPM blob (base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_public: Option<String>,

    /// Agent CA certificate (PEM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ca_cert_pem: Option<String>,

    /// Server gRPC address (e.g., "server:50051")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_address: Option<String>,

    /// Server CA certificate chain (PEM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_pem: Option<String>,

    /// Server SPKI pin for verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_spki: Option<String>,

    /// Storage version
    #[serde(default)]
    pub version: String,

    /// Description
    #[serde(default)]
    pub description: String,
}

impl TpmBlobStorage {
    /// Create a new empty storage with default version
    pub fn new() -> Self {
        Self {
            version: BLOB_STORAGE_VERSION.to_string(),
            description: "Device attestation state".to_string(),
            ..Default::default()
        }
    }

    /// Load storage from da.json, returns None if file doesn't exist
    pub fn load() -> Result<Option<Self>, StorageError> {
        let path = get_da_config_path();

        if !Path::new(&path).exists() {
            return Ok(None);
        }

        info!("Loading TPM blobs from: {}", path);
        let json_data = fs::read_to_string(&path)?;
        let storage: Self = serde_json::from_str(&json_data)?;

        // Accept version 2.0 and 3.0
        if storage.version != BLOB_STORAGE_VERSION && storage.version != "2.0" {
            warn!(
                "Blob version mismatch (got {}, want {}), will recreate",
                storage.version, BLOB_STORAGE_VERSION
            );
            return Ok(None);
        }

        info!("TPM blobs loaded");
        Ok(Some(storage))
    }

    /// Save storage to da.json
    pub fn save(&self) -> Result<(), StorageError> {
        let path = get_da_config_path();
        info!("Saving TPM blobs to: {}", path);

        // Create parent directory if needed
        if let Some(parent) = Path::new(&path).parent() {
            fs::create_dir_all(parent)?;
        }

        let json_data = serde_json::to_string_pretty(self)?;
        fs::write(&path, json_data)?;

        info!("TPM blobs saved");
        Ok(())
    }

    /// Get AK blobs as raw bytes
    pub fn get_ak_blobs(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, StorageError> {
        if self.ak_private.is_empty() || self.ak_public.is_empty() {
            return Ok(None);
        }

        let priv_blob = BASE64_STANDARD.decode(&self.ak_private)?;
        let pub_blob = BASE64_STANDARD.decode(&self.ak_public)?;
        Ok(Some((priv_blob, pub_blob)))
    }

    /// Set AK blobs from raw bytes
    pub fn set_ak_blobs(&mut self, priv_blob: &[u8], pub_blob: &[u8]) {
        self.ak_private = BASE64_STANDARD.encode(priv_blob);
        self.ak_public = BASE64_STANDARD.encode(pub_blob);
    }

    /// Get agent key blobs as raw bytes
    pub fn get_agent_key_blobs(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, StorageError> {
        let priv_str = self.agent_key_private.as_ref().filter(|s| !s.is_empty());
        let pub_str = self.agent_key_public.as_ref().filter(|s| !s.is_empty());

        match (priv_str, pub_str) {
            (Some(priv_b64), Some(pub_b64)) => {
                let priv_blob = BASE64_STANDARD.decode(priv_b64)?;
                let pub_blob = BASE64_STANDARD.decode(pub_b64)?;
                Ok(Some((priv_blob, pub_blob)))
            }
            _ => Ok(None),
        }
    }

    /// Set agent key blobs from raw bytes
    pub fn set_agent_key_blobs(&mut self, priv_blob: &[u8], pub_blob: &[u8]) {
        self.agent_key_private = Some(BASE64_STANDARD.encode(priv_blob));
        self.agent_key_public = Some(BASE64_STANDARD.encode(pub_blob));
    }

    /// Check if LAK certificate exists and is valid
    pub fn has_valid_lak(&self) -> bool {
        self.lak_cert_pem
            .as_ref()
            .map(|pem| is_cert_valid(pem))
            .unwrap_or(false)
    }

    /// Check if agent certificate exists and is valid
    pub fn has_valid_agent(&self) -> bool {
        self.agent_cert_pem
            .as_ref()
            .map(|pem| is_cert_valid(pem))
            .unwrap_or(false)
    }

    /// Check if server config is present
    pub fn has_server_config(&self) -> bool {
        self.server_address.is_some() && self.server_ca_pem.is_some()
    }

    /// Clear LAK and AK data (AK needs to be recreated with LAK)
    pub fn clear_lak(&mut self) {
        self.ak_private = String::new();
        self.ak_public = String::new();
        self.ak_creation_data = None;
        self.ak_create_attestation = None;
        self.ak_create_signature = None;
        self.lak_cert_pem = None;
        self.lak_ca_cert_pem = None;
    }

    /// Get AK creation data as raw bytes
    pub fn get_ak_creation_data(&self) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>, StorageError> {
        let creation_data = self.ak_creation_data.as_ref().filter(|s| !s.is_empty());
        let attestation = self.ak_create_attestation.as_ref().filter(|s| !s.is_empty());
        let signature = self.ak_create_signature.as_ref().filter(|s| !s.is_empty());

        match (creation_data, attestation, signature) {
            (Some(cd), Some(att), Some(sig)) => {
                let cd_bytes = BASE64_STANDARD.decode(cd)?;
                let att_bytes = BASE64_STANDARD.decode(att)?;
                let sig_bytes = BASE64_STANDARD.decode(sig)?;
                Ok(Some((cd_bytes, att_bytes, sig_bytes)))
            }
            _ => Ok(None),
        }
    }

    /// Set AK creation data
    pub fn set_ak_creation_data(&mut self, creation_data: &[u8], attestation: &[u8], signature: &[u8]) {
        self.ak_creation_data = Some(BASE64_STANDARD.encode(creation_data));
        self.ak_create_attestation = Some(BASE64_STANDARD.encode(attestation));
        self.ak_create_signature = Some(BASE64_STANDARD.encode(signature));
    }

    /// Clear agent data only
    pub fn clear_agent(&mut self) {
        self.agent_cert_pem = None;
        self.agent_key_private = None;
        self.agent_key_public = None;
        self.agent_ca_cert_pem = None;
    }
}

/// Save AK blobs and LAK certificate (preserves agent and server config)
pub fn save_blobs(
    ak_priv: &[u8],
    ak_pub: &[u8],
    lak_cert_pem: Option<&str>,
    lak_ca_cert_pem: Option<&str>,
) -> Result<(), StorageError> {
    let mut storage = TpmBlobStorage::load()?.unwrap_or_else(TpmBlobStorage::new);

    storage.set_ak_blobs(ak_priv, ak_pub);
    storage.lak_cert_pem = lak_cert_pem.map(String::from);
    storage.lak_ca_cert_pem = lak_ca_cert_pem.map(String::from);
    storage.version = BLOB_STORAGE_VERSION.to_string();

    storage.save()
}

/// Save agent certificate and key blobs (preserves AK/LAK and server config)
pub fn save_agent_blobs(
    agent_cert_pem: &str,
    agent_key_priv: &[u8],
    agent_key_pub: &[u8],
    agent_ca_cert_pem: Option<&str>,
) -> Result<(), StorageError> {
    let mut storage = TpmBlobStorage::load()?.unwrap_or_else(TpmBlobStorage::new);

    storage.agent_cert_pem = Some(agent_cert_pem.to_string());
    storage.set_agent_key_blobs(agent_key_priv, agent_key_pub);
    storage.agent_ca_cert_pem = agent_ca_cert_pem.map(String::from);
    storage.version = BLOB_STORAGE_VERSION.to_string();

    storage.save()
}

/// Save server configuration (preserves other data)
pub fn save_server_config(
    address: &str,
    ca_pem: &str,
    spki_pin: Option<&str>,
) -> Result<(), StorageError> {
    let mut storage = TpmBlobStorage::load()?.unwrap_or_else(TpmBlobStorage::new);

    storage.server_address = Some(address.to_string());
    storage.server_ca_pem = Some(ca_pem.to_string());
    storage.server_spki = spki_pin.map(String::from);
    storage.version = BLOB_STORAGE_VERSION.to_string();

    storage.save()
}

/// Load server configuration
pub fn load_server_config() -> Result<Option<(String, String, Option<String>)>, StorageError> {
    let storage = match TpmBlobStorage::load()? {
        Some(s) => s,
        None => return Ok(None),
    };

    match (storage.server_address, storage.server_ca_pem) {
        (Some(addr), Some(ca)) => Ok(Some((addr, ca, storage.server_spki))),
        _ => Ok(None),
    }
}

/// Clear LAK blobs (preserves agent and server config)
pub fn clear_lak_blobs() -> Result<(), StorageError> {
    if let Some(mut storage) = TpmBlobStorage::load()? {
        storage.clear_lak();
        storage.save()?;
        info!("LAK blobs cleared");
    }
    Ok(())
}

/// Clear agent blobs (preserves AK/LAK and server config)
pub fn clear_agent_blobs() -> Result<(), StorageError> {
    if let Some(mut storage) = TpmBlobStorage::load()? {
        storage.clear_agent();
        storage.save()?;
        info!("Agent blobs cleared");
    }
    Ok(())
}

/// Check if a PEM-encoded certificate is valid (not expired)
fn is_cert_valid(pem_data: &str) -> bool {
    use der::Decode;
    use std::time::{Duration, SystemTime};

    // Parse PEM
    let pem_result = pem::parse(pem_data);
    let pem_obj = match pem_result {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Parse certificate
    let cert = match Certificate::from_der(pem_obj.contents()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Check expiry with 1 hour buffer
    let not_after = cert.tbs_certificate.validity.not_after;

    // Convert to SystemTime for comparison
    let expiry_time = not_after.to_system_time();
    let buffer = Duration::from_secs(3600); // 1 hour
    let check_time = SystemTime::now() + buffer;
    check_time < expiry_time
}

/// Check if LAK certificate is valid
pub fn is_lak_valid() -> bool {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .map(|s| s.has_valid_lak())
        .unwrap_or(false)
}

/// Check if agent certificate is valid
pub fn is_agent_valid() -> bool {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .map(|s| s.has_valid_agent())
        .unwrap_or(false)
}

/// Check if agent blobs exist
pub fn agent_blobs_exist() -> bool {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .map(|s| s.agent_cert_pem.is_some() && s.agent_key_private.is_some())
        .unwrap_or(false)
}

/// Get agent certificate PEM
pub fn get_agent_cert_pem() -> Option<String> {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .and_then(|s| s.agent_cert_pem)
}

/// Get agent key blobs
pub fn get_agent_key_blobs() -> Option<(Vec<u8>, Vec<u8>)> {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .and_then(|s| s.get_agent_key_blobs().ok().flatten())
}

/// Get agent CA certificate PEM
pub fn get_agent_ca_cert_pem() -> Option<String> {
    TpmBlobStorage::load()
        .ok()
        .flatten()
        .and_then(|s| s.agent_ca_cert_pem)
}

/// Get blob file path (for logging)
pub fn get_blob_path() -> String {
    get_da_config_path()
}
