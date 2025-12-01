//! SPKI (Subject Public Key Info) pin verification for TOFU (Trust On First Use).
//!
//! Follows the standard format used by curl, wget, and Chrome HPKP:
//! `sha256//<base64-encoded-hash>`

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use der::Encode;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;

/// SPKI pin prefix
pub const SPKI_PIN_PREFIX: &str = "sha256//";

#[derive(Error, Debug)]
pub enum SpkiError {
    #[error("invalid SPKI pin format: must start with {SPKI_PIN_PREFIX}")]
    InvalidFormat,

    #[error("invalid SPKI pin: empty hash")]
    EmptyHash,

    #[error("invalid SPKI pin: bad base64 encoding: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("invalid SPKI pin: hash should be 32 bytes, got {0}")]
    InvalidHashLength(usize),

    #[error("SPKI pin mismatch: expected {expected}, got chain pins: {actual:?}")]
    Mismatch { expected: String, actual: Vec<String> },
}

/// Compute the SPKI pin for a certificate.
/// Returns format: `sha256//<base64-encoded-hash>`
pub fn compute_spki_pin(cert: &Certificate) -> String {
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("Failed to encode SPKI to DER");
    let hash = Sha256::digest(&spki_der);
    format!("{}{}", SPKI_PIN_PREFIX, BASE64_STANDARD.encode(hash))
}

/// Compute the SPKI pin from raw DER-encoded SPKI bytes.
pub fn compute_spki_pin_from_der(spki_der: &[u8]) -> String {
    let hash = Sha256::digest(spki_der);
    format!("{}{}", SPKI_PIN_PREFIX, BASE64_STANDARD.encode(hash))
}

/// Verify that at least one certificate in the chain matches the expected SPKI pin.
pub fn verify_chain_spki(chain: &[Certificate], expected_pin: &str) -> Result<(), SpkiError> {
    parse_spki_pin(expected_pin)?;

    for cert in chain {
        let pin = compute_spki_pin(cert);
        if pin == expected_pin {
            return Ok(());
        }
    }

    let pins: Vec<String> = chain.iter().map(compute_spki_pin).collect();
    Err(SpkiError::Mismatch {
        expected: expected_pin.to_string(),
        actual: pins,
    })
}

/// Parse and validate an SPKI pin string.
/// Returns the base64-encoded hash portion if valid.
pub fn parse_spki_pin(pin: &str) -> Result<String, SpkiError> {
    let hash_b64 = pin
        .strip_prefix(SPKI_PIN_PREFIX)
        .ok_or(SpkiError::InvalidFormat)?;

    if hash_b64.is_empty() {
        return Err(SpkiError::EmptyHash);
    }

    let decoded = BASE64_STANDARD.decode(hash_b64)?;

    // SHA256 hash should be 32 bytes
    if decoded.len() != 32 {
        return Err(SpkiError::InvalidHashLength(decoded.len()));
    }

    Ok(hash_b64.to_string())
}

/// Extract CA chain from certificates and return as PEM.
/// Includes all certificates including the leaf (first in chain).
/// This is needed for force mode where we need the complete chain for validation.
pub fn extract_ca_chain_pem(chain: &[Certificate]) -> Option<String> {
    use der::Encode;

    if chain.is_empty() {
        return None;
    }

    // Include all certificates - the tonic TLS needs the complete chain
    let certs_to_encode = chain;

    let mut pem_blocks = Vec::new();
    for cert in certs_to_encode {
        if let Ok(der) = cert.to_der() {
            let pem = pem::Pem::new("CERTIFICATE", der);
            pem_blocks.push(pem::encode(&pem));
        }
    }

    if pem_blocks.is_empty() {
        None
    } else {
        Some(pem_blocks.join(""))
    }
}

/// Encode a certificate to PEM format.
pub fn cert_to_pem(cert: &Certificate) -> Option<String> {
    use der::Encode;
    cert.to_der()
        .ok()
        .map(|der| pem::encode(&pem::Pem::new("CERTIFICATE", der)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spki_pin_valid() {
        // Valid SHA256 hash (32 bytes = 44 base64 chars with padding)
        let valid_pin = "sha256//yp/DAVVj1vR8tPqQ/KFq0kvXUKzJHMg6y58STUXM2vA=";
        assert!(parse_spki_pin(valid_pin).is_ok());
    }

    #[test]
    fn test_parse_spki_pin_invalid_prefix() {
        let invalid = "sha512//abc123";
        assert!(matches!(
            parse_spki_pin(invalid),
            Err(SpkiError::InvalidFormat)
        ));
    }

    #[test]
    fn test_parse_spki_pin_empty_hash() {
        let empty = "sha256//";
        assert!(matches!(parse_spki_pin(empty), Err(SpkiError::EmptyHash)));
    }
}
