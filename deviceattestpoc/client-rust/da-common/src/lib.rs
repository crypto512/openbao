//! Common library for device attestation Rust client tools.
//!
//! This crate provides shared functionality for TPM operations, storage persistence,
//! TLS/mTLS configuration, and gRPC client utilities.

pub mod config;
pub mod process;
pub mod runtime;
pub mod spki;
pub mod storage;
pub mod tls;
pub mod tpm;

/// Generated gRPC client code from certservice.proto
pub mod proto {
    tonic::include_proto!("certservice");
}

pub use config::*;
pub use spki::*;
pub use storage::*;
pub use tls::*;
pub use tpm::*;
