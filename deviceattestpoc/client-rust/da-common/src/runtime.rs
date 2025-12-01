//! Shared runtime initialization for device attestation tools.

use tracing_subscriber::EnvFilter;

/// Initialize the runtime environment for device attestation tools.
///
/// This sets up:
/// - rustls crypto provider (ring)
/// - tracing subscriber with da_common=info default
///
/// # Panics
/// Panics if the rustls crypto provider cannot be installed.
pub fn init() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("da_common=info".parse().expect("valid directive")),
        )
        .init();
}
