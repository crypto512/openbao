//! dar-fingerprint - Display the device permanent identifier (EK hash)
//!
//! This tool computes and displays the permanent identifier for a device
//! based on the TPM's Endorsement Key (EK) public key.
//!
//! Usage: dar-fingerprint [--tpm /dev/tpmrm0]
//!
//! The permanent identifier is computed as: base64(SHA-256(EK public key))
//! This value is stable and unique to the TPM/device.

use anyhow::{Context, Result};
use clap::Parser;
use da_common::TpmClient;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "dar-fingerprint")]
#[command(about = "Display the device permanent identifier (EK hash)")]
struct Args {
    /// TPM device path
    #[arg(long, short)]
    tpm: Option<String>,
}

fn main() -> Result<()> {
    // Initialize logging without timestamps for clean output
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let args = Args::parse();

    // Create TPM client for enrollment only (no AK needed)
    let tpm_client = TpmClient::new_for_enrollment(args.tpm.as_deref())
        .context("Failed to initialize TPM")?;

    // Get permanent identifier
    let permanent_id = tpm_client
        .get_permanent_id()
        .context("Failed to get permanent identifier")?;

    // Output permanent identifier (clean, single line)
    println!("{}", permanent_id);

    Ok(())
}
