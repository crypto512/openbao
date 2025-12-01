//! dar-init - Bootstrap device attestation trust anchor via TOFU
//!
//! This is the entry point for device initialization.
//!
//! Usage:
//!   dar-init <server-address> <spki-pin>  - First-time TOFU setup with SPKI verification
//!   dar-init --force <server-address>     - First-time setup without SPKI verification (insecure)
//!   dar-init                              - Full reinit (clears LAK/agent, re-provisions)

use anyhow::{Context, Result};
use da_common::{
    clear_agent_blobs, clear_lak_blobs, create_insecure_channel,
    create_tofu_channel, get_blob_path, load_server_config,
    process::run_tool,
    proto::certificate_service_client::CertificateServiceClient,
    proto::TpmEnrollmentRequest,
    save_server_config,
};
use std::env;
use std::process::ExitCode;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> ExitCode {
    da_common::runtime::init();

    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Check for --force flag
    if args.len() >= 2 && args[1] == "--force" {
        if args.len() != 3 {
            eprintln!("Usage: dar-init --force <server-address>");
            std::process::exit(1);
        }
        let server_addr = &args[2];
        return run_force(server_addr).await;
    }

    match args.len() {
        1 => {
            // Reinit mode: no arguments
            run_reinit().await
        }
        3 => {
            // TOFU mode: server-address and spki-pin
            let server_addr = &args[1];
            let spki_pin = &args[2];
            run_tofu(server_addr, spki_pin).await
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  dar-init <server-address> <spki-pin>  - First-time TOFU setup");
            eprintln!("  dar-init --force <server-address>     - Setup without SPKI verification (insecure)");
            eprintln!("  dar-init                              - Full reinit");
            eprintln!();
            eprintln!("Examples:");
            eprintln!("  dar-init grpc-server:50051 sha256//abc123...");
            eprintln!("  dar-init --force grpc-server:50051");
            eprintln!("  dar-init");
            std::process::exit(1);
        }
    }
}

/// TOFU setup with SPKI pin verification
async fn run_tofu(server_addr: &str, spki_pin: &str) -> Result<()> {
    info!("dar-init: TOFU Setup");
    info!("Server: {}", server_addr);
    info!("SPKI Pin: {}", spki_pin);

    info!("Connecting to {}...", server_addr);

    // Connect using TOFU credentials - TLS handshake triggers pin verification
    let (channel, tofu_result) = create_tofu_channel(server_addr, spki_pin).await?;

    // Make a simple call to ensure connection is working
    let mut client = CertificateServiceClient::new(channel);
    let _ = client
        .enroll_tpm(TpmEnrollmentRequest::default())
        .await;

    info!("SPKI pin verified");

    // Clear existing LAK/agent certificates
    info!("Clearing existing certificates...");
    clear_lak_blobs()?;
    clear_agent_blobs()?;

    // Save server config to da.json
    save_server_config(server_addr, &tofu_result.ca_pem, Some(&tofu_result.spki_pin))?;
    info!("Server CA saved to {}", get_blob_path());

    // Chain to dar-lak
    info!("");
    info!("Running dar-lak...");
    run_tool("dar-lak")?;

    // Chain to dar-agent
    info!("");
    info!("Running dar-agent...");
    run_tool("dar-agent")?;

    info!("");
    info!("Device initialized successfully!");
    Ok(())
}

/// Full reinitialization using existing server config
async fn run_reinit() -> Result<()> {
    info!("dar-init: Full Reinit");

    // Load existing server config
    let (server_addr, _, _) = load_server_config()?
        .context("Not configured. Run: dar-init <server-address> <spki-pin>")?;

    info!("Server: {}", server_addr);

    // Clear existing LAK/agent certificates
    info!("Clearing LAK and agent certificates...");
    clear_lak_blobs()?;
    clear_agent_blobs()?;

    // Chain to dar-lak
    info!("");
    info!("Running dar-lak...");
    run_tool("dar-lak")?;

    // Chain to dar-agent
    info!("");
    info!("Running dar-agent...");
    run_tool("dar-agent")?;

    info!("");
    info!("Device reinitialized successfully!");
    Ok(())
}

/// Force setup without SPKI verification (insecure, for development/testing)
async fn run_force(server_addr: &str) -> Result<()> {
    info!("dar-init: Force Setup (no SPKI verification)");
    warn!("WARNING: Skipping SPKI verification - use only for development/testing!");
    info!("Server: {}", server_addr);

    info!("Connecting to {}...", server_addr);

    // Connect with insecure TLS to capture certificate
    let (_channel, tofu_result) = create_insecure_channel(server_addr).await?;

    let tofu_result = tofu_result.context("Failed to capture server CA")?;

    info!("Server SPKI Pin: {}", tofu_result.spki_pin);
    info!("Captured server CA");

    // Clear existing LAK/agent certificates
    info!("Clearing existing certificates...");
    clear_lak_blobs()?;
    clear_agent_blobs()?;

    // Save server config to da.json
    save_server_config(server_addr, &tofu_result.ca_pem, Some(&tofu_result.spki_pin))?;
    info!("Server CA saved to {}", get_blob_path());

    // Chain to dar-lak
    info!("");
    info!("Running dar-lak...");
    run_tool("dar-lak")?;

    // Chain to dar-agent
    info!("");
    info!("Running dar-agent...");
    run_tool("dar-agent")?;

    info!("");
    info!("Device initialized successfully!");
    Ok(())
}
