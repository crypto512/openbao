//! dar-lak - Provision a Local Attestation Key (LAK) certificate
//!
//! This tool provisions a LAK certificate via TCG credential activation.
//! Prerequisites: dar-init must be run first to configure server trust.
//!
//! Usage: dar-lak [--tpm /dev/tpmrm0] [--clear]

use anyhow::{bail, Context, Result};
use clap::Parser;
use da_common::{
    clear_lak_blobs, create_tls_channel, get_blob_path, load_server_config,
    proto::certificate_service_client::CertificateServiceClient,
    proto::{ActivateCredentialRequest, ProvisionLakRequest, TpmEnrollmentRequest},
    TpmClient,
};
use std::process::ExitCode;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "dar-lak")]
#[command(about = "Provision a Local Attestation Key (LAK) certificate")]
struct Args {
    /// TPM device path
    #[arg(long, short)]
    tpm: Option<String>,

    /// Clear existing LAK and re-provision
    #[arg(long)]
    clear: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    da_common::runtime::init();

    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            // Check for pending approval
            if e.to_string().contains("PENDING APPROVAL") {
                eprintln!();
                eprintln!("════════════════════════════════════════════════════════════");
                eprintln!("  DEVICE PENDING APPROVAL");
                eprintln!("════════════════════════════════════════════════════════════");
                eprintln!();
                eprintln!("  This device has been registered but requires admin approval");
                eprintln!("  before it can proceed with provisioning.");
                eprintln!();
                eprintln!("  Next steps:");
                eprintln!("  1. Ask your administrator to approve this device");
                eprintln!("  2. Run 'dar-init' again after approval");
                eprintln!();
                eprintln!("════════════════════════════════════════════════════════════");
                return ExitCode::from(2); // Exit code 2 indicates pending approval
            }
            error!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    // Load server config from da.json
    let (server_addr, server_ca_pem, _) = load_server_config()?
        .context("Server not configured. Run dar-init first")?;

    info!("dar-lak: LAK Certificate Provisioning");
    info!("Server: {}", server_addr);
    info!(
        "TPM: {}",
        args.tpm.as_deref().unwrap_or("/dev/tpmrm0")
    );

    if args.clear {
        clear_lak_blobs()?;
        info!("LAK data cleared");
    }

    // Phase 1: Initialize TPM for enrollment only (no AK creation yet)
    let mut tpm_client = TpmClient::new_for_enrollment(args.tpm.as_deref())
        .context("Failed to initialize TPM")?;

    let permanent_id = tpm_client
        .get_permanent_id()
        .context("Failed to get permanent ID")?
        .to_string();
    info!("Permanent ID: {}", permanent_id);

    if !tpm_client.needs_lak_provisioning() {
        info!("LAK certificate already exists in {}", get_blob_path());
        info!("Use --clear to re-provision");
        return Ok(());
    }

    // Connect to server via TLS using stored CA
    let channel = create_tls_channel(&server_addr, &server_ca_pem).await?;
    let mut client = CertificateServiceClient::new(channel);

    // Phase 2: Check enrollment/approval status with server BEFORE creating AK
    info!("Checking device enrollment status...");
    let enroll_resp = client
        .enroll_tpm(TpmEnrollmentRequest {
            ek_certificate_pem: tpm_client.get_ek_certificate_pem().unwrap_or_default(),
            device_description: format!("Device {}", &permanent_id[..8.min(permanent_id.len())]),
        })
        .await
        .context("Failed to enroll TPM")?
        .into_inner();

    if enroll_resp.status == "error" {
        bail!("TPM enrollment failed: {}", enroll_resp.error);
    }
    info!("Device status: {}", enroll_resp.permanent_identifier);

    // Check if device needs approval - exit BEFORE any AK operations
    if enroll_resp.pending_approval {
        bail!("PENDING APPROVAL - Permanent ID: {}", enroll_resp.permanent_identifier);
    }

    // Phase 3: Device is approved - now initialize AK (create or load)
    info!("Device approved, initializing attestation key...");
    tpm_client
        .initialize_ak()
        .context("Failed to initialize AK")?;

    // Phase 4: Get AK activation data for credential challenge
    info!("Requesting credential challenge...");
    let (ak_params, ek_public) = tpm_client
        .get_ak_activation_data()
        .context("Failed to get AK activation data")?;

    let provision_resp = client
        .provision_lak(ProvisionLakRequest {
            permanent_identifier: permanent_id.clone(),
            ak_parameters: ak_params,
            ek_public,
            ek_cert_pem: tpm_client.get_ek_certificate_pem().unwrap_or_default(),
        })
        .await
        .context("Failed to request credential challenge")?
        .into_inner();

    if provision_resp.status != "challenge" {
        bail!("Credential challenge failed: {}", provision_resp.error);
    }

    // Activate credential
    info!("Activating credential...");
    let decrypted_secret = tpm_client
        .activate_credential(&provision_resp.encrypted_credential)
        .context("TPM ActivateCredential failed")?;

    let activate_resp = client
        .activate_credential(ActivateCredentialRequest {
            session_id: provision_resp.session_id,
            decrypted_secret,
        })
        .await
        .context("Failed to activate credential")?
        .into_inner();

    if activate_resp.status != "success" {
        bail!("Credential activation failed: {}", activate_resp.error);
    }

    // Store LAK certificate
    tpm_client
        .set_lak_certificate(
            &activate_resp.lak_certificate_pem,
            Some(&activate_resp.lak_root_ca_pem),
        )
        .context("Failed to store LAK certificate")?;

    info!("LAK certificate provisioned successfully");
    info!("  Valid from: {}", activate_resp.not_before);
    info!("  Valid until: {}", activate_resp.not_after);
    info!("  Saved to: {}", get_blob_path());

    // Explicitly close TPM handles before exit
    tpm_client.close();

    Ok(())
}
