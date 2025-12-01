//! dar-agent - Provision an agent certificate via ACME device-attest-01
//!
//! This is the bootstrap phase that creates a hardware-bound identity certificate.
//! Prerequisites: dar-init and dar-lak must be run first.
//!
//! Usage: dar-agent [--tpm /dev/tpmrm0] [--clear]

use anyhow::{bail, Context, Result};
use clap::Parser;
use da_common::{
    clear_agent_blobs, create_tls_channel, get_blob_path, load_server_config,
    proto::certificate_service_client::CertificateServiceClient,
    proto::{AttestationSubmit, CertRequest, FinalizeRequest, GetCertRequest},
    save_agent_blobs, TpmClient,
};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "dar-agent")]
#[command(about = "Provision an agent certificate via ACME device-attest-01")]
struct Args {
    /// TPM device path
    #[arg(long, short)]
    tpm: Option<String>,

    /// Clear existing agent cert and re-provision
    #[arg(long)]
    clear: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    da_common::runtime::init();

    match run().await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Error: {:#}", e);
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    // Load server config from da.json
    let (server_addr, server_ca_pem, _) = load_server_config()?
        .context("Server not configured. Run dar-init first")?;

    info!("dar-agent: Agent Certificate Provisioning (ACME device-attest-01)");
    info!("Server: {}", server_addr);
    info!(
        "TPM: {}",
        args.tpm.as_deref().unwrap_or("/dev/tpmrm0")
    );

    // Initialize TPM client with AK
    let mut tpm_client = TpmClient::new(args.tpm.as_deref())
        .context("Failed to initialize TPM")?;

    // Check LAK is provisioned
    if tpm_client.needs_lak_provisioning() {
        bail!("LAK not provisioned. Run dar-lak first");
    }

    // Check if agent already exists (unless --clear)
    if args.clear {
        clear_agent_blobs()?;
        info!("Agent state cleared");
    }

    if !tpm_client.needs_agent_provisioning() {
        info!("Agent certificate already exists in {}", get_blob_path());
        info!("Use --clear to re-provision");
        return Ok(());
    }

    let permanent_id = tpm_client
        .get_permanent_id()
        .context("Failed to get permanent ID")?
        .to_string();
    info!("Permanent ID: {}", permanent_id);

    // Create TPM-bound signing key for agent cert
    info!("Creating TPM-bound signing key...");
    let (key_priv, key_pub) = tpm_client
        .create_agent_key()
        .context("Failed to create TPM key")?;

    // Connect to server via TLS using stored CA
    let channel = create_tls_channel(&server_addr, &server_ca_pem).await?;
    let mut client = CertificateServiceClient::new(channel);

    // Common name includes "agent" prefix
    let common_name = format!("agent-{}", permanent_id);

    // Create ACME order with usage="agent"
    info!("Creating ACME order for agent certificate...");
    let resp = client
        .request_certificate(CertRequest {
            common_name: common_name.clone(),
            san_dns: vec![],
            san_ips: vec![],
            permanent_identifier: permanent_id.clone(),
            usage: "agent".to_string(),
        })
        .await
        .context("Failed to create order")?
        .into_inner();

    if resp.status == "error" {
        bail!("Order creation failed: {}", resp.error);
    }
    info!("ACME order created: {}", resp.order_id);

    // Generate attestation using TPM2_Certify
    info!("Generating TPM attestation...");
    let key_authorization = format!("{}.{}", resp.challenge_token, resp.account_thumbprint);
    let attestation_object = tpm_client
        .generate_attestation(&key_authorization)
        .context("Failed to generate attestation")?;

    // Submit attestation
    info!("Submitting attestation...");
    let att_resp = client
        .submit_attestation(AttestationSubmit {
            order_id: resp.order_id.clone(),
            authorization_url: resp.authorization_url.clone(),
            challenge_url: resp.challenge_url.clone(),
            attestation_object,
        })
        .await
        .context("Failed to submit attestation")?
        .into_inner();

    if att_resp.status == "error" {
        bail!("Attestation failed: {}", att_resp.error);
    }

    // Wait for order to become ready
    info!("Waiting for order to become ready...");
    let mut last_status = String::new();
    for attempt in 1..=10 {
        let order_resp = client
            .get_certificate(GetCertRequest {
                order_id: resp.order_id.clone(),
            })
            .await;

        match order_resp {
            Ok(r) => {
                let inner = r.into_inner();
                last_status = inner.status.clone();
                if last_status == "ready" || last_status == "valid" {
                    info!("Order is ready");
                    break;
                }
            }
            Err(e) => {
                warn!("Attempt {}: error checking order: {}", attempt, e);
            }
        }

        if attempt == 10 {
            bail!("Order not ready after 10 attempts, last status: {}", last_status);
        }
        sleep(Duration::from_secs(1)).await;
    }

    // Generate CSR signed by TPM key
    info!("Generating CSR (TPM-signed)...");
    let csr_pem = tpm_client
        .sign_csr(&common_name, &[])
        .context("Failed to generate CSR")?;

    // Finalize order
    info!("Finalizing order...");
    let finalize_resp = client
        .finalize_order(FinalizeRequest {
            order_id: resp.order_id.clone(),
            csr_pem,
        })
        .await
        .context("Failed to finalize order")?
        .into_inner();

    if finalize_resp.status == "error" {
        bail!("Order finalization failed: {}", finalize_resp.error);
    }

    // Retrieve certificate
    info!("Retrieving certificate...");
    let mut cert_resp = None;
    for attempt in 1..=30 {
        let result = client
            .get_certificate(GetCertRequest {
                order_id: resp.order_id.clone(),
            })
            .await;

        if let Ok(r) = result {
            let inner = r.into_inner();
            if inner.status == "valid" {
                cert_resp = Some(inner);
                break;
            }
        }

        if attempt == 30 {
            bail!("Certificate not ready after 30 attempts");
        }
        sleep(Duration::from_secs(2)).await;
    }

    let cert_resp = cert_resp.context("Failed to get certificate")?;

    // Store agent cert and key blobs in da.json
    let chain_pem = cert_resp.chain_pem.first().cloned();
    save_agent_blobs(
        &cert_resp.certificate_pem,
        &key_priv,
        &key_pub,
        chain_pem.as_deref(),
    )?;

    info!("Agent certificate provisioned successfully!");
    info!("  CN: {}", common_name);
    info!("  Saved to: {}", get_blob_path());

    // Explicitly close TPM handles before exit
    tpm_client.close();

    Ok(())
}
