//! dar-gen - Generate certificates using mTLS authentication with agent cert
//!
//! Prerequisites: dar-init, dar-lak, and dar-agent must be run first.
//!
//! Usage: dar-gen --usage vpn [--tpm /dev/tpmrm0] [--output ./certs]
//!
//! Output files:
//!   - <usage>-key.pem: Private key in standard PEM format (unencrypted)
//!   - <usage>-cert.pem: Certificate with full CA chain (leaf + intermediate + root)
//!
//! Note: Usage keys are ephemeral - generated on demand, not stored in device config.
//! The mTLS authentication uses the TPM-bound agent certificate.
//!
//! Self-healing: If LAK or agent certificates are expired, they will be
//! automatically refreshed before generating the usage certificate.

use anyhow::{bail, Context, Result};
use clap::Parser;
use da_common::{
    create_tpm_mtls_channel, get_agent_ca_cert_pem, get_agent_cert_pem, get_agent_key_blobs,
    get_output_dir, is_agent_valid, is_lak_valid, load_server_config,
    process::run_tool,
    proto::certificate_service_client::CertificateServiceClient,
    proto::IssueCertRequest,
    TpmClient,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::EncodePem;
use x509_cert::name::Name;

#[derive(Parser, Debug)]
#[command(name = "dar-gen")]
#[command(about = "Generate certificates using mTLS authentication with agent cert")]
struct Args {
    /// Certificate usage (e.g., vpn, wifi, tls)
    #[arg(long, required = true)]
    usage: String,

    /// TPM device path
    #[arg(long, short)]
    tpm: Option<String>,

    /// Output directory for certificate and key
    #[arg(long, short)]
    output: Option<String>,
}

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
    let args = Args::parse();

    let output_dir = get_output_dir(args.output.as_deref());

    // Load server config from da.json
    let (server_addr, server_ca_pem, _) =
        load_server_config()?.context("Server not configured. Run dar-init first")?;

    info!("dar-gen: Certificate Generation (mTLS)");
    info!("Usage: {}", args.usage);
    info!("Server: {}", server_addr);
    info!(
        "TPM: {}",
        args.tpm.as_deref().unwrap_or("/dev/tpmrm0")
    );
    info!("Output: {}", output_dir);

    // Self-healing: check and refresh LAK/agent if needed
    if !is_lak_valid() {
        info!("LAK certificate expired or invalid, refreshing...");
        run_tool("dar-lak")?;
    }
    if !is_agent_valid() {
        info!("Agent certificate expired or invalid, refreshing...");
        run_tool("dar-agent")?;
    }

    // Initialize TPM client wrapped in Arc<Mutex> for thread-safe access
    let tpm_client = TpmClient::new(args.tpm.as_deref()).context("Failed to initialize TPM")?;
    let tpm_client = Arc::new(Mutex::new(tpm_client));

    // Close AK to free TPM object slots - we don't need it for mTLS
    {
        let mut tpm = tpm_client.lock().unwrap();
        tpm.close_ak();
    }

    let permanent_id = {
        let tpm = tpm_client.lock().unwrap();
        tpm.get_permanent_id()
            .context("Failed to get permanent ID")?
            .to_string()
    };
    info!("Permanent ID: {}", permanent_id);

    // Generate standard RSA key (not TPM-bound)
    info!("Generating RSA key...");
    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).context("Failed to generate RSA key")?;

    // Build common name with usage prefix
    let common_name = format!("{}-{}", args.usage, permanent_id);

    // Generate CSR signed by the RSA key
    info!("Generating CSR...");
    let subject = Name::from_str(&format!("CN={}", common_name))
        .context("Failed to create subject name")?;

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key.clone());
    let csr_builder = RequestBuilder::new(subject, &signing_key)
        .context("Failed to create CSR builder")?;

    let csr = csr_builder.build::<rsa::pkcs1v15::Signature>()
        .context("Failed to build CSR")?;

    let csr_pem = csr.to_pem(LineEnding::LF)
        .context("Failed to encode CSR to PEM")?;

    // Load agent certificate for mTLS
    let agent_cert_pem = get_agent_cert_pem().context("Agent certificate not found")?;
    let (agent_key_priv, agent_key_pub) =
        get_agent_key_blobs().context("Agent key blobs not found")?;

    // Load agent key into TPM for mTLS signing
    {
        let mut tpm = tpm_client.lock().unwrap();
        tpm.load_agent_key(&agent_key_priv, &agent_key_pub)
            .context("Failed to load agent key")?;
    }

    // Get agent CA certificate for the full chain
    let agent_ca_pem = get_agent_ca_cert_pem();

    // Create full client cert chain (agent cert + CA)
    let full_client_cert = if let Some(ca_pem) = agent_ca_pem {
        format!("{}\n{}", agent_cert_pem, ca_pem)
    } else {
        agent_cert_pem.clone()
    };

    // Connect with TPM-backed mTLS
    info!("Connecting with TPM-backed mTLS...");
    let channel = create_tpm_mtls_channel(
        &server_addr,
        &server_ca_pem,
        &full_client_cert,
        tpm_client.clone(),
    )
    .await
    .context("Failed to connect to server with mTLS")?;

    let mut client = CertificateServiceClient::new(channel);

    // Call IssueCertificate RPC
    info!("Requesting certificate...");
    let resp = client
        .issue_certificate(IssueCertRequest {
            usage: args.usage.clone(),
            csr_pem,
            common_name: common_name.clone(),
            san_dns: vec![],
            san_ips: vec![],
        })
        .await
        .context("Certificate issuance failed")?
        .into_inner();

    if resp.status != "success" {
        bail!("Certificate issuance failed: {}", resp.error);
    }

    // Write output files
    fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

    let key_path = Path::new(&output_dir).join(format!("{}-key.pem", args.usage));
    let cert_path = Path::new(&output_dir).join(format!("{}-cert.pem", args.usage));

    // Save private key in PEM format
    let key_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .context("Failed to encode private key")?;
    fs::write(&key_path, key_pem.as_bytes()).context("Failed to write private key")?;

    // Set restrictive permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .context("Failed to set key file permissions")?;
    }

    // Write certificate with chain
    let mut cert_data = resp.certificate_pem;
    if !resp.chain_pem.is_empty() {
        cert_data.push('\n');
        cert_data.push_str(&resp.chain_pem);
    }
    fs::write(&cert_path, &cert_data).context("Failed to write certificate")?;

    info!("Certificate generated successfully!");
    info!("  Key: {}", key_path.display());
    info!("  Cert: {}", cert_path.display());
    info!("  CN: {}", common_name);
    if !resp.not_before.is_empty() && !resp.not_after.is_empty() {
        info!("  Valid: {} to {}", resp.not_before, resp.not_after);
    }

    Ok(())
}

// Helper trait for Name parsing
trait FromStrExt {
    fn from_str(s: &str) -> Result<Self>
    where
        Self: Sized;
}

impl FromStrExt for Name {
    fn from_str(s: &str) -> Result<Self> {
        <Name as std::str::FromStr>::from_str(s).context("Failed to parse distinguished name")
    }
}
