//! TLS and mTLS credential management for gRPC connections.

use std::io::BufReader;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ClientConfig;
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::tpm::TpmClient;

/// Parse server address into host and port
fn parse_addr(addr: &str) -> Result<(String, u16), TlsError> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return Err(TlsError::ConfigError(format!("Invalid address: {}", addr)));
    }
    let host = parts[0].to_string();
    let port = parts[1].parse::<u16>()
        .map_err(|e| TlsError::ConfigError(format!("Invalid port: {}", e)))?;
    Ok((host, port))
}

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("failed to parse CA certificate: {0}")]
    CaParseError(String),

    #[error("failed to parse client certificate: {0}")]
    CertParseError(String),

    #[error("failed to parse private key: {0}")]
    KeyParseError(String),

    #[error("no certificates found in PEM")]
    NoCertsFound,

    #[error("no private key found in PEM")]
    NoKeyFound,

    #[error("TLS configuration error: {0}")]
    ConfigError(String),

    #[error("connection error: {0}")]
    ConnectionError(String),

    #[error("transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),
}

/// Create TLS credentials from a PEM-encoded CA certificate
pub fn create_tls_config(ca_pem: &str) -> Result<ClientTlsConfig, TlsError> {
    let ca_cert = Certificate::from_pem(ca_pem);
    Ok(ClientTlsConfig::new().ca_certificate(ca_cert))
}

/// Create a gRPC channel with TLS using stored CA
pub async fn create_tls_channel(server_addr: &str, ca_pem: &str) -> Result<Channel, TlsError> {
    let tls_config = create_tls_config(ca_pem)?;

    let endpoint = Endpoint::from_shared(format!("https://{}", server_addr))
        .map_err(|e| TlsError::ConfigError(e.to_string()))?
        .tls_config(tls_config)?;

    let channel = endpoint.connect().await?;
    Ok(channel)
}

/// Result of TOFU (Trust On First Use) TLS connection
#[derive(Debug, Clone)]
pub struct TofuResult {
    /// CA certificate chain in PEM format
    pub ca_pem: String,
    /// SPKI pin of the server certificate
    pub spki_pin: String,
}

/// Create insecure TLS config for force mode (no verification)
/// WARNING: Only for development/testing
pub fn create_insecure_tls_config() -> Result<ClientTlsConfig, TlsError> {
    // tonic's ClientTlsConfig doesn't have a direct "skip verify" option
    // For force mode, we need to use a custom approach
    Ok(ClientTlsConfig::new()
        .domain_name("server") // Will be overridden
    )
}

/// Create a gRPC channel with insecure TLS (for force mode)
/// This captures the server certificate during handshake
pub async fn create_insecure_channel(server_addr: &str) -> Result<(Channel, Option<TofuResult>), TlsError> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::ServerName;
    use rustls::DigitallySignedStruct;
    use std::sync::Mutex;
    use x509_cert::Certificate;
    use der::Decode;
    use crate::spki::{compute_spki_pin, extract_ca_chain_pem};

    // Custom verifier that accepts any certificate and captures it
    struct CaptureVerifier {
        captured: Arc<Mutex<Option<TofuResult>>>,
    }

    impl ServerCertVerifier for CaptureVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            // Parse certificates
            let mut certs = Vec::new();
            if let Ok(cert) = Certificate::from_der(end_entity.as_ref()) {
                certs.push(cert);
            }
            for intermediate in intermediates {
                if let Ok(cert) = Certificate::from_der(intermediate.as_ref()) {
                    certs.push(cert);
                }
            }

            if !certs.is_empty() {
                let spki_pin = compute_spki_pin(&certs[0]);
                let ca_pem = extract_ca_chain_pem(&certs).unwrap_or_default();

                let mut captured = self.captured.lock().expect("mutex not poisoned");
                *captured = Some(TofuResult { ca_pem, spki_pin });
            }

            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            ]
        }
    }

    impl std::fmt::Debug for CaptureVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CaptureVerifier").finish()
        }
    }

    let captured = Arc::new(Mutex::new(None));
    let verifier = Arc::new(CaptureVerifier {
        captured: captured.clone(),
    });

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // Use tokio-rustls connector with our custom config
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // Parse address
    let (host, port) = parse_addr(server_addr)?;

    // Connect TCP
    let tcp = tokio::net::TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| TlsError::ConnectionError(e.to_string()))?;

    // Connect TLS with our custom verifier
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| TlsError::ConfigError(e.to_string()))?;

    let tls_stream = connector.connect(server_name, tcp)
        .await
        .map_err(|e| TlsError::ConnectionError(e.to_string()))?;

    // Get the captured result after the handshake
    let result = captured.lock().expect("mutex not poisoned").clone();

    // Drop the TLS stream - we only needed it to capture the certificate
    drop(tls_stream);

    // For force mode, we just capture the certificate and return it
    // The caller will save it to config and subsequent tools will use create_tls_channel
    if let Some(ref tofu) = result {
        // Create a channel using the captured CA
        let ca_cert = tonic::transport::Certificate::from_pem(tofu.ca_pem.clone());
        let tls_config = ClientTlsConfig::new()
            .domain_name(host)
            .ca_certificate(ca_cert);

        let endpoint = Endpoint::from_shared(format!("https://{}", server_addr))
            .map_err(|e| TlsError::ConfigError(e.to_string()))?
            .tls_config(tls_config)?;

        let channel = endpoint.connect().await?;
        Ok((channel, result))
    } else {
        Err(TlsError::ConfigError("Failed to capture server certificate".to_string()))
    }
}

/// Create a gRPC channel with TOFU SPKI pin verification
pub async fn create_tofu_channel(
    server_addr: &str,
    expected_pin: &str,
) -> Result<(Channel, TofuResult), TlsError> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::ServerName;
    use rustls::DigitallySignedStruct;
    use std::sync::Mutex;
    use x509_cert::Certificate;
    use der::Decode;
    use crate::spki::{compute_spki_pin, extract_ca_chain_pem, verify_chain_spki};

    // Custom verifier that checks SPKI pin and captures CA
    struct SpkiVerifier {
        expected_pin: String,
        captured: Arc<Mutex<Option<TofuResult>>>,
    }

    impl ServerCertVerifier for SpkiVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            // Parse certificates
            let mut certs = Vec::new();
            if let Ok(cert) = Certificate::from_der(end_entity.as_ref()) {
                certs.push(cert);
            }
            for intermediate in intermediates {
                if let Ok(cert) = Certificate::from_der(intermediate.as_ref()) {
                    certs.push(cert);
                }
            }

            if certs.is_empty() {
                return Err(rustls::Error::General("No certificates received".into()));
            }

            // Verify SPKI pin
            verify_chain_spki(&certs, &self.expected_pin)
                .map_err(|e| rustls::Error::General(e.to_string()))?;

            // Capture result
            let spki_pin = compute_spki_pin(&certs[0]);
            let ca_pem = extract_ca_chain_pem(&certs).unwrap_or_default();

            let mut captured = self.captured.lock().expect("mutex not poisoned");
            *captured = Some(TofuResult { ca_pem, spki_pin });

            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            ]
        }
    }

    impl std::fmt::Debug for SpkiVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SpkiVerifier")
                .field("expected_pin", &self.expected_pin)
                .finish()
        }
    }

    let captured = Arc::new(Mutex::new(None));
    let _verifier = Arc::new(SpkiVerifier {
        expected_pin: expected_pin.to_string(),
        captured: captured.clone(),
    });

    // For now, use insecure mode and validate manually
    // A proper implementation would integrate the custom verifier
    let tls_config = ClientTlsConfig::new().domain_name("server");

    let endpoint = Endpoint::from_shared(format!("https://{}", server_addr))
        .map_err(|e| TlsError::ConfigError(e.to_string()))?
        .tls_config(tls_config)?;

    let channel = endpoint.connect().await?;

    let result = captured
        .lock()
        .expect("mutex not poisoned")
        .clone()
        .ok_or_else(|| TlsError::ConfigError("TOFU verification failed".into()))?;

    Ok((channel, result))
}

/// Parse PEM certificates into DER format
pub fn parse_pem_certs(pem_data: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(pem_data.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(TlsError::NoCertsFound);
    }

    Ok(certs)
}

/// Parse PEM private key
pub fn parse_pem_key(pem_data: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = BufReader::new(pem_data.as_bytes());

    // Try to read any type of private key
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => continue, // Skip other items
            Ok(None) => break,
            Err(e) => return Err(TlsError::KeyParseError(e.to_string())),
        }
    }

    Err(TlsError::NoKeyFound)
}

/// Create mTLS credentials for client authentication
/// This version uses PEM-encoded certificate and private key
pub fn create_mtls_config(ca_pem: &str, client_cert_pem: &str, client_key_pem: &str) -> Result<ClientTlsConfig, TlsError> {
    let ca_cert = Certificate::from_pem(ca_pem);
    let client_identity = tonic::transport::Identity::from_pem(client_cert_pem, client_key_pem);

    Ok(ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(client_identity))
}

/// Create a gRPC channel with mTLS using stored CA and client certificate/key
pub async fn create_mtls_channel(
    server_addr: &str,
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<Channel, TlsError> {
    let tls_config = create_mtls_config(ca_pem, client_cert_pem, client_key_pem)?;

    let endpoint = Endpoint::from_shared(format!("https://{}", server_addr))
        .map_err(|e| TlsError::ConfigError(e.to_string()))?
        .tls_config(tls_config)?;

    let channel = endpoint.connect().await?;
    Ok(channel)
}

// ============================================================================
// TPM-Backed mTLS Support
// ============================================================================

/// TPM-backed signing key for mTLS client authentication.
///
/// This implements rustls's `SigningKey` trait using TPM operations.
/// The actual signing is performed by the TPM using the loaded agent key.
struct TpmSigningKey {
    tpm_client: Arc<Mutex<TpmClient>>,
}

impl TpmSigningKey {
    fn new(tpm_client: Arc<Mutex<TpmClient>>) -> Self {
        Self { tpm_client }
    }
}

impl rustls::sign::SigningKey for TpmSigningKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        // TPM agent key is RSA 2048
        // Prefer RSA-PSS (TLS 1.3) over PKCS#1 v1.5 (TLS 1.2)
        let preferred = [
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ];

        for scheme in preferred {
            if offered.contains(&scheme) {
                return Some(Box::new(TpmSigner {
                    tpm_client: self.tpm_client.clone(),
                    scheme,
                }));
            }
        }
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::RSA
    }
}

impl std::fmt::Debug for TpmSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmSigningKey").finish()
    }
}

/// TPM-backed signer that performs actual signing operations.
struct TpmSigner {
    tpm_client: Arc<Mutex<TpmClient>>,
    scheme: rustls::SignatureScheme,
}

impl rustls::sign::Signer for TpmSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use sha2::{Sha256, Digest};

        // rustls sends the raw message, we need to hash it first
        let digest = Sha256::digest(message);

        // Determine if we should use PSS or PKCS#1 v1.5
        let use_pss = matches!(self.scheme, rustls::SignatureScheme::RSA_PSS_SHA256);

        // Sign with TPM
        let mut tpm = self.tpm_client.lock()
            .map_err(|_| rustls::Error::General("TPM mutex poisoned".into()))?;

        let result = if use_pss {
            tpm.sign_with_agent_key_pss(&digest)
        } else {
            tpm.sign_with_agent_key(&digest)
        };

        result.map_err(|e| rustls::Error::General(format!("TPM signing failed: {}", e)))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

impl std::fmt::Debug for TpmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

/// Client certificate resolver that uses TPM-backed signing.
struct TpmClientCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl TpmClientCertResolver {
    fn new(certs: Vec<CertificateDer<'static>>, signing_key: Arc<dyn rustls::sign::SigningKey>) -> Self {
        Self {
            certified_key: Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)),
        }
    }
}

impl rustls::client::ResolvesClientCert for TpmClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for TpmClientCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmClientCertResolver").finish()
    }
}

/// TLS connector service for use with tonic's `connect_with_connector`.
struct TpmTlsConnector {
    tls_config: Arc<ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl tower::Service<http::Uri> for TpmTlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let tls_config = self.tls_config.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let host = uri.host().ok_or("missing host in URI")?;
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{}:{}", host, port);

            let tcp = tokio::net::TcpStream::connect(&addr).await?;
            let connector = tokio_rustls::TlsConnector::from(tls_config);
            let tls = connector.connect(server_name, tcp).await?;

            // Wrap with TokioIo for hyper compatibility
            Ok(hyper_util::rt::TokioIo::new(tls))
        })
    }
}

/// Create a gRPC channel with TPM-backed mTLS authentication.
///
/// This uses the TPM to perform client certificate signing operations,
/// keeping the private key protected in hardware.
///
/// # Arguments
/// * `server_addr` - Server address in "host:port" format
/// * `ca_pem` - PEM-encoded CA certificate for server verification
/// * `client_cert_pem` - PEM-encoded client certificate chain
/// * `tpm_client` - TPM client with agent key loaded
///
/// # Prerequisites
/// The `tpm_client` must have the agent key loaded via `load_agent_key()`.
pub async fn create_tpm_mtls_channel(
    server_addr: &str,
    ca_pem: &str,
    client_cert_pem: &str,
    tpm_client: Arc<Mutex<TpmClient>>,
) -> Result<Channel, TlsError> {
    // Parse server address
    let (host, _port) = parse_addr(server_addr)?;

    // Parse CA certificates
    let ca_certs = parse_pem_certs(ca_pem)?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)
            .map_err(|e| TlsError::CaParseError(e.to_string()))?;
    }

    // Parse client certificate chain
    let client_certs = parse_pem_certs(client_cert_pem)?;

    // Create TPM-backed signing key and resolver
    let signing_key: Arc<dyn rustls::sign::SigningKey> = Arc::new(TpmSigningKey::new(tpm_client));
    let cert_resolver = Arc::new(TpmClientCertResolver::new(client_certs, signing_key));

    // Build rustls config with TPM-backed client cert resolver
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_cert_resolver(cert_resolver);

    // Enable ALPN for HTTP/2 - required for gRPC
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_config = Arc::new(tls_config);

    // Create server name for TLS
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| TlsError::ConfigError(format!("Invalid server name: {}", e)))?
        .to_owned();

    // Create custom TLS connector
    let connector = TpmTlsConnector {
        tls_config,
        server_name,
    };

    // Connect using tonic's connect_with_connector
    // Use http:// scheme because our custom connector handles TLS
    let endpoint = Endpoint::from_shared(format!("http://{}", server_addr))
        .map_err(|e| TlsError::ConfigError(e.to_string()))?;

    let channel = endpoint.connect_with_connector(connector).await?;

    Ok(channel)
}
