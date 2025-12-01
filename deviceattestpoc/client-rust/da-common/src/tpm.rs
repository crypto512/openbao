//! TPM 2.0 operations using rust-tss-esapi high-level abstractions.
//!
//! This module provides functionality for:
//! - EK (Endorsement Key) retrieval and certificate reading
//! - AK (Attestation Key) creation and loading
//! - Credential activation for LAK provisioning
//! - Agent key creation and attestation
//! - TPM signing operations

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::env;
use thiserror::Error;
use tracing::{debug, info, warn};

use std::str::FromStr;
use tss_esapi::{
    abstraction::{
        nv,
        ek::create_ek_object,
        AsymmetricAlgorithmSelection,
    },
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        reserved_handles::Hierarchy,
        session_handles::PolicySession,
        reserved_handles::NvAuth,
    },
    structures::{
        CreationData, Data, Digest as TpmDigest, HashScheme,
        Private, Public, PublicBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme, Signature, SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMS_CREATION_DATA,
    Context,
};

use crate::config::get_tpm_device;
use crate::storage::TpmBlobStorage;

/// NV index for RSA EK certificate (TCG specification)
const RSA_EK_CERT_NV_INDEX: u32 = 0x01C00002;

/// Wrapper for CreationData to implement Marshall trait
/// This is needed because tss-esapi doesn't implement Marshall for CreationData
struct WrappedCreationData(CreationData);

impl Marshall for WrappedCreationData {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPMS_CREATION_DATA>();

    fn marshall(&self) -> tss_esapi::Result<Vec<u8>> {
        let mut buffer = vec![0u8; Self::BUFFER_SIZE];
        let mut offset = 0;

        unsafe {
            tss_esapi::tss2_esys::Tss2_MU_TPMS_CREATION_DATA_Marshal(
                &self.0.clone().into(),
                buffer.as_mut_ptr(),
                Self::BUFFER_SIZE.try_into().expect("BUFFER_SIZE fits in usize"),
                &mut offset,
            )
        };

        let checked_offset = usize::try_from(offset).unwrap_or(0);
        buffer.truncate(checked_offset);
        Ok(buffer)
    }
}

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("TPM error: {0}")]
    TssError(#[from] tss_esapi::Error),

    #[error("failed to parse TCTI configuration: {0}")]
    TctiError(String),

    #[error("EK not available")]
    NoEk,

    #[error("AK not loaded")]
    NoAk,

    #[error("SRK not available")]
    NoSrk,

    #[error("agent key not loaded")]
    NoAgentKey,

    #[error("LAK certificate not available")]
    NoLakCert,

    #[error("failed to read EK certificate from NV")]
    EkCertReadError,

    #[error("invalid key type")]
    InvalidKeyType,

    #[error("storage error: {0}")]
    StorageError(#[from] crate::storage::StorageError),
}

/// Attestation parameters in go-attestation compatible format
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttestationParameters {
    pub public: Vec<u8>,
    pub use_tcsd_activation_format: bool,
    pub create_data: Vec<u8>,
    pub create_attestation: Vec<u8>,
    pub create_signature: Vec<u8>,
}

/// Custom base64 deserialization for byte vectors (Go compatibility)
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Encrypted credential from server (go-attestation compatible format)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedCredential {
    #[serde(with = "base64_bytes")]
    pub credential: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub secret: Vec<u8>,
}

/// TPM client for device attestation operations
pub struct TpmClient {
    context: Context,
    ek_handle: Option<KeyHandle>,
    ek_public: Option<Public>,
    /// Flag indicating EK is from persistent storage (should not be flushed)
    ek_is_persistent: bool,
    srk_handle: Option<KeyHandle>,
    srk_public: Option<Public>,
    /// Flag indicating SRK is from persistent storage (should not be flushed)
    srk_is_persistent: bool,
    ak_handle: Option<KeyHandle>,
    ak_private: Option<Private>,
    ak_public: Option<Public>,
    ak_creation_data: Option<Vec<u8>>,
    ak_create_attestation: Option<Vec<u8>>,
    ak_create_signature: Option<Vec<u8>>,
    ek_cert_der: Option<Vec<u8>>,
    ek_hash_b64: Option<String>,
    lak_cert_pem: Option<String>,
    lak_ca_cert_pem: Option<String>,
    agent_key_handle: Option<KeyHandle>,
    agent_key_private: Option<Private>,
    agent_key_public: Option<Public>,
}

impl TpmClient {
    /// Create a new TPM client for full AK operations
    pub fn new(tpm_path: Option<&str>) -> Result<Self, TpmError> {
        let mut client = Self::new_for_enrollment(tpm_path)?;
        client.initialize_ak()?;
        Ok(client)
    }

    /// Create a new TPM client for enrollment only (no AK creation)
    /// Use this for enrollment check before creating AK
    pub fn new_for_enrollment(tpm_path: Option<&str>) -> Result<Self, TpmError> {
        let tcti_conf = Self::get_tcti_config(tpm_path)?;
        info!("Initializing TPM client with TCTI: {:?}", tcti_conf);

        let context = Context::new(tcti_conf)?;

        let mut client = Self {
            context,
            ek_handle: None,
            ek_public: None,
            ek_is_persistent: false,
            srk_handle: None,
            srk_public: None,
            srk_is_persistent: false,
            ak_handle: None,
            ak_private: None,
            ak_public: None,
            ak_creation_data: None,
            ak_create_attestation: None,
            ak_create_signature: None,
            ek_cert_der: None,
            ek_hash_b64: None,
            lak_cert_pem: None,
            lak_ca_cert_pem: None,
            agent_key_handle: None,
            agent_key_private: None,
            agent_key_public: None,
        };

        // Create EK
        client.create_ek()?;

        // Create SRK
        client.create_srk()?;

        // Try to load EK certificate
        if let Err(e) = client.load_ek_certificate() {
            warn!("Could not load EK certificate: {}", e);
        }

        // Compute EK hash
        client.compute_ek_hash()?;

        // Check if LAK already exists
        if let Ok(Some(storage)) = TpmBlobStorage::load() {
            if let Some(ref lak_cert) = storage.lak_cert_pem {
                client.lak_cert_pem = Some(lak_cert.clone());
            }
            if let Some(ref lak_ca_cert) = storage.lak_ca_cert_pem {
                client.lak_ca_cert_pem = Some(lak_ca_cert.clone());
            }
        }

        info!("TPM client initialized (enrollment mode)");
        Ok(client)
    }

    /// Get TCTI configuration from environment or parameter
    fn get_tcti_config(tpm_path: Option<&str>) -> Result<TctiNameConf, TpmError> {
        // Check for TPM2TOOLS_TCTI environment variable first
        if env::var("TPM2TOOLS_TCTI").is_ok() {
            return TctiNameConf::from_environment_variable()
                .map_err(|e| TpmError::TctiError(e.to_string()));
        }

        // Use provided path or default
        let device = get_tpm_device(tpm_path);

        // Check if it's a swtpm configuration
        if let Ok(swtpm_host) = env::var("TPM_SWTPM_HOST") {
            let port = env::var("TPM_SWTPM_PORT").unwrap_or_else(|_| "2321".to_string());
            let tcti_str = format!("swtpm:host={},port={}", swtpm_host, port);
            return TctiNameConf::from_str(&tcti_str)
                .map_err(|e| TpmError::TctiError(e.to_string()));
        }

        // Default to device
        let tcti_str = format!("device:{}", device);
        TctiNameConf::from_str(&tcti_str)
            .map_err(|e| TpmError::TctiError(e.to_string()))
    }

    /// Persistent handle for EK (standard TCG location, same as go-tpm-tools)
    const PERSISTENT_EK_HANDLE: u32 = 0x81010001;

    /// Create or load the Endorsement Key using the proper TCG specification template
    /// Uses the same approach as go-tpm-tools NewCachedKey:
    /// 1. Try to load from persistent handle first
    /// 2. If not found, create using TCG template and persist it
    fn create_ek(&mut self) -> Result<(), TpmError> {
        use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};

        // Try to load from persistent handle first (like go-tpm-tools does)
        let persistent_tpm_handle = PersistentTpmHandle::new(Self::PERSISTENT_EK_HANDLE)
            .map_err(|e| TpmError::TctiError(format!("invalid persistent handle: {:?}", e)))?;

        // Use tr_from_tpm_public to create ESAPI handle reference for persistent object
        if let Ok(object_handle) = self.context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
        }) {
            let key_handle = KeyHandle::from(object_handle);
            // Try to read public to verify handle is valid
            if let Ok((ek_public, _, _)) = self.context.execute_with_nullauth_session(|ctx| {
                ctx.read_public(key_handle)
            }) {
                info!("EK loaded from persistent handle 0x{:08X}", Self::PERSISTENT_EK_HANDLE);
                self.ek_handle = Some(key_handle);
                self.ek_public = Some(ek_public.clone());
                self.ek_is_persistent = true;

                return Ok(());
            }
        }

        // No persistent EK found - create one and persist it
        info!("Creating EK and persisting to 0x{:08X}", Self::PERSISTENT_EK_HANDLE);

        // Use the proper EK creation from tss-esapi abstraction
        // This uses the exact TCG EK Credential Profile template
        let ek_handle = create_ek_object(
            &mut self.context,
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
            None, // No customization - uses default template
        )?;

        // Read back the public key
        let (ek_public, _, _) = self.context.execute_with_nullauth_session(|ctx| {
            ctx.read_public(ek_handle)
        })?;

        // Persist the EK to the reserved handle (like go-tpm-tools EvictControl)
        use tss_esapi::interface_types::reserved_handles::Provision;
        use tss_esapi::interface_types::data_handles::Persistent;

        let persistent_tpm_handle_for_evict = PersistentTpmHandle::new(Self::PERSISTENT_EK_HANDLE)
            .map_err(|e| TpmError::TctiError(format!("invalid persistent handle: {:?}", e)))?;

        // Note: Go's NewCachedKey uses HandleOwner for EvictControl even for EK
        // (see go-tpm-tools/client/keys.go line 150)
        let persistent_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                ek_handle.into(),
                Persistent::Persistent(persistent_tpm_handle_for_evict),
            )
        })?;

        info!("EK persisted to handle 0x{:08X}", Self::PERSISTENT_EK_HANDLE);

        // Flush the transient handle since we now use the persistent one
        let _ = self.context.flush_context(ek_handle.into());

        self.ek_handle = Some(persistent_handle.into());
        self.ek_public = Some(ek_public);
        self.ek_is_persistent = true;

        debug!("EK created and persisted: {:?}", persistent_handle);
        Ok(())
    }

    /// Persistent handle for SRK (standard TCG location, same as go-tpm-tools)
    const PERSISTENT_SRK_HANDLE: u32 = 0x81000001;

    /// Create or load the Storage Root Key
    /// Uses the same approach as go-tpm-tools NewCachedKey:
    /// 1. Try to load from persistent handle first
    /// 2. If not found, create primary and persist it
    fn create_srk(&mut self) -> Result<(), TpmError> {
        use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};

        // Try to load from persistent handle first (like go-tpm-tools does)
        let persistent_tpm_handle = PersistentTpmHandle::new(Self::PERSISTENT_SRK_HANDLE)
            .map_err(|e| TpmError::TctiError(format!("invalid persistent handle: {:?}", e)))?;

        // Use tr_from_tpm_public to create ESAPI handle reference for persistent object
        if let Ok(object_handle) = self.context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
        }) {
            let key_handle = KeyHandle::from(object_handle);
            // Try to read public to verify handle is valid
            if let Ok((srk_public, _, _)) = self.context.execute_with_nullauth_session(|ctx| {
                ctx.read_public(key_handle)
            }) {
                info!("SRK loaded from persistent handle 0x{:08X}", Self::PERSISTENT_SRK_HANDLE);
                self.srk_handle = Some(key_handle);
                self.srk_public = Some(srk_public);
                self.srk_is_persistent = true;
                return Ok(());
            }
        }

        // No persistent SRK found - create one and persist it
        info!("Creating SRK and persisting to 0x{:08X}", Self::PERSISTENT_SRK_HANDLE);

        // SRK is a restricted decryption key - same template as go-tpm-tools SRKTemplateRSA
        let obj_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()?;

        let srk_public_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(obj_attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_scheme(RsaScheme::Null)
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.restricted())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        let srk_result = self.context.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, srk_public_template, None, None, None, None)
        })?;

        let transient_handle = srk_result.key_handle;
        debug!("SRK created as transient handle: {:?}", transient_handle);

        // Persist the SRK to the reserved handle (like go-tpm-tools EvictControl)
        use tss_esapi::interface_types::reserved_handles::Provision;
        use tss_esapi::interface_types::data_handles::Persistent;

        let persistent_tpm_handle_for_evict = PersistentTpmHandle::new(Self::PERSISTENT_SRK_HANDLE)
            .map_err(|e| TpmError::TctiError(format!("invalid persistent handle: {:?}", e)))?;

        let persistent_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                transient_handle.into(),
                Persistent::Persistent(persistent_tpm_handle_for_evict),
            )
        })?;

        info!("SRK persisted to handle 0x{:08X}", Self::PERSISTENT_SRK_HANDLE);

        // Flush the transient handle since we now use the persistent one
        let _ = self.context.flush_context(transient_handle.into());

        self.srk_handle = Some(persistent_handle.into());
        self.srk_public = Some(srk_result.out_public);
        self.srk_is_persistent = true;
        Ok(())
    }

    /// Load EK certificate from NV index
    fn load_ek_certificate(&mut self) -> Result<(), TpmError> {
        info!("Reading EK certificate from NV index 0x{:08X}", RSA_EK_CERT_NV_INDEX);

        let nv_index = NvIndexTpmHandle::new(RSA_EK_CERT_NV_INDEX)
            .map_err(|_| TpmError::EkCertReadError)?;

        // Read EK certificate from NV
        let cert_der = self.context.execute_with_nullauth_session(|ctx| {
            nv::read_full(ctx, NvAuth::Owner, nv_index)
        })?;

        self.ek_cert_der = Some(cert_der);
        info!("EK certificate loaded");
        Ok(())
    }

    /// Compute EK hash (permanent identifier)
    fn compute_ek_hash(&mut self) -> Result<(), TpmError> {
        // Use stored EK public from create_ek() to avoid read_public validation issues
        let public = self.ek_public.as_ref().ok_or(TpmError::NoEk)?;

        // Get the public key bytes
        let pub_key_der = match public {
            Public::Rsa { unique, .. } => {
                // For RSA, we need to construct PKIX format
                // This is simplified - a full implementation would use proper ASN.1
                unique.as_bytes().to_vec()
            }
            _ => return Err(TpmError::InvalidKeyType),
        };

        // If we have EK cert, use its public key
        let hash_input = if let Some(ref cert_der) = self.ek_cert_der {
            // Parse certificate and get SPKI
            use x509_cert::Certificate;
            use der::{Decode, Encode};
            if let Ok(cert) = Certificate::from_der(cert_der) {
                cert.tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap_or(pub_key_der)
            } else {
                pub_key_der
            }
        } else {
            pub_key_der
        };

        let hash = Sha256::digest(&hash_input);
        self.ek_hash_b64 = Some(BASE64_STANDARD.encode(hash));

        info!("EK Hash (base64): {}", self.ek_hash_b64.as_ref().expect("EK hash was just set"));
        Ok(())
    }

    /// Initialize AK (create or load from storage)
    pub fn initialize_ak(&mut self) -> Result<(), TpmError> {
        // Try to load from storage
        if let Ok(Some(storage)) = TpmBlobStorage::load() {
            if let Ok(Some((ak_priv, ak_pub))) = storage.get_ak_blobs() {
                if storage.lak_cert_pem.is_some() {
                    info!("Loading existing AK from blobs");
                    match self.load_ak_from_blobs(&ak_priv, &ak_pub) {
                        Ok(_) => {
                            self.lak_cert_pem = storage.lak_cert_pem.clone();
                            self.lak_ca_cert_pem = storage.lak_ca_cert_pem.clone();
                            // Load creation data if available
                            if let Ok(Some((cd, att, sig))) = storage.get_ak_creation_data() {
                                self.ak_creation_data = Some(cd);
                                self.ak_create_attestation = Some(att);
                                self.ak_create_signature = Some(sig);
                            }
                            info!("AK loaded from blobs");
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("Failed to load AK, creating new one: {}", e);
                        }
                    }
                }
            }
        }

        // Create new AK
        info!("Creating new AK");
        self.create_ak()?;
        info!("AK initialized");
        Ok(())
    }

    /// Create a new Attestation Key under SRK (like Go client does)
    /// This is a restricted signing key for LAK provisioning
    fn create_ak(&mut self) -> Result<(), TpmError> {
        let srk_handle = self.srk_handle.ok_or(TpmError::NoSrk)?;

        // AK template: restricted signing key (like Go's akTemplate)
        // Attributes: FlagSignerDefault | FlagRestricted | FlagFixedTPM | FlagFixedParent |
        //            FlagSensitiveDataOrigin | FlagUserWithAuth
        let obj_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)  // Restricted signing key
            .with_sign_encrypt(true)
            .build()?;

        let ak_public_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(obj_attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(true)
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        // Create the AK under SRK (like Go's tpm2.CreateKey with srkHandle)
        let result = self.context.execute_with_nullauth_session(|ctx| {
            ctx.create(srk_handle, ak_public_template, None, None, None, None)
        })?;

        let ak_private = result.out_private.clone();
        let ak_public = result.out_public.clone();

        // Marshall creation data
        let creation_data_bytes = WrappedCreationData(result.creation_data)
            .marshall()
            .map_err(|e| TpmError::TctiError(format!("Failed to marshall creation data: {}", e)))?;

        // Load the AK under SRK (like Go's tpm2.Load with srkHandle)
        let ak_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.load(srk_handle, ak_private.clone(), ak_public.clone())
        })?;

        // Certify the AK creation to prove it was genuinely created in the TPM
        let sig_scheme = SignatureScheme::RsaSsa {
            scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };

        let (attest, signature) = self.context.execute_with_nullauth_session(|ctx| {
            ctx.certify_creation(
                ak_handle,
                ak_handle.into(),
                Vec::new().try_into().expect("qualifying_data"),
                result.creation_hash,
                sig_scheme,
                result.creation_ticket,
            )
        })?;

        self.ak_private = Some(ak_private);
        self.ak_public = Some(ak_public);
        self.ak_handle = Some(ak_handle);
        self.ak_creation_data = Some(creation_data_bytes);
        self.ak_create_attestation = Some(attest.marshall()?);
        self.ak_create_signature = Some(signature.marshall()?);

        debug!("AK created under SRK, loaded and certified: {:?}", ak_handle);

        // Save blobs
        self.save_blobs()?;

        Ok(())
    }

    /// Load AK from saved blobs
    fn load_ak_from_blobs(&mut self, priv_blob: &[u8], pub_blob: &[u8]) -> Result<(), TpmError> {
        let srk_handle = self.srk_handle.ok_or(TpmError::NoSrk)?;

        // Deserialize blobs
        let private = Private::unmarshall(priv_blob)?;
        let public = Public::unmarshall(pub_blob)?;

        let ak_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.load(srk_handle, private.clone(), public.clone())
        })?;

        self.ak_handle = Some(ak_handle);
        self.ak_private = Some(private);
        self.ak_public = Some(public);

        debug!("AK loaded from blobs: {:?}", ak_handle);
        Ok(())
    }

    /// Save AK blobs to storage
    fn save_blobs(&self) -> Result<(), TpmError> {
        let ak_priv = self.ak_private.as_ref().ok_or(TpmError::NoAk)?;
        let ak_pub = self.ak_public.as_ref().ok_or(TpmError::NoAk)?;

        let priv_bytes = ak_priv.marshall()?;
        let pub_bytes = ak_pub.marshall()?;

        // Load existing storage to preserve other data
        let mut storage = crate::storage::TpmBlobStorage::load()
            .map_err(|e| TpmError::TctiError(format!("Failed to load storage: {}", e)))?
            .unwrap_or_else(crate::storage::TpmBlobStorage::new);

        storage.set_ak_blobs(&priv_bytes, &pub_bytes);
        storage.lak_cert_pem = self.lak_cert_pem.clone();
        storage.lak_ca_cert_pem = self.lak_ca_cert_pem.clone();

        // Save creation data if available
        if let (Some(cd), Some(att), Some(sig)) = (
            &self.ak_creation_data,
            &self.ak_create_attestation,
            &self.ak_create_signature,
        ) {
            storage.set_ak_creation_data(cd, att, sig);
        }

        storage.save()
            .map_err(|e| TpmError::TctiError(format!("Failed to save storage: {}", e)))?;

        Ok(())
    }

    /// Get EK certificate in PEM format
    pub fn get_ek_certificate_pem(&self) -> Option<String> {
        self.ek_cert_der.as_ref().map(|der| {
            let pem_data = pem::Pem::new("CERTIFICATE", der.clone());
            pem::encode(&pem_data)
        })
    }

    /// Get permanent identifier (EK hash)
    pub fn get_permanent_id(&self) -> Option<&str> {
        self.ek_hash_b64.as_deref()
    }

    /// Check if LAK provisioning is needed
    pub fn needs_lak_provisioning(&self) -> bool {
        self.lak_cert_pem.is_none()
    }

    /// Check if agent provisioning is needed
    pub fn needs_agent_provisioning(&self) -> bool {
        !crate::storage::agent_blobs_exist()
    }

    /// Get AK activation data for credential challenge
    pub fn get_ak_activation_data(&mut self) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
        // Use stored AK public to avoid read_public validation issues
        let ak_public = self.ak_public.as_ref().ok_or(TpmError::NoAk)?;
        let ak_pub_bytes = ak_public.marshall()?;

        // Build attestation parameters
        let params = AttestationParameters {
            public: ak_pub_bytes,
            use_tcsd_activation_format: false,
            create_data: self.ak_creation_data.clone().unwrap_or_default(),
            create_attestation: self.ak_create_attestation.clone().unwrap_or_default(),
            create_signature: self.ak_create_signature.clone().unwrap_or_default(),
        };

        let ak_params = serde_json::to_vec(&params)
            .map_err(|e| TpmError::TctiError(e.to_string()))?;

        let ek_pub_der = if let Some(ref cert_der) = self.ek_cert_der {
            use x509_cert::Certificate;
            use der::{Decode, Encode};
            info!("Extracting EK public from certificate ({} bytes)", cert_der.len());
            if let Ok(cert) = Certificate::from_der(cert_der) {
                cert.tbs_certificate.subject_public_key_info.to_der().unwrap_or_default()
            } else {
                warn!("Failed to parse EK certificate");
                return Err(TpmError::TctiError("Failed to parse EK certificate".into()));
            }
        } else {
            // No EK certificate available - this shouldn't happen with proper TPM setup
            return Err(TpmError::TctiError("EK certificate required for enrollment".into()));
        };

        Ok((ak_params, ek_pub_der))
    }

    /// Activate credential challenge
    /// Follows the Go client approach from tpm_client.go:ActivateCredentialChallenge
    pub fn activate_credential(&mut self, encrypted_credential: &[u8]) -> Result<Vec<u8>, TpmError> {
        use tss_esapi::handles::SessionHandle;
        use tss_esapi::structures::{IdObject, EncryptedSecret, SymmetricDefinition};

        let ak_handle = self.ak_handle.ok_or(TpmError::NoAk)?;
        let ek_handle = self.ek_handle.ok_or(TpmError::NoEk)?;

        // Parse encrypted credential
        let enc_cred: EncryptedCredential = serde_json::from_slice(encrypted_credential)
            .map_err(|e| TpmError::TctiError(format!("failed to parse credential: {}", e)))?;

        // Strip 2-byte length prefix from blobs (go-attestation format)
        if enc_cred.credential.len() <= 2 {
            return Err(TpmError::TctiError("malformed credential blob".into()));
        }
        if enc_cred.secret.len() <= 2 {
            return Err(TpmError::TctiError("malformed secret blob".into()));
        }

        // Use try_from(Vec<u8>) for parsing
        let id_object = IdObject::try_from(enc_cred.credential[2..].to_vec())
            .map_err(|e| TpmError::TctiError(format!("failed to parse IdObject: {:?}", e)))?;
        let encrypted_secret = EncryptedSecret::try_from(enc_cred.secret[2..].to_vec())
            .map_err(|e| TpmError::TctiError(format!("failed to parse EncryptedSecret: {:?}", e)))?;

        // Create password (HMAC) session for AK authorization
        // AK has UserWithAuth attribute, so it accepts password auth
        let ak_session = self.context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?.ok_or_else(|| TpmError::TctiError("failed to create HMAC session for AK".into()))?;

        // Create policy session for endorsement hierarchy (EK)
        // Go: tpm2.StartAuthSession with SessionPolicy
        let policy_session = self.context.start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Null,  // Go uses AlgNull for symmetric
            HashingAlgorithm::Sha256,
        )?.ok_or_else(|| TpmError::TctiError("failed to create policy session for EK".into()))?;

        // Apply policy secret for endorsement hierarchy
        // Go: tpm2.PolicySecret(rwc, HandleEndorsement, ...)
        self.context.execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                PolicySession::try_from(policy_session).expect("policy session conversion"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })?;

        // Activate credential:
        // Go: tpm2.ActivateCredentialUsingAuth with:
        //   - first auth: password session for AK
        //   - second auth: policy session for EK
        let decrypted = self.context.execute_with_sessions(
            (Some(ak_session), Some(policy_session), None),
            |ctx| {
                ctx.activate_credential(ak_handle, ek_handle, id_object.clone(), encrypted_secret.clone())
            },
        )?;

        // Clean up sessions
        self.context.flush_context(SessionHandle::from(ak_session).into())?;
        self.context.flush_context(SessionHandle::from(policy_session).into())?;

        info!("Credential activated - AK and EK are in the same TPM");
        Ok(decrypted.as_slice().to_vec())
    }

    /// Set LAK certificate
    pub fn set_lak_certificate(
        &mut self,
        lak_cert_pem: &str,
        lak_ca_cert_pem: Option<&str>,
    ) -> Result<(), TpmError> {
        self.lak_cert_pem = Some(lak_cert_pem.to_string());
        self.lak_ca_cert_pem = lak_ca_cert_pem.map(String::from);
        self.save_blobs()?;
        Ok(())
    }

    /// Get LAK certificate PEM
    pub fn get_lak_cert_pem(&self) -> Option<&str> {
        self.lak_cert_pem.as_deref()
    }

    /// Get LAK CA certificate PEM
    pub fn get_lak_ca_cert_pem(&self) -> Option<&str> {
        self.lak_ca_cert_pem.as_deref()
    }

    /// Create a non-restricted signing key for agent certificate
    pub fn create_agent_key(&mut self) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
        let srk_handle = self.srk_handle.ok_or(TpmError::NoSrk)?;

        // Agent key template: non-restricted signing key with flexible scheme
        let key_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_sign_encrypt(true)
                    // NOT restricted - can sign arbitrary data
                    .build()?,
            )
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_scheme(RsaScheme::Null) // Flexible scheme
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        let result = self.context.execute_with_nullauth_session(|ctx| {
            ctx.create(srk_handle, key_public, None, None, None, None)
        })?;

        self.agent_key_private = Some(result.out_private.clone());
        self.agent_key_public = Some(result.out_public.clone());

        // Load the key
        let key_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.load(srk_handle, result.out_private.clone(), result.out_public.clone())
        })?;

        self.agent_key_handle = Some(key_handle);

        let priv_bytes = result.out_private.marshall()?;
        let pub_bytes = result.out_public.marshall()?;

        info!("Agent key created: {:?}", key_handle);
        Ok((priv_bytes, pub_bytes))
    }

    /// Load agent key from blobs
    pub fn load_agent_key(&mut self, priv_blob: &[u8], pub_blob: &[u8]) -> Result<(), TpmError> {
        let srk_handle = self.srk_handle.ok_or(TpmError::NoSrk)?;

        let private = Private::unmarshall(priv_blob)?;
        let public = Public::unmarshall(pub_blob)?;

        let key_handle = self.context.execute_with_nullauth_session(|ctx| {
            ctx.load(srk_handle, private.clone(), public.clone())
        })?;

        self.agent_key_handle = Some(key_handle);
        self.agent_key_private = Some(private);
        self.agent_key_public = Some(public);

        info!("Agent key loaded: {:?}", key_handle);
        Ok(())
    }

    /// Close agent key handle
    pub fn close_agent_key(&mut self) {
        if let Some(handle) = self.agent_key_handle.take() {
            let _ = self.context.flush_context(handle.into());
        }
        self.agent_key_private = None;
        self.agent_key_public = None;
    }

    /// Close AK handle
    pub fn close_ak(&mut self) {
        if let Some(handle) = self.ak_handle.take() {
            let _ = self.context.flush_context(handle.into());
        }
    }

    /// Generate attestation for agent key using TPM2_Certify
    pub fn generate_attestation(&mut self, key_authorization: &str) -> Result<String, TpmError> {
        let ak_handle = self.ak_handle.ok_or(TpmError::NoAk)?;
        let agent_key_handle = self.agent_key_handle.ok_or(TpmError::NoAgentKey)?;
        let lak_cert_pem = self.lak_cert_pem.as_ref().ok_or(TpmError::NoLakCert)?;

        // Compute qualifying data = SHA256(keyAuthorization)
        let qualifying_data = Sha256::digest(key_authorization.as_bytes());
        let data = Data::try_from(qualifying_data.to_vec())?;

        // TPM2_Certify - requires two auth sessions (one for object, one for signing key)
        use tss_esapi::interface_types::session_handles::AuthSession;

        let (attest, signature) = self.context.execute_with_sessions(
            (Some(AuthSession::Password), Some(AuthSession::Password), None),
            |ctx| {
                ctx.certify(
                    agent_key_handle.into(),
                    ak_handle,
                    data,
                    SignatureScheme::RsaSsa {
                        scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                )
            },
        )?;

        // Get pubArea (TPMT_PUBLIC) for the agent key - use stored public
        let agent_public = self.agent_key_public.as_ref().ok_or(TpmError::NoAgentKey)?;
        let pub_area = agent_public.marshall()?;

        // Get LAK cert DER
        let lak_cert_der = {
            let pem_obj = pem::parse(lak_cert_pem)
                .map_err(|e| TpmError::TctiError(format!("failed to parse LAK cert: {}", e)))?;
            pem_obj.into_contents()
        };

        // Build WebAuthn TPM attestation object
        let sig_bytes = signature.marshall()?;
        let attest_bytes = attest.marshall()?;

        let att_stmt = std::collections::BTreeMap::from([
            ("ver".to_string(), ciborium::Value::Text("2.0".to_string())),
            ("alg".to_string(), ciborium::Value::Integer((-257).into())), // RS256
            ("x5c".to_string(), ciborium::Value::Array(vec![
                ciborium::Value::Bytes(lak_cert_der),
            ])),
            ("sig".to_string(), ciborium::Value::Bytes(sig_bytes)),
            ("certInfo".to_string(), ciborium::Value::Bytes(attest_bytes)),
            ("pubArea".to_string(), ciborium::Value::Bytes(pub_area)),
        ]);

        let att_obj = std::collections::BTreeMap::from([
            ("fmt".to_string(), ciborium::Value::Text("tpm".to_string())),
            ("attStmt".to_string(), ciborium::Value::Map(
                att_stmt.into_iter().map(|(k, v)| (ciborium::Value::Text(k), v)).collect()
            )),
        ]);

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(
            att_obj.into_iter().map(|(k, v)| (ciborium::Value::Text(k), v)).collect()
        ), &mut cbor_bytes)
            .map_err(|e| TpmError::TctiError(format!("CBOR encode error: {}", e)))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes))
    }

    /// Sign a CSR using the agent key with rcgen + TPM signing
    pub fn sign_csr(&mut self, common_name: &str, _san_dns: &[String]) -> Result<String, TpmError> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use rsa::pkcs1::EncodeRsaPublicKey;

        let agent_key_handle = self.agent_key_handle.ok_or(TpmError::NoAgentKey)?;
        let public = self.agent_key_public.as_ref().ok_or(TpmError::NoAgentKey)?;

        // Extract RSA public key modulus and exponent
        let (modulus, exponent) = match public {
            Public::Rsa { unique, parameters, .. } => {
                let exp = parameters.exponent().value();
                // TPM returns 0 for default exponent (65537)
                let exp = if exp == 0 { 65537u32 } else { exp };
                let mod_bytes = unique.as_bytes().to_vec();
                debug!("Agent key modulus: {} bytes", mod_bytes.len());
                debug!("Agent key exponent: {}", exp);
                (mod_bytes, exp)
            }
            _ => return Err(TpmError::InvalidKeyType),
        };

        // Build RSA public key
        let rsa_pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&modulus),
            rsa::BigUint::from(exponent),
        ).map_err(|e| TpmError::TctiError(format!("failed to build RSA key: {}", e)))?;

        // Get PKCS#1 RSAPublicKey DER (NOT SPKI - rcgen/ring expects PKCS#1 format)
        let pkcs1_der = rsa_pub_key.to_pkcs1_der()
            .map_err(|e| TpmError::TctiError(format!("failed to encode public key: {}", e)))?;
        debug!("PKCS#1 RSAPublicKey DER: {} bytes", pkcs1_der.as_bytes().len());

        // Create TPM signer wrapper
        // Safety: context is borrowed for duration of this function only
        let tpm_signer = unsafe {
            TpmSigningKey::new(
                &mut self.context as *mut Context,
                agent_key_handle,
                pkcs1_der.as_bytes().to_vec(),
            )
        };

        // Create KeyPair from remote signer
        let key_pair = KeyPair::from_remote(Box::new(tpm_signer))
            .map_err(|e| TpmError::TctiError(format!("failed to create key pair: {}", e)))?;

        // Build CSR params
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Serialize CSR with TPM signing
        let csr = params.serialize_request(&key_pair)
            .map_err(|e| TpmError::TctiError(format!("failed to create CSR: {}", e)))?;

        let csr_pem = csr.pem()
            .map_err(|e| TpmError::TctiError(format!("failed to encode CSR: {}", e)))?;

        info!("CSR generated for CN={}", common_name);
        debug!("CSR PEM:\n{}", csr_pem);
        Ok(csr_pem)
    }

    /// Sign data with agent key
    pub fn sign_with_agent_key(&mut self, digest: &[u8]) -> Result<Vec<u8>, TpmError> {
        let agent_key_handle = self.agent_key_handle.ok_or(TpmError::NoAgentKey)?;

        // Convert digest to fixed-size array for SHA256 (32 bytes)
        let digest_array: [u8; 32] = digest.try_into()
            .map_err(|_| TpmError::InvalidKeyType)?;
        let tpm_digest = TpmDigest::from(digest_array);

        use tss_esapi::structures::HashcheckTicket;
        let signature = self.context.execute_with_nullauth_session(|ctx| {
            ctx.sign(
                agent_key_handle,
                tpm_digest,
                SignatureScheme::RsaSsa {
                    scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                None::<HashcheckTicket>,
            )
        })?;

        // Extract raw signature from TPMT_SIGNATURE
        // For RSASSA, extract the signature value
        match signature {
            Signature::RsaSsa(rsa_sig) => Ok(rsa_sig.signature().to_vec()),
            _ => Err(TpmError::InvalidKeyType),
        }
    }

    /// Get agent key public key
    pub fn get_agent_public_key(&self) -> Option<&Public> {
        self.agent_key_public.as_ref()
    }

    /// Explicitly close all TPM handles
    /// Call this before dropping to ensure handles are flushed
    /// Note: Persistent handles (EK at 0x81010001, SRK at 0x81000001) are not flushed
    pub fn close(&mut self) {
        if let Some(handle) = self.agent_key_handle.take() {
            debug!("Flushing agent key handle: {:?}", handle);
            let _ = self.context.flush_context(handle.into());
        }
        if let Some(handle) = self.ak_handle.take() {
            debug!("Flushing AK handle: {:?}", handle);
            let _ = self.context.flush_context(handle.into());
        }
        if let Some(handle) = self.srk_handle.take() {
            if !self.srk_is_persistent {
                debug!("Flushing SRK handle: {:?}", handle);
                let _ = self.context.flush_context(handle.into());
            } else {
                debug!("Skipping flush of persistent SRK handle: {:?}", handle);
            }
        }
        if let Some(handle) = self.ek_handle.take() {
            if !self.ek_is_persistent {
                debug!("Flushing EK handle: {:?}", handle);
                let _ = self.context.flush_context(handle.into());
            } else {
                debug!("Skipping flush of persistent EK handle: {:?}", handle);
            }
        }
        info!("All TPM handles flushed");
    }
}

impl Drop for TpmClient {
    fn drop(&mut self) {
        // Flush any remaining handles
        self.close();
    }
}

/// TPM signing key wrapper for rcgen
/// Implements rcgen's RemoteKeyPair trait to use TPM for signing
/// Uses raw pointer to avoid lifetime issues with rcgen's 'static requirement
pub struct TpmSigningKey {
    context: *mut Context,
    handle: KeyHandle,
    spki_der: Vec<u8>,
}

// Safety: TpmSigningKey is only used within the scope of sign_csr
// The Context is borrowed mutably for the duration of the function
unsafe impl Send for TpmSigningKey {}
unsafe impl Sync for TpmSigningKey {}

impl TpmSigningKey {
    /// Create a new TPM signing key wrapper
    /// # Safety
    /// The context pointer must remain valid for the lifetime of this struct
    pub unsafe fn new(context: *mut Context, handle: KeyHandle, spki_der: Vec<u8>) -> Self {
        Self { context, handle, spki_der }
    }
}

impl rcgen::RemoteKeyPair for TpmSigningKey {
    fn public_key(&self) -> &[u8] {
        &self.spki_der
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Hash the message with SHA256
        let digest = Sha256::digest(msg);
        let digest_array: [u8; 32] = digest.into();
        let tpm_digest = TpmDigest::from(digest_array);

        // Sign with TPM
        let ctx = unsafe { &mut *self.context };

        use tss_esapi::structures::HashcheckTicket;
        let signature = ctx.execute_with_nullauth_session(|ctx| {
            ctx.sign(
                self.handle,
                tpm_digest,
                SignatureScheme::RsaSsa {
                    scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                None::<HashcheckTicket>,
            )
        }).map_err(|_| rcgen::Error::CouldNotParseCertificate)?;

        // Extract signature bytes
        match signature {
            Signature::RsaSsa(rsa_sig) => Ok(rsa_sig.signature().to_vec()),
            _ => Err(rcgen::Error::CouldNotParseCertificate),
        }
    }
}
