package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// AttestationParameters mirrors go-attestation's format for server compatibility
type AttestationParameters struct {
	Public                  []byte `json:"Public"`
	UseTCSDActivationFormat bool   `json:"UseTCSDActivationFormat"`
	CreateData              []byte `json:"CreateData"`
	CreateAttestation       []byte `json:"CreateAttestation"`
	CreateSignature         []byte `json:"CreateSignature"`
}

// EncryptedCredential mirrors go-attestation's format for server compatibility
type EncryptedCredential struct {
	Credential []byte `json:"Credential"`
	Secret     []byte `json:"Secret"`
}

// TPMKey interface for keys that can be used with TPM operations
type TPMKey interface {
	Handle() tpmutil.Handle
	Close() error
}

type TPMClient struct {
	rwc                 io.ReadWriteCloser
	ek                  *client.Key
	srk                 *client.Key
	ak                  TPMKey
	akHandle            tpmutil.Handle
	akPrivBlob          []byte
	akPubBlob           []byte
	akCreationData      []byte
	akCreateAttestation []byte
	akCreateSignature   []byte
	ekCert              *x509.Certificate
	ekHashB64           string
	lakCert             *x509.Certificate
	lakCACert           *x509.Certificate
	lakCACertPEM        string
	tpmDevice           string
}

func NewTPMClient(tpmPath string) (*TPMClient, error) {
	log.Printf("Initializing TPM client")

	if tpmPath == "" {
		tpmPath = "/dev/tpmrm0"
	}

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}

	c := &TPMClient{
		rwc:       rwc,
		tpmDevice: tpmPath,
	}

	// Get EK
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to get EK: %w", err)
	}
	c.ek = ek

	// Get SRK
	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		ek.Close()
		rwc.Close()
		return nil, fmt.Errorf("failed to get SRK: %w", err)
	}
	c.srk = srk
	log.Printf("SRK loaded (handle: 0x%x)", srk.Handle())

	// Load EK certificate
	if err := c.loadEKCertificate(); err != nil {
		log.Printf("Warning: could not load EK certificate: %v", err)
	}

	// Compute EK hash
	if err := c.computeEKHash(); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to compute EK hash: %w", err)
	}
	log.Printf("EK Hash (base64): %s", c.ekHashB64)

	// Load saved blobs
	akPriv, akPub, lakCertPEM, lakCACertPEM, blobsExist, err := LoadBlobs()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to load blobs: %w", err)
	}

	if blobsExist && len(akPriv) > 0 && len(akPub) > 0 && lakCertPEM != "" {
		log.Printf("Loading existing AK from blobs")
		if err := c.loadAKFromBlobs(akPriv, akPub); err != nil {
			log.Printf("Failed to load AK, creating new one: %v", err)
			if err := c.createAK(); err != nil {
				c.Close()
				return nil, fmt.Errorf("failed to create AK: %w", err)
			}
		} else {
			c.akPrivBlob = akPriv
			c.akPubBlob = akPub
			c.loadLAKCertificate(lakCertPEM)
			c.loadLAKCACertificate(lakCACertPEM)
		}
	} else {
		log.Printf("Creating new AK")
		if err := c.createAK(); err != nil {
			c.Close()
			return nil, fmt.Errorf("failed to create AK: %w", err)
		}
	}

	log.Printf("TPM client initialized")
	return c, nil
}

func (c *TPMClient) loadEKCertificate() error {
	ekCertNVIndex := tpmutil.Handle(0x01C00002)
	certDER, err := tpm2.NVReadEx(c.rwc, ekCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return fmt.Errorf("failed to read EK cert from NV: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse EK certificate: %w", err)
	}

	c.ekCert = cert
	return nil
}

func (c *TPMClient) computeEKHash() error {
	var pubKey crypto.PublicKey
	if c.ekCert != nil {
		pubKey = c.ekCert.PublicKey
	} else if c.ek != nil {
		pubKey = c.ek.PublicKey()
	} else {
		return fmt.Errorf("no EK available")
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EK public key: %w", err)
	}
	hash := sha256.Sum256(pubKeyDER)
	c.ekHashB64 = base64.StdEncoding.EncodeToString(hash[:])
	return nil
}

func akTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagRestricted |
			tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

func (c *TPMClient) createAK() error {
	srkHandle := c.srk.Handle()

	privBlob, pubBlob, creationData, creationHash, creationTicket, err := tpm2.CreateKey(
		c.rwc,
		srkHandle,
		tpm2.PCRSelection{},
		"",
		"",
		akTemplate(),
	)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	c.akPrivBlob = privBlob
	c.akPubBlob = pubBlob
	c.akCreationData = creationData

	akHandle, _, err := tpm2.Load(c.rwc, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		return fmt.Errorf("failed to load AK: %w", err)
	}
	c.akHandle = akHandle

	sigScheme := akTemplate().RSAParameters.Sign
	attestation, signature, err := tpm2.CertifyCreation(
		c.rwc,
		"",
		akHandle,
		akHandle,
		nil,
		creationHash,
		*sigScheme,
		creationTicket,
	)
	if err != nil {
		tpm2.FlushContext(c.rwc, akHandle)
		return fmt.Errorf("failed to certify AK creation: %w", err)
	}

	c.akCreateAttestation = attestation
	c.akCreateSignature = signature

	// Use simple wrapper instead of CachedKey to avoid handle leaks
	c.ak = &akKeyWrapper{
		rwc:    c.rwc,
		handle: akHandle,
	}

	log.Printf("AK created and certified (handle: 0x%x)", akHandle)
	return c.saveBlobs()
}

func (c *TPMClient) loadAKFromBlobs(privBlob, pubBlob []byte) error {
	srkHandle := c.srk.Handle()

	akHandle, _, err := tpm2.Load(c.rwc, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		return fmt.Errorf("failed to load AK: %w", err)
	}
	c.akHandle = akHandle

	// Use the loaded handle directly without wrapping in CachedKey
	// CachedKey creates additional handles which can leak
	c.ak = &akKeyWrapper{
		rwc:    c.rwc,
		handle: akHandle,
	}

	log.Printf("AK loaded from blobs (handle: 0x%x)", akHandle)
	return nil
}

// akKeyWrapper wraps a TPM handle for the AK without creating additional resources
type akKeyWrapper struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
}

func (k *akKeyWrapper) Handle() tpmutil.Handle {
	return k.handle
}

func (k *akKeyWrapper) Close() error {
	return tpm2.FlushContext(k.rwc, k.handle)
}

func (c *TPMClient) saveBlobs() error {
	var lakCertPEM string
	if c.lakCert != nil {
		lakCertPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.lakCert.Raw,
		}))
	}
	return SaveBlobs(c.akPrivBlob, c.akPubBlob, lakCertPEM, c.lakCACertPEM)
}

func (c *TPMClient) loadLAKCertificate(lakCertPEM string) {
	block, _ := pem.Decode([]byte(lakCertPEM))
	if block == nil {
		log.Printf("Warning: failed to decode LAK certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Warning: failed to parse LAK certificate: %v", err)
		return
	}

	c.lakCert = cert
}

func (c *TPMClient) loadLAKCACertificate(lakCACertPEM string) {
	if lakCACertPEM == "" {
		return
	}

	block, _ := pem.Decode([]byte(lakCACertPEM))
	if block == nil {
		log.Printf("Warning: failed to decode LAK CA certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Warning: failed to parse LAK CA certificate: %v", err)
		return
	}

	c.lakCACert = cert
	c.lakCACertPEM = lakCACertPEM
}

func (c *TPMClient) GetEKCertificatePEM() string {
	if c.ekCert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.ekCert.Raw,
	}))
}

func (c *TPMClient) GetAKActivationData() (akParams []byte, ekPublic []byte, err error) {
	if c.ak == nil {
		return nil, nil, fmt.Errorf("AK not loaded")
	}

	akPub, _, _, err := tpm2.ReadPublic(c.rwc, c.ak.Handle())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read AK public: %w", err)
	}

	akPubBytes, err := akPub.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AK public: %w", err)
	}

	params := AttestationParameters{
		Public:                  akPubBytes,
		UseTCSDActivationFormat: false,
		CreateData:              c.akCreationData,
		CreateAttestation:       c.akCreateAttestation,
		CreateSignature:         c.akCreateSignature,
	}

	akParams, err = json.Marshal(params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal AK parameters: %w", err)
	}

	var ekPubKey crypto.PublicKey
	if c.ekCert != nil {
		ekPubKey = c.ekCert.PublicKey
	} else if c.ek != nil {
		ekPubKey = c.ek.PublicKey()
	} else {
		return nil, nil, fmt.Errorf("no EK available")
	}

	ekPublic, err = x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal EK public key: %w", err)
	}

	return akParams, ekPublic, nil
}

func (c *TPMClient) ActivateCredentialChallenge(encryptedCredential []byte) ([]byte, error) {
	if c.ak == nil {
		return nil, fmt.Errorf("AK not loaded")
	}
	if c.ek == nil {
		return nil, fmt.Errorf("EK not loaded")
	}

	var encCred EncryptedCredential
	if err := json.Unmarshal(encryptedCredential, &encCred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted credential: %w", err)
	}

	if len(encCred.Credential) < 2 {
		return nil, fmt.Errorf("malformed credential blob")
	}
	credential := encCred.Credential[2:]
	if len(encCred.Secret) < 2 {
		return nil, fmt.Errorf("malformed encrypted secret")
	}
	secret := encCred.Secret[2:]

	sessHandle, _, err := tpm2.StartAuthSession(
		c.rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("creating policy session: %w", err)
	}
	defer tpm2.FlushContext(c.rwc, sessHandle)

	if _, _, err := tpm2.PolicySecret(
		c.rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		sessHandle,
		nil, nil, nil, 0,
	); err != nil {
		return nil, fmt.Errorf("PolicySecret failed: %w", err)
	}

	decryptedSecret, err := tpm2.ActivateCredentialUsingAuth(
		c.rwc,
		[]tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
			{Session: sessHandle, Attributes: tpm2.AttrContinueSession},
		},
		c.ak.Handle(),
		c.ek.Handle(),
		credential,
		secret,
	)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ActivateCredential failed: %w", err)
	}

	log.Printf("Credential activated - AK and EK are in the same TPM")
	return decryptedSecret, nil
}

func (c *TPMClient) SetLAKCertificate(lakCertPEM, lakCACertPEM string) error {
	block, _ := pem.Decode([]byte(lakCertPEM))
	if block == nil {
		return fmt.Errorf("failed to decode LAK certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse LAK certificate: %w", err)
	}

	c.lakCert = cert

	if lakCACertPEM != "" {
		c.lakCACertPEM = lakCACertPEM
		caBlock, _ := pem.Decode([]byte(lakCACertPEM))
		if caBlock != nil {
			if caCert, err := x509.ParseCertificate(caBlock.Bytes); err == nil {
				c.lakCACert = caCert
			}
		}
	}

	return c.saveBlobs()
}

func (c *TPMClient) NeedsLAKProvisioning() bool {
	return c.lakCert == nil
}

// TPM 2.0 constants for attestation
const (
	TPM_GENERATED_VALUE   = 0xff544347
	TPM_ST_ATTEST_CERTIFY = 0x8017
	TPM_ALG_RSA           = 0x0001
	TPM_ALG_SHA256        = 0x000B
	TPM_ALG_NULL          = 0x0010
	TPM_ALG_RSASSA        = 0x0014
)

// CertKey represents a TPM-bound signing key for certificate requests
type CertKey struct {
	handle   tpmutil.Handle
	privBlob []byte
	pubBlob  []byte
	pubKey   *rsa.PublicKey
}

// certKeyTemplate returns the template for a non-restricted signing key
// This key can sign arbitrary data (like CSRs) unlike the restricted AK
func certKeyTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		// Non-restricted signing key: can sign arbitrary data
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

// CreateCertKey creates a new TPM-bound signing key for certificate requests
// Returns the key with its encrypted blobs for persistence
func (c *TPMClient) CreateCertKey() (*CertKey, error) {
	srkHandle := c.srk.Handle()

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(
		c.rwc,
		srkHandle,
		tpm2.PCRSelection{},
		"",
		"",
		certKeyTemplate(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert key: %w", err)
	}

	// Load the key to get its handle
	handle, _, err := tpm2.Load(c.rwc, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert key: %w", err)
	}

	// Read public key
	pub, _, _, err := tpm2.ReadPublic(c.rwc, handle)
	if err != nil {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("failed to read cert key public: %w", err)
	}

	// Extract RSA public key
	rsaPub, err := pub.Key()
	if err != nil {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("failed to extract RSA public key: %w", err)
	}

	rsaPubKey, ok := rsaPub.(*rsa.PublicKey)
	if !ok {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("cert key is not RSA")
	}

	log.Printf("Created TPM-bound cert key (handle: 0x%x)", handle)

	return &CertKey{
		handle:   handle,
		privBlob: privBlob,
		pubBlob:  pubBlob,
		pubKey:   rsaPubKey,
	}, nil
}

// LoadCertKey loads a previously created cert key from its blobs
func (c *TPMClient) LoadCertKey(privBlob, pubBlob []byte) (*CertKey, error) {
	srkHandle := c.srk.Handle()

	handle, _, err := tpm2.Load(c.rwc, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert key: %w", err)
	}

	// Read public key
	pub, _, _, err := tpm2.ReadPublic(c.rwc, handle)
	if err != nil {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("failed to read cert key public: %w", err)
	}

	rsaPub, err := pub.Key()
	if err != nil {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("failed to extract RSA public key: %w", err)
	}

	rsaPubKey, ok := rsaPub.(*rsa.PublicKey)
	if !ok {
		tpm2.FlushContext(c.rwc, handle)
		return nil, fmt.Errorf("cert key is not RSA")
	}

	log.Printf("Loaded TPM-bound cert key (handle: 0x%x)", handle)

	return &CertKey{
		handle:   handle,
		privBlob: privBlob,
		pubBlob:  pubBlob,
		pubKey:   rsaPubKey,
	}, nil
}

// CloseCertKey releases the TPM handle for the cert key
func (c *TPMClient) CloseCertKey(key *CertKey) {
	if key != nil && key.handle != 0 {
		tpm2.FlushContext(c.rwc, key.handle)
	}
}

// GenerateAttestation generates TPM attestation for a cert key using TPM2_Certify
// This follows the WebAuthn TPM attestation format (draft-acme-device-attest-07)
func (c *TPMClient) GenerateAttestation(certKey *CertKey, keyAuthorization string) (string, error) {
	if c.lakCert == nil {
		return "", fmt.Errorf("LAK certificate not available")
	}
	if c.ak == nil {
		return "", fmt.Errorf("AK not loaded")
	}
	if certKey == nil {
		return "", fmt.Errorf("cert key not provided")
	}

	// Compute qualifying data = SHA256(keyAuthorization)
	// Per WebAuthn spec, this goes in extraData field of TPMS_ATTEST
	qualifyingData := sha256.Sum256([]byte(keyAuthorization))

	// Use TPM2_Certify to certify the cert key with the AK
	// This produces TPMS_ATTEST with type TPM_ST_ATTEST_CERTIFY
	certifyInfo, signature, err := tpm2.Certify(
		c.rwc,
		"", // certKey password
		"", // AK password
		certKey.handle,
		c.ak.Handle(),
		qualifyingData[:],
	)
	if err != nil {
		return "", fmt.Errorf("TPM2_Certify failed: %w", err)
	}

	// Build pubArea (TPMT_PUBLIC) for the cert key
	pubArea, err := c.buildPubArea(certKey)
	if err != nil {
		return "", fmt.Errorf("failed to build pubArea: %w", err)
	}

	// Build attestation statement per WebAuthn TPM format
	attStmt := map[string]interface{}{
		"ver":      "2.0",
		"alg":      int64(-257), // RS256 (COSE algorithm)
		"x5c":      [][]byte{c.lakCert.Raw},
		"sig":      signature,   // TPMT_SIGNATURE from TPM2_Certify
		"certInfo": certifyInfo, // TPMS_ATTEST from TPM2_Certify
		"pubArea":  pubArea,     // TPMT_PUBLIC of the certified key
	}

	// Build attestation object (WebAuthn format for TPM attestation)
	// Note: authData is NOT included for TPM attestation - the extraData
	// field in TPMS_ATTEST (certInfo) contains the qualifying data
	attObj := map[string]interface{}{
		"fmt":     "tpm",
		"attStmt": attStmt,
	}

	// Encode as CBOR
	cborBytes, err := cbor.Marshal(attObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CBOR: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(cborBytes), nil
}

// buildPubArea constructs the TPMT_PUBLIC structure for a cert key
func (c *TPMClient) buildPubArea(certKey *CertKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Type (TPM_ALG_RSA)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSA))

	// NameAlg (TPM_ALG_SHA256)
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))

	// ObjectAttributes - non-restricted signing key
	// FlagSign | FlagFixedTPM | FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	attrs := uint32(0x00040072)
	binary.Write(buf, binary.BigEndian, attrs)

	// AuthPolicy (empty TPM2B_DIGEST)
	binary.Write(buf, binary.BigEndian, uint16(0))

	// RSA Parameters (TPMS_RSA_PARMS)
	// symmetric = TPM_ALG_NULL
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_NULL))
	// scheme = RSASSA with SHA256
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_RSASSA))
	binary.Write(buf, binary.BigEndian, uint16(TPM_ALG_SHA256))
	// keyBits
	binary.Write(buf, binary.BigEndian, uint16(certKey.pubKey.N.BitLen()))
	// exponent (0 = default 65537)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Unique (TPM2B_PUBLIC_KEY_RSA) - RSA modulus
	modulus := certKey.pubKey.N.Bytes()
	binary.Write(buf, binary.BigEndian, uint16(len(modulus)))
	buf.Write(modulus)

	return buf.Bytes(), nil
}

// SignCSR signs a CSR using the TPM-bound cert key
func (c *TPMClient) SignCSR(certKey *CertKey, commonName string, sanDNS []string) (string, error) {
	if certKey == nil {
		return "", fmt.Errorf("cert key not provided")
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:           sanDNS,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create a TPM signer that implements crypto.Signer
	signer := &tpmSigner{
		rwc:    c.rwc,
		handle: certKey.handle,
		pub:    certKey.pubKey,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})), nil
}

// tpmSigner implements crypto.Signer for TPM-bound keys
type tpmSigner struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	pub    *rsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *tpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Determine hash algorithm
	var hashAlg tpm2.Algorithm
	switch opts.HashFunc() {
	case crypto.SHA256:
		hashAlg = tpm2.AlgSHA256
	case crypto.SHA384:
		hashAlg = tpm2.AlgSHA384
	case crypto.SHA512:
		hashAlg = tpm2.AlgSHA512
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", opts.HashFunc())
	}

	// Sign using TPM
	sig, err := tpm2.Sign(
		s.rwc,
		s.handle,
		"", // key password
		digest,
		nil, // validation ticket (not needed for non-restricted key)
		&tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: hashAlg,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Sign failed: %w", err)
	}

	// Extract raw signature from TPMT_SIGNATURE
	// For RSASSA, the signature is in sig.RSA.Signature
	if sig.RSA == nil {
		return nil, fmt.Errorf("expected RSA signature")
	}

	return sig.RSA.Signature, nil
}

// GetCertKeyBlobs returns the encrypted blobs for a cert key (for persistence)
func (key *CertKey) GetBlobs() (privBlob, pubBlob []byte) {
	return key.privBlob, key.pubBlob
}

// GetPublicKey returns the RSA public key
func (key *CertKey) GetPublicKey() *rsa.PublicKey {
	return key.pubKey
}

// GetPublicKeyPEM returns the public key in PEM format
func (key *CertKey) GetPublicKeyPEM() string {
	pubDER, err := x509.MarshalPKIXPublicKey(key.pubKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))
}

func (c *TPMClient) GetPermanentID() string {
	return c.ekHashB64
}

func (c *TPMClient) GetLAKCertPEM() string {
	if c.lakCert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.lakCert.Raw,
	}))
}

func (c *TPMClient) GetLAKCACertPEM() string {
	return c.lakCACertPEM
}

func (c *TPMClient) Close() error {
	if c.ak != nil {
		c.ak.Close()
	}
	if c.srk != nil {
		c.srk.Close()
	}
	if c.ek != nil {
		c.ek.Close()
	}
	if c.rwc != nil {
		return c.rwc.Close()
	}
	return nil
}
