package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
)

type OpenBaoClient struct {
	baseURL        string
	token          string
	httpClient     *http.Client
	accountManager *ACMEAccountManager
}

type ACMEOrder struct {
	OrderID           string
	AuthorizationURL  string
	ChallengeURL      string
	ChallengeToken    string
	AccountThumbprint string
	FinalizeURL       string
	CertificateURL    string
}

func NewOpenBaoClient(baseURL, token string, database *db.DB) (*OpenBaoClient, error) {
	accountManager, err := NewACMEAccountManager(database)
	if err != nil {
		return nil, fmt.Errorf("failed to create account manager: %w", err)
	}

	client := &OpenBaoClient{
		baseURL:        strings.TrimSuffix(baseURL, "/"),
		token:          token,
		httpClient:     &http.Client{},
		accountManager: accountManager,
	}

	log.Printf("OpenBao client initialized with database-backed account persistence")
	return client, nil
}

// isAuthError returns true if the response indicates an authentication failure
func isAuthError(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
}

// refreshToken re-reads the token from environment variable or keys file
func (c *OpenBaoClient) refreshToken() error {
	token := os.Getenv("BAO_TOKEN")
	if token == "" {
		// Try to read from keys file
		keysFile := os.Getenv("BAO_KEYS_FILE")
		if keysFile == "" {
			return fmt.Errorf("BAO_TOKEN not set and BAO_KEYS_FILE not specified")
		}
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return fmt.Errorf("failed to read keys file: %w", err)
		}
		var keys struct {
			RootToken string `json:"root_token"`
		}
		if err := json.Unmarshal(data, &keys); err != nil {
			return fmt.Errorf("failed to parse keys file: %w", err)
		}
		if keys.RootToken == "" {
			return fmt.Errorf("root_token not found in keys file")
		}
		token = keys.RootToken
	}
	c.token = token
	return nil
}

// doWithRetry executes an HTTP request with automatic retry on auth failures
func (c *OpenBaoClient) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	const maxRetries = 2

	for attempt := 0; attempt <= maxRetries; attempt++ {
		reqCopy := req.Clone(ctx)
		reqCopy.Header.Set("X-Vault-Token", c.token)

		resp, err := c.httpClient.Do(reqCopy)
		if err != nil {
			return nil, err
		}

		if !isAuthError(resp) {
			return resp, nil
		}

		resp.Body.Close()
		log.Printf("Auth error (attempt %d/%d), refreshing token and clearing cache", attempt+1, maxRetries+1)

		if err := c.refreshToken(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		c.accountManager.ClearAccounts()
	}

	return nil, fmt.Errorf("auth failed after %d retries", maxRetries+1)
}

// ensureACMEAccount ensures an ACME account exists for the given PKI path
func (c *OpenBaoClient) ensureACMEAccount(pkiPath string) (*ACMEAccount, error) {
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return nil, err
	}

	// If account URL is not set, register with OpenBao
	if account.AccountURL == "" {
		directory, err := c.getACMEDirectoryForPath(pkiPath)
		if err != nil {
			return nil, err
		}

		payload := map[string]interface{}{
			"termsOfServiceAgreed": true,
			"contact":              []string{},
		}
		payloadBytes, _ := json.Marshal(payload)

		jws, err := c.buildJWSWithAccount(directory.NewAccount, "", payloadBytes, true, account)
		if err != nil {
			return nil, err
		}

		resp, err := http.Post(directory.NewAccount, "application/jose+json", strings.NewReader(jws))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("account creation failed: %s", string(body))
		}

		accountURL := resp.Header.Get("Location")
		if err := c.accountManager.SetAccountURL(pkiPath, accountURL); err != nil {
			log.Printf("Warning: failed to persist account URL: %v", err)
		}
		account.AccountURL = accountURL
		log.Printf("ACME account registered for %s: %s", pkiPath, accountURL)
	}

	return account, nil
}

func (c *OpenBaoClient) CreateACMEOrder(ctx context.Context, req *CertRequest) (*ACMEOrder, error) {
	// Get PKI configuration for this usage
	usageConfig, err := GetUsageConfig(req.Usage)
	if err != nil {
		return nil, err
	}
	pkiPath := usageConfig.GetACMEPath()

	// Retry loop for ACME account recovery
	const maxRetries = 2
	for attempt := 0; attempt <= maxRetries; attempt++ {
		order, err := c.createACMEOrderOnce(ctx, pkiPath, req.PermanentIdentifier)
		if err == nil {
			return order, nil
		}

		// Check if this is an account-not-found error
		if strings.Contains(err.Error(), "accountDoesNotExist") || strings.Contains(err.Error(), "account not found") {
			log.Printf("ACME account not found (attempt %d/%d), re-registering...", attempt+1, maxRetries+1)
			if clearErr := c.accountManager.ClearAccountURL(pkiPath); clearErr != nil {
				log.Printf("Warning: failed to clear account URL: %v", clearErr)
			}
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("ACME order creation failed after %d retries", maxRetries+1)
}

func (c *OpenBaoClient) createACMEOrderOnce(ctx context.Context, pkiPath, permanentIdentifier string) (*ACMEOrder, error) {
	// Ensure we have an account for this PKI
	account, err := c.ensureACMEAccount(pkiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure ACME account: %w", err)
	}

	directory, err := c.getACMEDirectoryForPath(pkiPath)
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "permanent-identifier", "value": permanentIdentifier},
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWSWithAccount(directory.NewOrder, account.AccountURL, payloadBytes, false, account)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(directory.NewOrder, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("order creation failed: %s", string(body))
	}

	orderURL := resp.Header.Get("Location")

	var orderResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		return nil, err
	}

	authorizations := orderResp["authorizations"].([]interface{})
	if len(authorizations) == 0 {
		return nil, fmt.Errorf("no authorizations in order")
	}
	authzURL := authorizations[0].(string)

	authz, err := c.getAuthorizationWithAccount(authzURL, account)
	if err != nil {
		return nil, err
	}

	var challengeURL, challengeToken string
	for _, ch := range authz.Challenges {
		if ch.Type == "device-attest-01" {
			challengeURL = ch.URL
			challengeToken = ch.Token
			break
		}
	}

	if challengeURL == "" {
		return nil, fmt.Errorf("no device-attest-01 challenge found")
	}

	return &ACMEOrder{
		OrderID:           orderURL,
		AuthorizationURL:  authzURL,
		ChallengeURL:      challengeURL,
		ChallengeToken:    challengeToken,
		AccountThumbprint: account.Thumbprint,
		FinalizeURL:       orderResp["finalize"].(string),
	}, nil
}

// extractPKIPathFromURL extracts the PKI path from an ACME URL
// e.g., http://openbao:8200/v1/pki-agent/roles/agent/acme/order/xxx -> pki-agent/roles/agent
func extractPKIPathFromURL(acmeURL string) string {
	// Find /v1/ and then extract until /acme/
	idx := strings.Index(acmeURL, "/v1/")
	if idx == -1 {
		return "pki-agent/roles/agent" // default fallback
	}
	rest := acmeURL[idx+4:] // after /v1/
	acmeIdx := strings.Index(rest, "/acme/")
	if acmeIdx == -1 {
		return "pki-agent/roles/agent" // default fallback
	}
	return rest[:acmeIdx]
}

func (c *OpenBaoClient) SubmitAttestation(ctx context.Context, challengeURL, attestationObject string) error {
	pkiPath := extractPKIPathFromURL(challengeURL)
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}

	payload := map[string]interface{}{"attObj": attestationObject}
	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWSWithAccount(challengeURL, account.AccountURL, payloadBytes, false, account)
	if err != nil {
		return err
	}

	resp, err := http.Post(challengeURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("attestation submission failed: %s", string(body))
	}

	return nil
}

func (c *OpenBaoClient) GetOrderStatus(ctx context.Context, orderURL string) (string, error) {
	pkiPath := extractPKIPathFromURL(orderURL)
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return "", fmt.Errorf("failed to get account: %w", err)
	}

	jws, err := c.buildJWSWithAccount(orderURL, account.AccountURL, []byte(""), false, account)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(orderURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var orderResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		return "", err
	}

	return orderResp["status"].(string), nil
}

func (c *OpenBaoClient) FinalizeOrder(ctx context.Context, finalizeURL, csrPEM string) error {
	pkiPath := extractPKIPathFromURL(finalizeURL)
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}

	csrDER, err := pemToBase64URL(csrPEM)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{"csr": csrDER}
	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWSWithAccount(finalizeURL, account.AccountURL, payloadBytes, false, account)
	if err != nil {
		return err
	}

	resp, err := http.Post(finalizeURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("finalize failed: %s", string(body))
	}

	return nil
}

func (c *OpenBaoClient) GetCertificate(ctx context.Context, orderURL string) (string, []string, error) {
	pkiPath := extractPKIPathFromURL(orderURL)
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get account: %w", err)
	}

	jws, err := c.buildJWSWithAccount(orderURL, account.AccountURL, []byte(""), false, account)
	if err != nil {
		return "", nil, err
	}

	resp, err := http.Post(orderURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	var orderResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &orderResp); err != nil {
		return "", nil, err
	}

	if orderResp["status"].(string) != "valid" {
		return "", nil, fmt.Errorf("order status is %s", orderResp["status"])
	}

	certificateURL := orderResp["certificate"].(string)

	jws, err = c.buildJWSWithAccount(certificateURL, account.AccountURL, []byte(""), false, account)
	if err != nil {
		return "", nil, err
	}

	resp, err = http.Post(certificateURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	certPEM, _ := io.ReadAll(resp.Body)
	return string(certPEM), []string{}, nil
}

func (c *OpenBaoClient) SignLAKCertificate(
	ctx context.Context,
	ekHashBase64 string,
	csrPEM string,
) (lakCertPEM, lakRootCAPEM string, err error) {
	log.Printf("Issuing LAK certificate for EK hash: %s", ekHashBase64)

	if csrPEM == "" {
		return "", "", fmt.Errorf("CSR is required")
	}

	// sign-verbatim uses SANs from CSR when UseCSRSANs=true
	// The CSR already contains the SAN URI, so we don't need to pass it here
	signPayload := map[string]interface{}{
		"csr":                csrPEM,
		"ttl":                "8760h",
		"key_usage":          []string{"DigitalSignature"},
		"ext_key_usage_oids": []string{"2.23.133.8.3"},
	}

	signPayloadJSON, _ := json.Marshal(signPayload)

	signURL := fmt.Sprintf("%s/v1/pki-ak/sign-verbatim/lak-device", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", signURL, bytes.NewReader(signPayloadJSON))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("sign LAK certificate failed: %s", string(body))
	}

	var signResp struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &signResp); err != nil {
		return "", "", err
	}

	lakCertPEM = signResp.Data.Certificate

	rootCAURL := fmt.Sprintf("%s/v1/pki-ak/cert/ca", c.baseURL)
	rootReq, _ := http.NewRequestWithContext(ctx, "GET", rootCAURL, nil)

	rootResp, err := c.doWithRetry(ctx, rootReq)
	if err != nil {
		return "", "", err
	}
	defer rootResp.Body.Close()

	rootBody, _ := io.ReadAll(rootResp.Body)

	// Parse JSON response to extract certificate
	var rootCAResp struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rootBody, &rootCAResp); err != nil {
		return "", "", fmt.Errorf("failed to parse AK CA response: %w", err)
	}
	lakRootCAPEM = rootCAResp.Data.Certificate

	log.Printf("LAK certificate issued for EK: %s", ekHashBase64)
	return lakCertPEM, lakRootCAPEM, nil
}

type CertRequest struct {
	CommonName          string
	SanIPs              []string
	SanDNS              []string
	PermanentIdentifier string
	Usage               string
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

type acmeAuthorization struct {
	Identifier map[string]string `json:"identifier"`
	Status     string            `json:"status"`
	Challenges []acmeChallenge   `json:"challenges"`
}

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

func (c *OpenBaoClient) getACMEDirectory() (*acmeDirectory, error) {
	return c.getACMEDirectoryForPath("pki-agent/roles/agent")
}

func (c *OpenBaoClient) getACMEDirectoryForPath(pkiPath string) (*acmeDirectory, error) {
	directoryURL := fmt.Sprintf("%s/v1/%s/acme/directory", c.baseURL, pkiPath)
	resp, err := http.Get(directoryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var directory acmeDirectory
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		return nil, err
	}
	return &directory, nil
}

func (c *OpenBaoClient) getAuthorization(authzURL string) (*acmeAuthorization, error) {
	// Legacy method - get default account for backward compatibility
	pkiPath := extractPKIPathFromURL(authzURL)
	account, err := c.accountManager.GetOrCreateAccount(pkiPath)
	if err != nil {
		return nil, err
	}
	return c.getAuthorizationWithAccount(authzURL, account)
}

func (c *OpenBaoClient) getAuthorizationWithAccount(authzURL string, account *ACMEAccount) (*acmeAuthorization, error) {
	jws, err := c.buildJWSWithAccount(authzURL, account.AccountURL, []byte(""), false, account)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(authzURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authz acmeAuthorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, err
	}
	return &authz, nil
}

func (c *OpenBaoClient) buildJWS(url, kid string, payload []byte, includeJWK bool) (string, error) {
	// Legacy method - get default account for backward compatibility
	account, err := c.accountManager.GetOrCreateAccount("pki-agent/roles/agent")
	if err != nil {
		return "", err
	}
	return c.buildJWSWithAccount(url, kid, payload, includeJWK, account)
}

func (c *OpenBaoClient) buildJWSWithAccount(url, kid string, payload []byte, includeJWK bool, account *ACMEAccount) (string, error) {
	// Extract PKI path from the URL to get nonce from correct endpoint
	pkiPath := extractPKIPathFromURL(url)
	nonce, err := c.getNonceForPath(pkiPath)
	if err != nil {
		return "", err
	}

	protected := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}

	if includeJWK {
		pubKey := account.PrivateKey.Public().(*ecdsa.PublicKey)
		xBytes := make([]byte, 32)
		yBytes := make([]byte, 32)
		pubKey.X.FillBytes(xBytes)
		pubKey.Y.FillBytes(yBytes)
		protected["jwk"] = map[string]string{
			"crv": "P-256",
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		}
	} else {
		protected["kid"] = kid
	}

	protectedBytes, _ := json.Marshal(protected)
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signInput := protectedB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signInput))

	r, s, err := ecdsa.Sign(rand.Reader, account.PrivateKey, hash[:])
	if err != nil {
		return "", err
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jws := map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}
	jwsBytes, _ := json.Marshal(jws)
	return string(jwsBytes), nil
}

func (c *OpenBaoClient) getNonce() (string, error) {
	return c.getNonceForPath("pki-agent/roles/agent")
}

func (c *OpenBaoClient) getNonceForPath(pkiPath string) (string, error) {
	directory, err := c.getACMEDirectoryForPath(pkiPath)
	if err != nil {
		return "", err
	}
	resp, err := http.Head(directory.NewNonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Header.Get("Replay-Nonce"), nil
}

func pemToBase64URL(pemData string) (string, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}
	return base64.RawURLEncoding.EncodeToString(block.Bytes), nil
}

func (c *OpenBaoClient) IsTPMEnrolled(ctx context.Context, permanentID string) (bool, error) {
	listURL := fmt.Sprintf("%s/v1/pki-agent/config/acme/ak-ca-roots?list=true", c.baseURL)
	req, _ := http.NewRequestWithContext(ctx, "GET", listURL, nil)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var listResp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return false, err
	}

	return len(listResp.Data.Keys) > 0, nil
}

func (c *OpenBaoClient) ValidateEKCertificate(ctx context.Context, ekCert *x509.Certificate, trustedCAs map[string]*x509.Certificate) (*x509.Certificate, string, error) {
	for _, cert := range trustedCAs {
		if cert.Subject.String() == ekCert.Issuer.String() {
			if err := ekCert.CheckSignatureFrom(cert); err == nil {
				for caName, ca := range trustedCAs {
					if ca.Equal(cert) {
						return cert, caName, nil
					}
				}
				return cert, "unknown", nil
			}
		}
	}
	return nil, "", fmt.Errorf("EK certificate issuer not found in trusted CAs")
}

func ComputeEKHashBase64(ekCert *x509.Certificate) (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(pubKeyDER)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// BuildUnsignedCSR creates a PKCS#10 CSR from a public key with a dummy signature.
// This bypasses Go's x509.CreateCertificateRequest which validates signatures (Go 1.20+).
// OpenBao's sign-verbatim endpoint with allow_unsigned_csr accepts these CSRs.
//
// This function is self-contained and can be replaced with a proper library later.
// Supports: RSA, ECDSA (P-256, P-384, P-521), Ed25519
func BuildUnsignedCSR(pubKey crypto.PublicKey, cn string, uriSANs []string) (string, error) {
	csrDER, err := buildPKCS10CSR(pubKey, cn, uriSANs)
	if err != nil {
		return "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

// buildPKCS10CSR constructs a PKCS#10 CSR using raw ASN.1 encoding.
// RFC 2986: PKCS #10 Certification Request Syntax
//
// CertificationRequest ::= SEQUENCE {
//   certificationRequestInfo CertificationRequestInfo,
//   signatureAlgorithm       AlgorithmIdentifier,
//   signature                BIT STRING
// }
//
// CertificationRequestInfo ::= SEQUENCE {
//   version       INTEGER { v1(0) },
//   subject       Name,
//   subjectPKInfo SubjectPublicKeyInfo,
//   attributes    [0] IMPLICIT Attributes
// }
func buildPKCS10CSR(pubKey crypto.PublicKey, cn string, uriSANs []string) ([]byte, error) {
	// Build SubjectPublicKeyInfo
	spki, err := buildSubjectPublicKeyInfo(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build SPKI: %w", err)
	}

	// Build Subject Name (CN=...)
	subject := pkix.Name{CommonName: cn}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Build attributes (including SAN extension if provided)
	var attributes []asn1.RawValue
	if len(uriSANs) > 0 {
		sanAttr, err := buildSANAttribute(uriSANs)
		if err != nil {
			return nil, fmt.Errorf("failed to build SAN attribute: %w", err)
		}
		attributes = append(attributes, sanAttr)
	}

	// Build CertificationRequestInfo
	certReqInfo := pkcs10CertReqInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: subjectDER},
		SubjectPKInfo: spki,
		Attributes:    attributes,
	}

	// Get signature algorithm and dummy signature size
	sigAlg, sigLen := getSignatureAlgorithm(pubKey)

	// Build complete CSR with dummy (zero) signature
	csr := pkcs10CSR{
		CertificationRequestInfo: certReqInfo,
		SignatureAlgorithm:       sigAlg,
		Signature: asn1.BitString{
			Bytes:     make([]byte, sigLen),
			BitLength: sigLen * 8,
		},
	}

	return asn1.Marshal(csr)
}

// OID for extensionRequest attribute (PKCS#9)
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// OID for Subject Alternative Name extension
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// buildSANAttribute builds the extensionRequest attribute containing SAN extension
// RFC 2985: PKCS #9 extensionRequest attribute
func buildSANAttribute(uriSANs []string) (asn1.RawValue, error) {
	// Build GeneralNames sequence for URI SANs
	// GeneralName ::= CHOICE { uniformResourceIdentifier [6] IA5String }
	var generalNames []asn1.RawValue
	for _, uri := range uriSANs {
		// Tag 6 = uniformResourceIdentifier (IA5String, implicit)
		generalNames = append(generalNames, asn1.RawValue{
			Tag:   6,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(uri),
		})
	}

	// Marshal GeneralNames sequence
	sanValue, err := asn1.Marshal(generalNames)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build Extension: SEQUENCE { extnID, critical (optional), extnValue }
	ext := pkix.Extension{
		Id:    oidSubjectAltName,
		Value: sanValue,
	}
	extDER, err := asn1.Marshal(ext)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build Extensions SEQUENCE
	extensions := []asn1.RawValue{{FullBytes: extDER}}
	extensionsDER, err := asn1.Marshal(extensions)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build Attribute: SEQUENCE { type OID, values SET }
	// extensionRequest attribute contains a SET of Extensions
	attrValue := asn1.RawValue{FullBytes: extensionsDER}
	attrValues := []asn1.RawValue{attrValue}
	attrValuesDER, err := asn1.MarshalWithParams(attrValues, "set")
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build the attribute structure
	attr := struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{
		Type:   oidExtensionRequest,
		Values: asn1.RawValue{FullBytes: attrValuesDER},
	}

	attrDER, err := asn1.Marshal(attr)
	if err != nil {
		return asn1.RawValue{}, err
	}

	return asn1.RawValue{FullBytes: attrDER}, nil
}

// ASN.1 structures for PKCS#10 CSR (RFC 2986)
type pkcs10CSR struct {
	CertificationRequestInfo pkcs10CertReqInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	Signature                asn1.BitString
}

type pkcs10CertReqInfo struct {
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo pkcs10SPKI
	Attributes    []asn1.RawValue `asn1:"tag:0"`
}

type pkcs10SPKI struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// OIDs for key types and signature algorithms
var (
	oidRSA             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384            = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521            = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// buildSubjectPublicKeyInfo creates the SPKI structure for the given public key
func buildSubjectPublicKeyInfo(pubKey crypto.PublicKey) (pkcs10SPKI, error) {
	var spki pkcs10SPKI

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// RSA: SEQUENCE { modulus INTEGER, exponent INTEGER }
		rsaPub := struct {
			N *big.Int
			E int
		}{N: key.N, E: key.E}
		pubKeyDER, err := asn1.Marshal(rsaPub)
		if err != nil {
			return spki, err
		}
		// RSA AlgorithmIdentifier requires NULL parameters per RFC 3279
		spki = pkcs10SPKI{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidRSA,
				Parameters: asn1.NullRawValue,
			},
			PublicKey: asn1.BitString{Bytes: pubKeyDER, BitLength: len(pubKeyDER) * 8},
		}

	case *ecdsa.PublicKey:
		// EC: uncompressed point 0x04 || X || Y
		curveOID := getCurveOID(key.Curve)
		byteLen := (key.Params().BitSize + 7) / 8
		pubKeyBytes := make([]byte, 1+2*byteLen)
		pubKeyBytes[0] = 0x04 // uncompressed point
		key.X.FillBytes(pubKeyBytes[1 : 1+byteLen])
		key.Y.FillBytes(pubKeyBytes[1+byteLen:])

		curveOIDDER, _ := asn1.Marshal(curveOID)
		spki = pkcs10SPKI{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidECPublicKey,
				Parameters: asn1.RawValue{FullBytes: curveOIDDER},
			},
			PublicKey: asn1.BitString{Bytes: pubKeyBytes, BitLength: len(pubKeyBytes) * 8},
		}

	case ed25519.PublicKey:
		spki = pkcs10SPKI{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
			PublicKey: asn1.BitString{Bytes: key, BitLength: len(key) * 8},
		}

	default:
		return spki, fmt.Errorf("unsupported key type: %T", pubKey)
	}

	return spki, nil
}

// getSignatureAlgorithm returns the signature algorithm and dummy signature size
func getSignatureAlgorithm(pubKey crypto.PublicKey) (pkix.AlgorithmIdentifier, int) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA}, (key.N.BitLen() + 7) / 8

	case *ecdsa.PublicKey:
		byteLen := (key.Params().BitSize + 7) / 8
		// ECDSA signature: ASN.1 SEQUENCE { INTEGER r, INTEGER s }
		// Max size with padding: 2 (seq) + 2 (len) + 2 (int tag+len) + byteLen+1 + 2 + byteLen+1
		sigLen := 2 + 2 + byteLen + 1 + 2 + byteLen + 1
		sigAlg := getECDSASigAlgorithm(key.Curve)
		return pkix.AlgorithmIdentifier{Algorithm: sigAlg}, sigLen

	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidEd25519}, ed25519.SignatureSize

	default:
		// Fallback to RSA SHA256
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA}, 256
	}
}

func getCurveOID(curve elliptic.Curve) asn1.ObjectIdentifier {
	switch curve {
	case elliptic.P256():
		return oidP256
	case elliptic.P384():
		return oidP384
	case elliptic.P521():
		return oidP521
	default:
		return oidP256
	}
}

func getECDSASigAlgorithm(curve elliptic.Curve) asn1.ObjectIdentifier {
	switch curve {
	case elliptic.P256():
		return oidECDSAWithSHA256
	case elliptic.P384():
		return oidECDSAWithSHA384
	case elliptic.P521():
		return oidECDSAWithSHA512
	default:
		return oidECDSAWithSHA256
	}
}

// RequestServerCertificate requests a TLS certificate from OpenBao pki-grpc for the server
func (c *OpenBaoClient) RequestServerCertificate(ctx context.Context, cn string, sans []string) (certPEM, keyPEM string, err error) {
	payload := map[string]interface{}{
		"common_name": cn,
		"alt_names":   strings.Join(sans, ","),
		"ttl":         "720h",
	}
	payloadJSON, _ := json.Marshal(payload)

	issueURL := fmt.Sprintf("%s/v1/pki-grpc/issue/server", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", issueURL, bytes.NewReader(payloadJSON))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("certificate issuance failed: %s", string(body))
	}

	var issueResp struct {
		Data struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &issueResp); err != nil {
		return "", "", err
	}

	return issueResp.Data.Certificate, issueResp.Data.PrivateKey, nil
}

// SignCertificate uses sign-verbatim to issue a certificate for mTLS-authenticated requests
func (c *OpenBaoClient) SignCertificate(ctx context.Context, pkiPath, role, csrPEM, ttl string) (certPEM, chainPEM, caPEM string, err error) {
	signURL := fmt.Sprintf("%s/v1/%s/sign-verbatim/%s", c.baseURL, pkiPath, role)

	payload := map[string]interface{}{
		"csr": csrPEM,
		"ttl": ttl,
	}
	payloadJSON, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", signURL, bytes.NewReader(payloadJSON))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("sign-verbatim failed: %s", string(body))
	}

	var signResp struct {
		Data struct {
			Certificate string   `json:"certificate"`
			CAChain     []string `json:"ca_chain"`
			IssuingCA   string   `json:"issuing_ca"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &signResp); err != nil {
		return "", "", "", err
	}

	return signResp.Data.Certificate, strings.Join(signResp.Data.CAChain, "\n"), signResp.Data.IssuingCA, nil
}
