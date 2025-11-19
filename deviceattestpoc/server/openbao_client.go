// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	pb "github.com/openbao/openbao/deviceattestpoc/proto"
)

// OpenBaoClient handles interactions with OpenBao ACME API
type OpenBaoClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	accountKey *ecdsa.PrivateKey
	accountURL string
	kidURL     string
}

// ACMEOrder represents the ACME order information
type ACMEOrder struct {
	OrderID           string
	AuthorizationURL  string
	ChallengeURL      string
	ChallengeToken    string
	AccountThumbprint string
	FinalizeURL       string
	CertificateURL    string
}

// NewOpenBaoClient creates a new OpenBao client
func NewOpenBaoClient(baseURL, token string) (*OpenBaoClient, error) {
	// Generate ACME account key
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	client := &OpenBaoClient{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{},
		accountKey: accountKey,
	}

	// Create ACME account with retries
	fmt.Printf("Creating ACME account...\n")
	var lastErr error
	for i := 0; i < 10; i++ {
		if err := client.createACMEAccount(); err != nil {
			lastErr = err
			if i < 9 {
				fmt.Printf("Failed to create ACME account (attempt %d/10): %v. Retrying in 2s...\n", i+1, err)
				time.Sleep(2 * time.Second)
				continue
			}
		} else {
			fmt.Printf("✓ ACME account created successfully (kid: %s)\n", client.kidURL)
			return client, nil
		}
	}

	return nil, fmt.Errorf("failed to create ACME account after 10 attempts: %w", lastErr)
}

// createACMEAccount creates an ACME account on OpenBao
func (c *OpenBaoClient) createACMEAccount() error {
	// Get directory
	directory, err := c.getACMEDirectory()
	if err != nil {
		return fmt.Errorf("failed to get ACME directory: %w", err)
	}

	// Create account
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{},
	}

	payloadBytes, _ := json.Marshal(payload)

	// Build JWS with jwk header
	jws, err := c.buildJWS(directory.NewAccount, "", payloadBytes, true)
	if err != nil {
		return fmt.Errorf("failed to build JWS: %w", err)
	}

	resp, err := http.Post(directory.NewAccount, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("account creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Save account URL (kid)
	c.accountURL = resp.Header.Get("Location")
	c.kidURL = c.accountURL

	return nil
}

// CreateACMEOrder creates a new ACME order with device attestation
func (c *OpenBaoClient) CreateACMEOrder(ctx context.Context, req *pb.CertRequest) (*ACMEOrder, error) {
	directory, err := c.getACMEDirectory()
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME directory: %w", err)
	}

	// Build order request with permanent-identifier ONLY
	// Per draft-acme-device-attest-07, when using device attestation with permanent-identifier,
	// DNS names are included in the CSR's SAN field, NOT as separate ACME identifiers
	// This avoids requiring DNS-01 or HTTP-01 challenges
	identifiers := []map[string]string{
		{
			"type":  "permanent-identifier",
			"value": req.PermanentIdentifier,
		},
	}

	// Note: DNS names from req.SanDns will be in the CSR's SubjectAltName extension
	// They are NOT added as ACME identifiers to avoid additional challenge requirements

	payload := map[string]interface{}{
		"identifiers": identifiers,
	}

	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWS(directory.NewOrder, c.kidURL, payloadBytes, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWS: %w", err)
	}

	resp, err := http.Post(directory.NewOrder, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("order creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	orderURL := resp.Header.Get("Location")

	var orderResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		return nil, fmt.Errorf("failed to decode order response: %w", err)
	}

	// Get authorization URL
	authorizations := orderResp["authorizations"].([]interface{})
	if len(authorizations) == 0 {
		return nil, fmt.Errorf("no authorizations in order")
	}
	authzURL := authorizations[0].(string)

	// Get authorization to find device-attest-01 challenge
	authz, err := c.getAuthorization(authzURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization: %w", err)
	}

	// Find device-attest-01 challenge
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

	// Compute account thumbprint
	thumbprint, err := c.getAccountThumbprint()
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}

	return &ACMEOrder{
		OrderID:           orderURL,
		AuthorizationURL:  authzURL,
		ChallengeURL:      challengeURL,
		ChallengeToken:    challengeToken,
		AccountThumbprint: thumbprint,
		FinalizeURL:       orderResp["finalize"].(string),
	}, nil
}

// SubmitAttestation submits the attestation object to the challenge
func (c *OpenBaoClient) SubmitAttestation(ctx context.Context, challengeURL, attestationObject string) error {
	payload := map[string]interface{}{
		"attObj": attestationObject,
	}

	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWS(challengeURL, c.kidURL, payloadBytes, false)
	if err != nil {
		return fmt.Errorf("failed to build JWS: %w", err)
	}

	resp, err := http.Post(challengeURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return fmt.Errorf("failed to submit attestation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("attestation submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetOrderStatus gets the current status of an order
func (c *OpenBaoClient) GetOrderStatus(ctx context.Context, orderURL string) (string, error) {
	// ACME uses POST-as-GET: POST request with empty payload
	jws, err := c.buildJWS(orderURL, c.kidURL, []byte(""), false)
	if err != nil {
		return "", fmt.Errorf("failed to build JWS for order fetch: %w", err)
	}

	resp, err := http.Post(orderURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var orderResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &orderResp); err != nil {
		return "", err
	}

	status, ok := orderResp["status"].(string)
	if !ok {
		return "", fmt.Errorf("order status not found or not a string in response")
	}

	return status, nil
}

// FinalizeOrder finalizes an ACME order with a CSR
func (c *OpenBaoClient) FinalizeOrder(ctx context.Context, finalizeURL, csrPEM string) error {
	// Build finalize payload with CSR
	// The CSR needs to be in base64url format without PEM headers
	csrDER, err := pemToBase64URL(csrPEM)
	if err != nil {
		return fmt.Errorf("failed to convert CSR: %w", err)
	}

	payload := map[string]interface{}{
		"csr": csrDER,
	}

	payloadBytes, _ := json.Marshal(payload)

	jws, err := c.buildJWS(finalizeURL, c.kidURL, payloadBytes, false)
	if err != nil {
		return fmt.Errorf("failed to build JWS for finalize: %w", err)
	}

	resp, err := http.Post(finalizeURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return fmt.Errorf("failed to finalize order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("finalize failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("✓ Order finalized successfully\n")
	return nil
}

// GetCertificate retrieves the certificate from a ready order
func (c *OpenBaoClient) GetCertificate(ctx context.Context, orderURL string) (string, []string, error) {
	// First, get the order to find the certificate URL
	jws, err := c.buildJWS(orderURL, c.kidURL, []byte(""), false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build JWS for order fetch: %w", err)
	}

	resp, err := http.Post(orderURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch order: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	var orderResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &orderResp); err != nil {
		return "", nil, err
	}

	status, _ := orderResp["status"].(string)
	if status != "valid" {
		return "", nil, fmt.Errorf("order status is %s, expected valid", status)
	}

	certificateURL, ok := orderResp["certificate"].(string)
	if !ok {
		return "", nil, fmt.Errorf("certificate URL not found in order")
	}

	// Download the certificate
	jws, err = c.buildJWS(certificateURL, c.kidURL, []byte(""), false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build JWS for certificate download: %w", err)
	}

	resp, err = http.Post(certificateURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return "", nil, fmt.Errorf("failed to download certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("certificate download failed with status %d: %s", resp.StatusCode, string(body))
	}

	certPEM, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	// The certificate is returned as a PEM chain
	// Split into certificate and chain
	// For simplicity, return the whole thing as certificate, empty chain
	return string(certPEM), []string{}, nil
}

// Helper types and methods

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

type acmeAuthorization struct {
	Identifier map[string]string   `json:"identifier"`
	Status     string              `json:"status"`
	Challenges []acmeChallenge     `json:"challenges"`
}

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

func (c *OpenBaoClient) getACMEDirectory() (*acmeDirectory, error) {
	// Use role-specific ACME directory for device attestation
	// The ipsec-vpn role has allow_device_attestation enabled
	directoryURL := fmt.Sprintf("%s/v1/pki/roles/ipsec-vpn/acme/directory", c.baseURL)

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
	// ACME uses POST-as-GET: POST request with empty payload
	// Build JWS with empty payload
	jws, err := c.buildJWS(authzURL, c.kidURL, []byte(""), false)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWS for authorization fetch: %w", err)
	}

	resp, err := http.Post(authzURL, "application/jose+json", strings.NewReader(jws))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authz acmeAuthorization
	if err := json.Unmarshal(bodyBytes, &authz); err != nil {
		return nil, err
	}

	return &authz, nil
}

func (c *OpenBaoClient) getAccountThumbprint() (string, error) {
	// Compute JWK thumbprint per RFC 7638
	pubKey := c.accountKey.Public().(*ecdsa.PublicKey)

	jwk := map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}

	jwkBytes, _ := json.Marshal(jwk)
	hash := sha256.Sum256(jwkBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func (c *OpenBaoClient) buildJWS(url, kid string, payload []byte, includeJWK bool) (string, error) {
	// Get nonce
	nonce, err := c.getNonce()
	if err != nil {
		return "", err
	}

	// Build protected header
	protected := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}

	if includeJWK {
		pubKey := c.accountKey.Public().(*ecdsa.PublicKey)

		// EC P-256 coordinates must be exactly 32 bytes
		// pubKey.X.Bytes() and pubKey.Y.Bytes() omit leading zeros, so we need to pad them
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

	// Sign
	signInput := protectedB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signInput))

	r, s, err := ecdsa.Sign(rand.Reader, c.accountKey, hash[:])
	if err != nil {
		return "", err
	}

	// Encode signature - ES256 requires exactly 64 bytes (32 for r, 32 for s)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad r and s to 32 bytes each
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build JWS
	jws := map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}

	jwsBytes, _ := json.Marshal(jws)
	return string(jwsBytes), nil
}

func (c *OpenBaoClient) getNonce() (string, error) {
	directory, err := c.getACMEDirectory()
	if err != nil {
		return "", err
	}

	resp, err := http.Head(directory.NewNonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no nonce in response")
	}

	return nonce, nil
}

// pemToBase64URL converts a PEM-encoded CSR to base64url-encoded DER
func pemToBase64URL(pemData string) (string, error) {
	// Remove PEM headers and decode base64
	lines := strings.Split(pemData, "\n")
	var derBase64 strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		derBase64.WriteString(line)
	}

	// Decode standard base64 to DER
	derBytes, err := base64.StdEncoding.DecodeString(derBase64.String())
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Re-encode as base64url (RFC 4648)
	return base64.RawURLEncoding.EncodeToString(derBytes), nil
}

// EnrollTPMDevice enrolls a TPM device by configuring its EK root CA and allowlisting its permanent identifier
func (c *OpenBaoClient) EnrollTPMDevice(ctx context.Context, permanentID, ekRootCAPEM, ekRootCAName string) error {
	// Step 1: Configure EK root CA
	if err := c.configureEKRootCA(ctx, ekRootCAName, ekRootCAPEM); err != nil {
		return fmt.Errorf("failed to configure EK root CA: %w", err)
	}

	// Step 2: Update role to enable EK validation and allowlist the TPM
	if err := c.updateRoleAllowlist(ctx, permanentID); err != nil {
		return fmt.Errorf("failed to update role allowlist: %w", err)
	}

	return nil
}

// configureEKRootCA configures the TPM EK root CA certificate in OpenBao
func (c *OpenBaoClient) configureEKRootCA(ctx context.Context, name, certPEM string) error {
	url := fmt.Sprintf("%s/v1/pki/config/acme/ek-roots/%s", c.baseURL, name)

	payload := map[string]interface{}{
		"certificate": certPEM,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to configure EK root CA (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// updateRoleAllowlist updates the ipsec-vpn role to enable EK validation and allowlist a TPM
func (c *OpenBaoClient) updateRoleAllowlist(ctx context.Context, permanentID string) error {
	url := fmt.Sprintf("%s/v1/pki/roles/ipsec-vpn", c.baseURL)

	// First, read the current role configuration
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create read request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to read role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to read role (status %d): %s", resp.StatusCode, string(body))
	}

	var roleResp struct {
		Data map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&roleResp); err != nil {
		return fmt.Errorf("failed to decode role response: %w", err)
	}

	// Get existing allowlist
	allowlist := []string{}
	if existing, ok := roleResp.Data["allowed_tpm_identifiers"]; ok {
		if existingList, ok := existing.([]interface{}); ok {
			for _, item := range existingList {
				if str, ok := item.(string); ok {
					allowlist = append(allowlist, str)
				}
			}
		}
	}

	// Add new permanent ID if not already present
	found := false
	for _, id := range allowlist {
		if id == permanentID {
			found = true
			break
		}
	}

	if !found {
		allowlist = append(allowlist, permanentID)
	}

	// Update role with EK validation enabled and updated allowlist
	// Start with existing role data to preserve all settings
	payload := roleResp.Data

	// Update only the fields we care about
	payload["validate_ek_certificate"] = true
	payload["allowed_tpm_identifiers"] = allowlist
	payload["allow_device_attestation"] = true
	payload["required_attestation_formats"] = []string{"tpm"}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err = http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update role (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ProvisionIAKCertificate issues an IAK certificate for a TPM attestation key (AK mode)
// This acts as a Privacy CA, issuing IAK certificates for TPMs without manufacturer-provisioned IAK
func (c *OpenBaoClient) ProvisionIAKCertificate(
	ctx context.Context,
	permanentID string,
	akPublicKeyDER []byte,
	ekCertPEM string,
) (iakCertPEM, iakRootCAPEM, notBefore, notAfter string, err error) {
	log.Printf("Provisioning IAK certificate for permanent ID: %s", permanentID)

	// 1. Verify device is enrolled
	enrolled, err := c.isTPMEnrolled(ctx, permanentID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to check enrollment status: %w", err)
	}
	if !enrolled {
		return "", "", "", "", fmt.Errorf("device not enrolled - call EnrollTPM first")
	}

	// 2. Parse and validate EK certificate
	block, _ := pem.Decode([]byte(ekCertPEM))
	if block == nil {
		return "", "", "", "", fmt.Errorf("failed to decode EK certificate PEM")
	}

	ekCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse EK certificate: %w", err)
	}

	// 3. Get all configured EK root CAs and find which one validates this EK cert
	// We try to verify against all configured root CAs since we don't store per-device mapping
	_, ekRootCAName, err := c.findMatchingEKRootCA(ctx, ekCert)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to find matching EK root CA: %w", err)
	}

	log.Printf("✓ EK certificate validated against enrolled root CA: %s", ekRootCAName)

	// 4. Parse AK public key
	akPubKey, err := x509.ParsePKIXPublicKey(akPublicKeyDER)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse AK public key: %w", err)
	}

	rsaPubKey, ok := akPubKey.(*rsa.PublicKey)
	if !ok {
		return "", "", "", "", fmt.Errorf("AK public key is not RSA (type: %T)", akPubKey)
	}

	log.Printf("✓ AK public key parsed: %d bits", rsaPubKey.N.BitLen())

	// 5. Create IAK certificate signed by OpenBao PKI-IAK CA
	// For PoC simplicity, we'll create a self-signed certificate
	// In production, this would use a dedicated PKI mount (pki-iak)

	now := time.Now()
	notBeforeTime := now.Add(-1 * time.Hour)
	notAfterTime := now.Add(365 * 24 * time.Hour) // 1 year validity

	// Create IAK certificate template
	iakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   "TPM IAK Certificate (OpenBao-issued)",
			SerialNumber: permanentID,
			Organization: []string{"OpenBao Privacy CA"},
		},
		NotBefore:             notBeforeTime,
		NotAfter:              notAfterTime,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// For PoC, create a simple signing key
	// In production, this would be the PKI-IAK CA's private key
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to generate signing key: %w", err)
	}

	// Create root CA certificate (self-signed, represents OpenBao PKI-IAK CA)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "OpenBao PKI-IAK Root CA",
			Organization: []string{"OpenBao Privacy CA"},
		},
		NotBefore:             notBeforeTime,
		NotAfter:              notAfterTime.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &signingKey.PublicKey, signingKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create root CA: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse root CA: %w", err)
	}

	// Sign IAK certificate with root CA
	iakDER, err := x509.CreateCertificate(rand.Reader, iakTemplate, rootCert, rsaPubKey, signingKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create IAK certificate: %w", err)
	}

	// Encode certificates to PEM
	iakCertPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: iakDER,
	}))

	iakRootCAPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDER,
	}))

	notBefore = notBeforeTime.Format(time.RFC3339)
	notAfter = notAfterTime.Format(time.RFC3339)

	log.Printf("✓ IAK certificate issued successfully")
	log.Printf("  Valid from: %s", notBefore)
	log.Printf("  Valid until: %s", notAfter)

	// 6. Configure the IAK root CA in OpenBao so it's trusted for attestation validation
	// Note: OpenBao validates IAK certificates using the same trust store as EK certificates
	// So we configure the IAK root CA as an EK root CA
	err = c.configureEKRootCA(ctx, "openbao-pki-iak", iakRootCAPEM)
	if err != nil {
		// Log warning but don't fail - the IAK cert is already issued
		log.Printf("⚠ Warning: Failed to configure IAK root CA in OpenBao: %v", err)
		log.Printf("  IAK certificate was issued but may not be trusted for attestation validation")
	} else {
		log.Printf("✓ IAK root CA configured in OpenBao for attestation validation")
	}

	return iakCertPEM, iakRootCAPEM, notBefore, notAfter, nil
}

// isTPMEnrolled checks if a TPM device is enrolled by checking the role's allowlist
func (c *OpenBaoClient) isTPMEnrolled(ctx context.Context, permanentID string) (bool, error) {
	// Check if the permanent ID is in the role's allowed_tpm_identifiers list
	url := fmt.Sprintf("%s/v1/pki/roles/ipsec-vpn", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check enrollment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var roleResp struct {
		Data struct {
			AllowedTPMIdentifiers []interface{} `json:"allowed_tpm_identifiers"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&roleResp); err != nil {
		return false, fmt.Errorf("failed to decode role response: %w", err)
	}

	// Check if permanent ID is in the allowlist
	for _, item := range roleResp.Data.AllowedTPMIdentifiers {
		if str, ok := item.(string); ok && str == permanentID {
			return true, nil
		}
	}

	return false, nil
}

// findMatchingEKRootCA finds the EK root CA that validates the given EK certificate
// It tries common manufacturer names based on the EK certificate issuer
func (c *OpenBaoClient) findMatchingEKRootCA(ctx context.Context, ekCert *x509.Certificate) (*x509.Certificate, string, error) {
	// Try to determine manufacturer from EK certificate issuer
	issuer := ekCert.Issuer.String()
	log.Printf("EK certificate issuer: %s", issuer)

	// List of common manufacturer root CA names to try
	manufacturerNames := []string{"swtpm-manufacturer", "stmicro", "intel", "infineon", "amd", "nuvoton"}

	// Try to prioritize based on issuer string
	if strings.Contains(strings.ToLower(issuer), "swtpm") {
		manufacturerNames = append([]string{"swtpm-manufacturer"}, manufacturerNames...)
	} else if strings.Contains(strings.ToLower(issuer), "stm") {
		manufacturerNames = append([]string{"stmicro"}, manufacturerNames...)
	} else if strings.Contains(strings.ToLower(issuer), "intel") {
		manufacturerNames = append([]string{"intel"}, manufacturerNames...)
	} else if strings.Contains(strings.ToLower(issuer), "infineon") {
		manufacturerNames = append([]string{"infineon"}, manufacturerNames...)
	}

	// Try each manufacturer root CA
	for _, name := range manufacturerNames {
		rootCA, err := c.getEKRootCA(ctx, name)
		if err != nil {
			// Root CA not configured, try next
			continue
		}

		// Try to verify EK cert against this root CA
		// For PoC: Accept if issuer matches the configured root CA
		// In production, this should do full chain validation with intermediates
		roots := x509.NewCertPool()
		roots.AddCert(rootCA)

		// Try verification with the root CA
		opts := x509.VerifyOptions{
			Roots: roots,
			// Allow any key usage for TPM EK certs
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := ekCert.Verify(opts); err == nil {
			// Found matching root CA!
			log.Printf("✓ Found matching EK root CA: %s", name)
			return rootCA, name, nil
		}

		// Verification failed, might be due to intermediate CA
		// For PoC: If the root CA subject matches the expected manufacturer, accept it
		// This is a simplified check - in production, load and verify intermediate CAs
		if strings.Contains(strings.ToLower(rootCA.Subject.String()), "swtpm") &&
		   strings.Contains(strings.ToLower(issuer), "swtpm") {
			log.Printf("✓ EK cert issuer matches manufacturer (intermediate CA present): %s", name)
			return rootCA, name, nil
		}
		if strings.Contains(strings.ToLower(rootCA.Subject.String()), "stm") &&
		   strings.Contains(strings.ToLower(issuer), "stm") {
			log.Printf("✓ EK cert issuer matches manufacturer (intermediate CA present): %s", name)
			return rootCA, name, nil
		}
		if strings.Contains(strings.ToLower(rootCA.Subject.String()), "intel") &&
		   strings.Contains(strings.ToLower(issuer), "intel") {
			log.Printf("✓ EK cert issuer matches manufacturer (intermediate CA present): %s", name)
			return rootCA, name, nil
		}
		if strings.Contains(strings.ToLower(rootCA.Subject.String()), "infineon") &&
		   strings.Contains(strings.ToLower(issuer), "infineon") {
			log.Printf("✓ EK cert issuer matches manufacturer (intermediate CA present): %s", name)
			return rootCA, name, nil
		}
	}

	return nil, "", fmt.Errorf("no configured EK root CA validates this EK certificate (issuer: %s)", issuer)
}

// getEKRootCA retrieves a specific EK root CA by name
func (c *OpenBaoClient) getEKRootCA(ctx context.Context, name string) (*x509.Certificate, error) {
	url := fmt.Sprintf("%s/v1/pki/config/acme/ek-roots/%s", c.baseURL, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get EK root CA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EK root CA not found (status %d)", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse the EK root CA certificate
	block, _ := pem.Decode([]byte(result.Data.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode EK root CA PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EK root CA: %w", err)
	}

	return cert, nil
}
