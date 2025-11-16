// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

	fmt.Printf("Authorization has %d challenges\n", len(authz.Challenges))
	for i, ch := range authz.Challenges {
		fmt.Printf("Challenge %d: type=%s, url=%s\n", i, ch.Type, ch.URL)
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

	// Read body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Printf("Order status response body: %s\n", string(bodyBytes))

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
	fmt.Printf("Finalizing order at: %s\n", finalizeURL)

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
	fmt.Printf("Getting certificate for order: %s\n", orderURL)

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

	// Read body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Authorization response body: %s\n", string(bodyBytes))

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
		protected["jwk"] = map[string]string{
			"crv": "P-256",
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
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
