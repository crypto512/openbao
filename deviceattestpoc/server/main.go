package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/uuid"
	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"google.golang.org/grpc"
)

// computeSPKIPinFromPEM computes the SPKI pin from a PEM-encoded certificate
// Returns format: sha256//<base64-encoded-hash>
func computeSPKIPinFromPEM(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "error: failed to parse certificate PEM"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:])
}

// readTokenFromKeysFile reads the root token from the OpenBao keys file
func readTokenFromKeysFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read keys file: %w", err)
	}

	var keys struct {
		RootToken string `json:"root_token"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return "", fmt.Errorf("failed to parse keys file: %w", err)
	}

	if keys.RootToken == "" {
		return "", fmt.Errorf("root_token not found in keys file")
	}

	return keys.RootToken, nil
}

type Server struct {
	pb.UnimplementedCertificateServiceServer
	openbaoClient      *OpenBaoClient
	orders             map[string]*OrderInfo
	trustedEKCAs       map[string]*x509.Certificate
	allowedEKHashes    map[string]bool
	activationSessions map[string]*ActivationSession
	agentCACertPool    *x509.CertPool // For mTLS validation of agent certificates
}

type ActivationSession struct {
	PermanentID    string
	AKParameters   []byte
	EKCertPEM      string
	ExpectedSecret []byte
	CreatedAt      time.Time
}

type OrderInfo struct {
	Order      *ACMEOrder
	CSR        string
	CommonName string
}

func (s *Server) RequestCertificate(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	usage := req.Usage
	if usage == "" {
		usage = "ipsec-vpn" // Default for backward compatibility
	}
	log.Printf("RequestCertificate: CN=%s, permanentID=%s, usage=%s", req.CommonName, req.PermanentIdentifier, usage)

	order, err := s.openbaoClient.CreateACMEOrder(ctx, &CertRequest{
		CommonName:          req.CommonName,
		SanDNS:              req.SanDns,
		SanIPs:              req.SanIps,
		PermanentIdentifier: req.PermanentIdentifier,
		Usage:               usage,
	})
	if err != nil {
		return &pb.CertResponse{Status: "error", Error: err.Error()}, nil
	}

	s.orders[order.OrderID] = &OrderInfo{
		Order:      order,
		CommonName: req.CommonName,
	}

	return &pb.CertResponse{
		Status:            "pending",
		OrderId:           order.OrderID,
		AuthorizationUrl:  order.AuthorizationURL,
		ChallengeUrl:      order.ChallengeURL,
		ChallengeToken:    order.ChallengeToken,
		AccountThumbprint: order.AccountThumbprint,
		FinalizeUrl:       order.FinalizeURL,
	}, nil
}

func (s *Server) SubmitAttestation(ctx context.Context, req *pb.AttestationSubmit) (*pb.CertResponse, error) {
	log.Printf("SubmitAttestation: orderID=%s", req.OrderId)

	// Submit attestation to OpenBao ACME - validation is done by the CA
	if err := s.openbaoClient.SubmitAttestation(ctx, req.ChallengeUrl, req.AttestationObject); err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	status, err := s.openbaoClient.GetOrderStatus(ctx, req.OrderId)
	if err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	return &pb.CertResponse{Status: status, OrderId: req.OrderId}, nil
}

func (s *Server) FinalizeOrder(ctx context.Context, req *pb.FinalizeRequest) (*pb.CertResponse, error) {
	log.Printf("FinalizeOrder: orderID=%s", req.OrderId)

	orderInfo, ok := s.orders[req.OrderId]
	if !ok {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: "order not found"}, nil
	}

	orderInfo.CSR = req.CsrPem

	if err := s.openbaoClient.FinalizeOrder(ctx, orderInfo.Order.FinalizeURL, req.CsrPem); err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	return &pb.CertResponse{Status: "processing", OrderId: req.OrderId}, nil
}

func (s *Server) GetCertificate(ctx context.Context, req *pb.GetCertRequest) (*pb.CertResponse, error) {
	log.Printf("GetCertificate: orderID=%s", req.OrderId)

	status, err := s.openbaoClient.GetOrderStatus(ctx, req.OrderId)
	log.Printf("GetCertificate: status=%s, err=%v", status, err)

	// Return current status for polling - let client handle waiting
	if status != "valid" {
		return &pb.CertResponse{Status: status, OrderId: req.OrderId}, nil
	}

	cert, chain, err := s.openbaoClient.GetCertificate(ctx, req.OrderId)
	if err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	return &pb.CertResponse{
		Status:         "valid",
		OrderId:        req.OrderId,
		CertificatePem: cert,
		ChainPem:       chain,
	}, nil
}

func (s *Server) EnrollTPM(ctx context.Context, req *pb.TPMEnrollmentRequest) (*pb.EnrollmentResponse, error) {
	log.Printf("EnrollTPM request")

	block, _ := pem.Decode([]byte(req.EkCertificatePem))
	if block == nil {
		return &pb.EnrollmentResponse{Status: "error", Error: "invalid EK certificate PEM"}, nil
	}

	ekCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &pb.EnrollmentResponse{Status: "error", Error: err.Error()}, nil
	}

	if _, _, err := s.validateEKCertificate(ekCert); err != nil {
		return &pb.EnrollmentResponse{Status: "error", Error: err.Error()}, nil
	}

	ekHash, err := ComputeEKHashBase64(ekCert)
	if err != nil {
		return &pb.EnrollmentResponse{Status: "error", Error: err.Error()}, nil
	}

	s.allowedEKHashes[ekHash] = true

	log.Printf("TPM enrolled: %s", ekHash)
	return &pb.EnrollmentResponse{
		Status:              "success",
		PermanentIdentifier: ekHash,
	}, nil
}

func (s *Server) ProvisionLAK(ctx context.Context, req *pb.ProvisionLAKRequest) (*pb.ProvisionLAKResponse, error) {
	log.Printf("ProvisionLAK: permanentID=%s", req.PermanentIdentifier)

	if !s.allowedEKHashes[req.PermanentIdentifier] {
		return &pb.ProvisionLAKResponse{Status: "error", Error: "device not enrolled"}, nil
	}

	var akParams attest.AttestationParameters
	if err := json.Unmarshal(req.AkParameters, &akParams); err != nil {
		return &pb.ProvisionLAKResponse{Status: "error", Error: err.Error()}, nil
	}

	ekPubKey, err := x509.ParsePKIXPublicKey(req.EkPublic)
	if err != nil {
		return &pb.ProvisionLAKResponse{Status: "error", Error: err.Error()}, nil
	}

	activationParams := attest.ActivationParameters{
		EK:   ekPubKey,
		AK:   akParams,
		Rand: rand.Reader,
	}

	secret, encryptedCredential, err := activationParams.Generate()
	if err != nil {
		return &pb.ProvisionLAKResponse{Status: "error", Error: err.Error()}, nil
	}

	encCredBytes, _ := json.Marshal(encryptedCredential)

	sessionID := uuid.New().String()
	s.activationSessions[sessionID] = &ActivationSession{
		PermanentID:    req.PermanentIdentifier,
		AKParameters:   req.AkParameters,
		EKCertPEM:      req.EkCertPem,
		ExpectedSecret: secret,
		CreatedAt:      time.Now(),
	}

	log.Printf("MakeCredential challenge generated: session=%s", sessionID)
	return &pb.ProvisionLAKResponse{
		Status:              "challenge",
		EncryptedCredential: encCredBytes,
		SessionId:           sessionID,
	}, nil
}

func (s *Server) ActivateCredential(ctx context.Context, req *pb.ActivateCredentialRequest) (*pb.ActivateCredentialResponse, error) {
	log.Printf("ActivateCredential: session=%s", req.SessionId)

	session, exists := s.activationSessions[req.SessionId]
	if !exists {
		return &pb.ActivateCredentialResponse{Status: "error", Error: "invalid session"}, nil
	}

	if time.Since(session.CreatedAt) > 5*time.Minute {
		delete(s.activationSessions, req.SessionId)
		return &pb.ActivateCredentialResponse{Status: "error", Error: "session expired"}, nil
	}

	if string(req.DecryptedSecret) != string(session.ExpectedSecret) {
		delete(s.activationSessions, req.SessionId)
		return &pb.ActivateCredentialResponse{Status: "error", Error: "secret verification failed"}, nil
	}

	log.Printf("Secret verified - AK-EK binding proven")
	delete(s.activationSessions, req.SessionId)

	// Extract AK public key from attestation parameters
	var akParams attest.AttestationParameters
	if err := json.Unmarshal(session.AKParameters, &akParams); err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to parse AK parameters: %v", err)}, nil
	}

	akPubKey, err := attest.ParseAKPublic(akParams.Public)
	if err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to parse AK public: %v", err)}, nil
	}

	// Build unsigned CSR from AK public key with SAN URI
	// Subject is empty (privacy-preserving), SAN contains permanent identifier URI
	// Format: urn:permanent-identifier:<value> (aligns with RFC 4043 concepts)
	sanURI := fmt.Sprintf("urn:permanent-identifier:%s", session.PermanentID)
	csrPEM, err := BuildUnsignedCSR(akPubKey.Public, "", []string{sanURI})
	if err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to build CSR: %v", err)}, nil
	}

	log.Printf("Built unsigned CSR for AK with permanent identifier URI: %s", sanURI)

	lakCertPEM, lakRootCAPEM, err := s.openbaoClient.SignLAKCertificate(ctx, session.PermanentID, csrPEM)
	if err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: err.Error()}, nil
	}

	block, _ := pem.Decode([]byte(lakCertPEM))
	var notBefore, notAfter string
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			notBefore = cert.NotBefore.Format(time.RFC3339)
			notAfter = cert.NotAfter.Format(time.RFC3339)
		}
	}

	log.Printf("LAK certificate issued: %s", session.PermanentID)
	return &pb.ActivateCredentialResponse{
		Status:           "success",
		LakCertificatePem: lakCertPEM,
		LakRootCaPem:     lakRootCAPEM,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
	}, nil
}

// IssueCertificate handles mTLS-authenticated certificate issuance
// This RPC is protected by MTLSUnaryInterceptor - client cert already validated
func (s *Server) IssueCertificate(ctx context.Context, req *pb.IssueCertRequest) (*pb.IssueCertResponse, error) {
	// Client cert already validated by interceptor
	clientCert := GetClientCert(ctx)
	if clientCert == nil {
		return &pb.IssueCertResponse{Status: "error", Error: "no client certificate"}, nil
	}

	permanentID := ExtractPermanentIDFromCert(clientCert)
	log.Printf("IssueCertificate: usage=%s, requester=%s", req.Usage, permanentID)

	// Get PKI configuration for this usage
	usageConfig, err := GetUsageConfig(req.Usage)
	if err != nil {
		return &pb.IssueCertResponse{Status: "error", Error: err.Error()}, nil
	}

	// Validate CSR
	if req.CsrPem == "" {
		return &pb.IssueCertResponse{Status: "error", Error: "CSR is required"}, nil
	}

	// Use sign-verbatim for certificate issuance
	certPEM, chainPEM, caPEM, err := s.openbaoClient.SignCertificate(ctx, usageConfig.PKIPath, usageConfig.Role, req.CsrPem, "72h")
	if err != nil {
		log.Printf("IssueCertificate failed: %v", err)
		return &pb.IssueCertResponse{Status: "error", Error: err.Error()}, nil
	}

	// Parse cert for validity dates
	block, _ := pem.Decode([]byte(certPEM))
	var notBefore, notAfter string
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			notBefore = cert.NotBefore.Format(time.RFC3339)
			notAfter = cert.NotAfter.Format(time.RFC3339)
		}
	}

	log.Printf("IssueCertificate success: usage=%s, requester=%s", req.Usage, permanentID)
	return &pb.IssueCertResponse{
		Status:         "success",
		CertificatePem: certPEM,
		ChainPem:       chainPEM,
		CaPem:          caPEM,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}, nil
}

// parseCertificateAuto parses a certificate from raw data, auto-detecting format.
// For .der files, it parses directly as DER.
// For .pem and .crt files, it tries PEM first, then falls back to DER.
func parseCertificateAuto(data []byte, ext string) (*x509.Certificate, error) {
	ext = strings.ToLower(ext)

	// For .der extension, parse directly as DER
	if ext == ".der" {
		return x509.ParseCertificate(data)
	}

	// For .pem and .crt, try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	// PEM decode failed, try DER as fallback
	return x509.ParseCertificate(data)
}

func loadTrustedEKCAs(caBasePath string) (map[string]*x509.Certificate, error) {
	trustedCAs := make(map[string]*x509.Certificate)

	log.Printf("Loading trusted EK CAs from: %s", caBasePath)

	err := filepath.Walk(caBasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(caBasePath, path)
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext != ".crt" && ext != ".pem" && ext != ".der" && ext != ".cer" {
			log.Printf("  Skipped (unsupported extension): %s", relPath)
			return nil
		}

		certData, err := os.ReadFile(path)
		if err != nil {
			log.Printf("  Skipped (read error): %s: %v", relPath, err)
			return nil
		}

		cert, err := parseCertificateAuto(certData, ext)
		if err != nil {
			log.Printf("  Skipped (parse error): %s: %v", relPath, err)
			return nil
		}
		if !cert.IsCA {
			log.Printf("  Skipped (not a CA): %s", relPath)
			return nil
		}

		caName := strings.TrimSuffix(relPath, filepath.Ext(relPath))
		trustedCAs[caName] = cert
		log.Printf("  Loaded CA: %s (%s)", caName, ext)

		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(trustedCAs) == 0 {
		return nil, fmt.Errorf("no trusted CA certificates found")
	}

	return trustedCAs, nil
}

func (s *Server) validateEKCertificate(ekCert *x509.Certificate) (*x509.Certificate, string, error) {
	for _, cert := range s.trustedEKCAs {
		if cert.Subject.String() == ekCert.Issuer.String() {
			if err := ekCert.CheckSignatureFrom(cert); err == nil {
				for caName, ca := range s.trustedEKCAs {
					if ca.Equal(cert) {
						return cert, caName, nil
					}
				}
				return cert, "unknown", nil
			}
		}
	}

	for caName, cert := range s.trustedEKCAs {
		if cert.Subject.String() == cert.Issuer.String() {
			if err := ekCert.CheckSignatureFrom(cert); err == nil {
				return cert, caName, nil
			}
		}
	}

	return nil, "", fmt.Errorf("EK certificate issuer not found in trusted CAs")
}


func main() {
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	baoAddr := os.Getenv("BAO_ADDR")
	if baoAddr == "" {
		log.Fatal("BAO_ADDR not set")
	}

	baoToken := os.Getenv("BAO_TOKEN")
	if baoToken == "" {
		// Try to read from keys file
		keysFile := os.Getenv("BAO_KEYS_FILE")
		if keysFile != "" {
			token, err := readTokenFromKeysFile(keysFile)
			if err != nil {
				log.Fatalf("Failed to read token from keys file: %v", err)
			}
			baoToken = token
		} else {
			log.Fatal("BAO_TOKEN not set and BAO_KEYS_FILE not specified")
		}
	}

	log.Printf("Starting server on port %s", port)
	log.Printf("OpenBao: %s", baoAddr)

	caBasePath := os.Getenv("CA_BASE_PATH")
	if caBasePath == "" {
		caBasePath = "/ca"
	}

	trustedCAs, err := loadTrustedEKCAs(caBasePath)
	if err != nil {
		log.Fatalf("Failed to load EK CAs: %v", err)
	}

	openbaoClient, err := NewOpenBaoClient(baoAddr, baoToken)
	if err != nil {
		log.Fatalf("Failed to create OpenBao client: %v", err)
	}

	// Load agent CA for mTLS client validation
	agentCAPath := os.Getenv("AGENT_CA_PATH")
	if agentCAPath == "" {
		agentCAPath = "/openbao-data/agent-ca.pem"
	}
	agentCAPool, err := LoadCACertPool(agentCAPath)
	if err != nil {
		log.Fatalf("Failed to load agent CA: %v", err)
	}
	log.Printf("Loaded agent CA from: %s", agentCAPath)

	// Request TLS certificate from OpenBao
	ctx := context.Background()
	certPEM, keyPEM, err := openbaoClient.RequestServerCertificate(ctx, "grpc-server", []string{"server", "localhost"})
	if err != nil {
		log.Fatalf("Failed to get server TLS certificate: %v", err)
	}
	log.Printf("Server TLS certificate obtained from OpenBao")

	// Compute and display SPKI pin for TOFU bootstrap
	spkiPin := computeSPKIPinFromPEM(certPEM)
	log.Printf("")
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("Server SPKI Pin: %s", spkiPin)
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("")

	// Create TLS credentials with optional mTLS
	creds, err := NewServerTLSCredentials(certPEM, keyPEM, agentCAPool)
	if err != nil {
		log.Fatalf("Failed to create TLS credentials: %v", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	server := &Server{
		openbaoClient:      openbaoClient,
		orders:             make(map[string]*OrderInfo),
		trustedEKCAs:       trustedCAs,
		allowedEKHashes:    make(map[string]bool),
		activationSessions: make(map[string]*ActivationSession),
		agentCACertPool:    agentCAPool,
	}

	// Create gRPC server with TLS and mTLS interceptor
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(server.MTLSUnaryInterceptor),
	)
	pb.RegisterCertificateServiceServer(grpcServer, server)

	log.Printf("Server ready (TLS enabled)")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
