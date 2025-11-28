package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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

func loadTrustedEKCAs(caBasePath string) (map[string]*x509.Certificate, error) {
	trustedCAs := make(map[string]*x509.Certificate)

	log.Printf("Loading trusted EK CAs from: %s", caBasePath)

	err := filepath.Walk(caBasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(info.Name()), ".crt") &&
			!strings.HasSuffix(strings.ToLower(info.Name()), ".pem") {
			return nil
		}

		certData, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			return nil
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil
		}

		relPath, _ := filepath.Rel(caBasePath, path)
		caName := strings.TrimSuffix(relPath, filepath.Ext(relPath))
		trustedCAs[caName] = cert
		log.Printf("  Loaded CA: %s", caName)

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

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterCertificateServiceServer(grpcServer, &Server{
		openbaoClient:      openbaoClient,
		orders:             make(map[string]*OrderInfo),
		trustedEKCAs:       trustedCAs,
		allowedEKHashes:    make(map[string]bool),
		activationSessions: make(map[string]*ActivationSession),
	})

	log.Printf("Server ready")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
