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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/uuid"
	"github.com/openbao/openbao/deviceattestpoc/server/db"
	"github.com/openbao/openbao/deviceattestpoc/server/events"
	pb "github.com/openbao/openbao/deviceattestpoc/proto"
	"github.com/openbao/openbao/deviceattestpoc/server/web"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

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
	openbaoClient   *OpenBaoClient
	trustedEKCAs    map[string]*x509.Certificate
	agentCACertPool *x509.CertPool
	db              *db.DB
	sseHub          *events.Hub
}

func (s *Server) RequestCertificate(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	usage := req.Usage
	if usage == "" {
		usage = "ipsec-vpn"
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

	if err := s.db.CreateOrder(order.OrderID, req.CommonName, order); err != nil {
		log.Printf("Failed to persist order: %v", err)
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

	orderInfo, err := s.db.GetOrder(req.OrderId)
	if err != nil || orderInfo == nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: "order not found"}, nil
	}

	var order ACMEOrder
	if err := orderInfo.UnmarshalOrderData(&order); err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: "invalid order data"}, nil
	}

	if err := s.db.UpdateOrderCSR(req.OrderId, req.CsrPem); err != nil {
		log.Printf("Failed to update order CSR: %v", err)
	}

	if err := s.openbaoClient.FinalizeOrder(ctx, order.FinalizeURL, req.CsrPem); err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	return &pb.CertResponse{Status: "processing", OrderId: req.OrderId}, nil
}

func (s *Server) GetCertificate(ctx context.Context, req *pb.GetCertRequest) (*pb.CertResponse, error) {
	log.Printf("GetCertificate: orderID=%s", req.OrderId)

	status, err := s.openbaoClient.GetOrderStatus(ctx, req.OrderId)
	log.Printf("GetCertificate: status=%s, err=%v", status, err)

	if status != "valid" {
		return &pb.CertResponse{Status: status, OrderId: req.OrderId}, nil
	}

	cert, chain, err := s.openbaoClient.GetCertificate(ctx, req.OrderId)
	if err != nil {
		return &pb.CertResponse{Status: "error", OrderId: req.OrderId, Error: err.Error()}, nil
	}

	orderInfo, _ := s.db.GetOrder(req.OrderId)
	if orderInfo != nil {
		block, _ := pem.Decode([]byte(cert))
		if block != nil {
			if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
				ekHash := strings.TrimPrefix(orderInfo.CommonName, "agent-")
				s.db.UpdateAgentCertValidity(ekHash, parsedCert.NotBefore, parsedCert.NotAfter)
				s.db.CreateAuditEntry(db.EventAgentCertIssued, nil, orderInfo.CommonName, "Agent certificate issued via ACME", getClientIP(ctx), true)
				s.sseHub.BroadcastAll()
			}
		}
		s.db.DeleteOrder(req.OrderId)
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
		s.db.CreateAuditEntry(db.EventEnrollmentFailed, nil, "", err.Error(), getClientIP(ctx), false)
		return &pb.EnrollmentResponse{Status: "error", Error: err.Error()}, nil
	}

	ekHash, err := ComputeEKHashBase64(ekCert)
	if err != nil {
		return &pb.EnrollmentResponse{Status: "error", Error: err.Error()}, nil
	}

	existingDevice, _ := s.db.GetDeviceByEKHash(ekHash)
	if existingDevice != nil {
		// Device already exists - update status to provisioned if it was only registered
		if existingDevice.Status == db.StatusRegistered {
			s.db.UpdateDeviceStatusByEKHash(ekHash, db.StatusProvisioned)
			s.db.CreateAuditEntry(db.EventDeviceEnrolled, &existingDevice.ID, ekHash, "Device provisioned via da-init", getClientIP(ctx), true)
			s.sseHub.BroadcastAll()
			log.Printf("Device provisioned: %s (was registered)", ekHash)
		} else {
			s.db.UpdateLastSeen(ekHash)
			log.Printf("Device already provisioned: %s", ekHash)
		}
		return &pb.EnrollmentResponse{
			Status:              "success",
			PermanentIdentifier: ekHash,
		}, nil
	}

	autoApprove, _ := s.db.GetAutoApprove()
	status := db.StatusRegistered
	if autoApprove {
		status = db.StatusProvisioned
	}

	fingerprint := ekHash
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}

	device, err := s.db.CreateDevice(ekHash, fingerprint, req.DeviceDescription, status)
	if err != nil {
		log.Printf("Failed to create device: %v", err)
		return &pb.EnrollmentResponse{Status: "error", Error: "failed to provision device"}, nil
	}

	s.db.CreateAuditEntry(db.EventDeviceEnrolled, &device.ID, ekHash, fmt.Sprintf("Device provisioned (auto-approve: %v)", autoApprove), getClientIP(ctx), true)
	s.sseHub.BroadcastAll()

	pendingApproval := status == db.StatusRegistered
	log.Printf("Device provisioned: %s (status: %s, pending_approval: %v)", ekHash, status, pendingApproval)
	return &pb.EnrollmentResponse{
		Status:              "success",
		PermanentIdentifier: ekHash,
		PendingApproval:     pendingApproval,
	}, nil
}

func (s *Server) ProvisionLAK(ctx context.Context, req *pb.ProvisionLAKRequest) (*pb.ProvisionLAKResponse, error) {
	log.Printf("ProvisionLAK: permanentID=%s", req.PermanentIdentifier)

	allowed, err := s.db.IsDeviceAllowed(req.PermanentIdentifier)
	if err != nil || !allowed {
		return &pb.ProvisionLAKResponse{Status: "error", Error: "device not registered or provisioned"}, nil
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
	if err := s.db.CreateActivationSession(sessionID, req.PermanentIdentifier, req.AkParameters, req.EkCertPem, secret); err != nil {
		log.Printf("Failed to create activation session: %v", err)
		return &pb.ProvisionLAKResponse{Status: "error", Error: "failed to create session"}, nil
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

	session, err := s.db.GetActivationSession(req.SessionId)
	if err != nil || session == nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: "invalid session"}, nil
	}

	if session.IsExpired() {
		s.db.DeleteActivationSession(req.SessionId)
		return &pb.ActivateCredentialResponse{Status: "error", Error: "session expired"}, nil
	}

	if string(req.DecryptedSecret) != string(session.ExpectedSecret) {
		s.db.DeleteActivationSession(req.SessionId)
		s.db.CreateAuditEntry(db.EventLAKFailed, nil, session.PermanentID, "Secret verification failed", getClientIP(ctx), false)
		return &pb.ActivateCredentialResponse{Status: "error", Error: "secret verification failed"}, nil
	}

	log.Printf("Secret verified - AK-EK binding proven")
	s.db.DeleteActivationSession(req.SessionId)

	var akParams attest.AttestationParameters
	if err := json.Unmarshal(session.AKParameters, &akParams); err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to parse AK parameters: %v", err)}, nil
	}

	akPubKey, err := attest.ParseAKPublic(akParams.Public)
	if err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to parse AK public: %v", err)}, nil
	}

	sanURI := fmt.Sprintf("urn:permanent-identifier:%s", session.PermanentID)
	csrPEM, err := BuildUnsignedCSR(akPubKey.Public, "", []string{sanURI})
	if err != nil {
		return &pb.ActivateCredentialResponse{Status: "error", Error: fmt.Sprintf("failed to build CSR: %v", err)}, nil
	}

	log.Printf("Built unsigned CSR for AK with permanent identifier URI: %s", sanURI)

	lakCertPEM, lakRootCAPEM, err := s.openbaoClient.SignLAKCertificate(ctx, session.PermanentID, csrPEM)
	if err != nil {
		s.db.CreateAuditEntry(db.EventLAKFailed, nil, session.PermanentID, err.Error(), getClientIP(ctx), false)
		return &pb.ActivateCredentialResponse{Status: "error", Error: err.Error()}, nil
	}

	block, _ := pem.Decode([]byte(lakCertPEM))
	var notBefore, notAfter string
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			notBefore = cert.NotBefore.Format(time.RFC3339)
			notAfter = cert.NotAfter.Format(time.RFC3339)
			s.db.UpdateLAKCertValidity(session.PermanentID, cert.NotBefore, cert.NotAfter)
		}
	}

	device, _ := s.db.GetDeviceByEKHash(session.PermanentID)
	var deviceID *int64
	if device != nil {
		deviceID = &device.ID
	}
	s.db.CreateAuditEntry(db.EventLAKIssued, deviceID, session.PermanentID, "LAK certificate issued", getClientIP(ctx), true)
	s.sseHub.BroadcastAll()

	log.Printf("LAK certificate issued: %s", session.PermanentID)
	return &pb.ActivateCredentialResponse{
		Status:            "success",
		LakCertificatePem: lakCertPEM,
		LakRootCaPem:      lakRootCAPEM,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
	}, nil
}

func (s *Server) IssueCertificate(ctx context.Context, req *pb.IssueCertRequest) (*pb.IssueCertResponse, error) {
	clientCert := GetClientCert(ctx)
	if clientCert == nil {
		return &pb.IssueCertResponse{Status: "error", Error: "no client certificate"}, nil
	}

	permanentID := ExtractPermanentIDFromCert(clientCert)
	log.Printf("IssueCertificate: usage=%s, requester=%s", req.Usage, permanentID)

	usageConfig, err := GetUsageConfig(req.Usage)
	if err != nil {
		return &pb.IssueCertResponse{Status: "error", Error: err.Error()}, nil
	}

	if req.CsrPem == "" {
		return &pb.IssueCertResponse{Status: "error", Error: "CSR is required"}, nil
	}

	certPEM, chainPEM, caPEM, err := s.openbaoClient.SignCertificate(ctx, usageConfig.PKIPath, usageConfig.Role, req.CsrPem, "72h")
	if err != nil {
		log.Printf("IssueCertificate failed: %v", err)
		return &pb.IssueCertResponse{Status: "error", Error: err.Error()}, nil
	}

	block, _ := pem.Decode([]byte(certPEM))
	var notBefore, notAfter string
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			notBefore = cert.NotBefore.Format(time.RFC3339)
			notAfter = cert.NotAfter.Format(time.RFC3339)

			device, _ := s.db.GetDeviceByEKHash(permanentID)
			if device != nil {
				s.db.CreateUsageCertificate(device.ID, req.Usage, "", cert.NotBefore, cert.NotAfter)
				s.db.CreateAuditEntry(db.EventUsageCertIssued, &device.ID, permanentID, fmt.Sprintf("Usage: %s", req.Usage), getClientIP(ctx), true)
				s.sseHub.BroadcastAuditUpdate()
			}
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

func parseCertificateAuto(data []byte, ext string) (*x509.Certificate, error) {
	ext = strings.ToLower(ext)

	if ext == ".der" {
		return x509.ParseCertificate(data)
	}

	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

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

func getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	webPort := os.Getenv("WEB_PORT")
	if webPort == "" {
		webPort = "8443"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/data/db/devices.db"
	}

	baoAddr := os.Getenv("BAO_ADDR")
	if baoAddr == "" {
		log.Fatal("BAO_ADDR not set")
	}

	baoToken := os.Getenv("BAO_TOKEN")
	if baoToken == "" {
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

	log.Printf("Starting server on gRPC port %s, web port %s", port, webPort)
	log.Printf("OpenBao: %s", baoAddr)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()
	database.StartCleanupRoutine(ctx)
	log.Printf("Database initialized: %s", dbPath)

	sseHub := events.NewHub()

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

	agentCAPath := os.Getenv("AGENT_CA_PATH")
	if agentCAPath == "" {
		agentCAPath = "/openbao-data/agent-ca.pem"
	}
	agentCAPool, err := LoadCACertPool(agentCAPath)
	if err != nil {
		log.Fatalf("Failed to load agent CA: %v", err)
	}
	log.Printf("Loaded agent CA from: %s", agentCAPath)

	certManager := NewServerCertManager(database, openbaoClient)
	certPEM, keyPEM, err := certManager.GetOrCreateCertificate(ctx, "grpc-server", "grpc-server", []string{"server", "localhost"})
	if err != nil {
		log.Fatalf("Failed to get server TLS certificate: %v", err)
	}

	spkiPin := computeSPKIPinFromPEM(certPEM)
	database.SetServerSPKI(spkiPin)

	log.Printf("")
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("Server SPKI Pin: %s", spkiPin)
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("")

	creds, err := NewServerTLSCredentials(certPEM, keyPEM, agentCAPool)
	if err != nil {
		log.Fatalf("Failed to create TLS credentials: %v", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	server := &Server{
		openbaoClient:   openbaoClient,
		trustedEKCAs:    trustedCAs,
		agentCACertPool: agentCAPool,
		db:              database,
		sseHub:          sseHub,
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(server.MTLSUnaryInterceptor),
	)
	pb.RegisterCertificateServiceServer(grpcServer, server)

	webServer, err := web.NewWebServer(&web.Config{
		Port:    webPort,
		DB:      database,
		SSEHub:  sseHub,
		SPKIPin: spkiPin,
	})
	if err != nil {
		log.Fatalf("Failed to create web server: %v", err)
	}

	go func() {
		if err := webServer.Start(ctx, webPort, certPEM, keyPEM); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("Server ready (gRPC: %s, Web: %s)", port, webPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
