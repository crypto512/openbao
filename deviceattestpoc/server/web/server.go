package web

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
	"github.com/openbao/openbao/deviceattestpoc/server/events"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

// WebServer handles HTTP requests for the web interface
type WebServer struct {
	db        *db.DB
	templates *template.Template
	sseHub    *events.Hub
	spkiPin   string
	server    *http.Server
}

// Config holds configuration for the web server
type Config struct {
	Port      string
	TLSCert   string
	TLSKey    string
	DB        *db.DB
	SSEHub    *events.Hub
	SPKIPin   string
}

// NewWebServer creates a new web server instance
func NewWebServer(cfg *Config) (*WebServer, error) {
	funcMap := template.FuncMap{
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"formatTime": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.Format("2006-01-02 15:04")
		},
		"certStatus": func(notAfter *time.Time) string {
			if notAfter == nil {
				return "none"
			}
			now := time.Now()
			if notAfter.Before(now) {
				return "expired"
			}
			if notAfter.Before(now.Add(7 * 24 * time.Hour)) {
				return "expiring"
			}
			return "valid"
		},
		"statusBadgeClass": func(status string) string {
			switch status {
			case "pending_approval":
				return "badge-warning"
			case "enrolled":
				return "badge-info"
			case "lak_issued":
				return "badge-primary"
			case "agent_cert_issued":
				return "badge-success"
			default:
				return "badge-secondary"
			}
		},
		"statusLabel": func(status string) string {
			switch status {
			case "pending_approval":
				return "Pending"
			case "enrolled":
				return "Enrolled"
			case "lak_issued":
				return "LAK Issued"
			case "agent_cert_issued":
				return "Agent Cert"
			default:
				return status
			}
		},
		"eventLabel": func(eventType string) string {
			labels := map[string]string{
				"device_enrolled":    "Enrolled",
				"device_approved":    "Approved",
				"device_deleted":     "Deleted",
				"lak_issued":         "LAK Issued",
				"agent_cert_issued":  "Agent Cert",
				"usage_cert_issued":  "Usage Cert",
				"enrollment_failed":  "Enroll Failed",
				"lak_failed":         "LAK Failed",
				"cert_revoked":       "Revoked",
			}
			if label, ok := labels[eventType]; ok {
				return label
			}
			return eventType
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	ws := &WebServer{
		db:        cfg.DB,
		templates: tmpl,
		sseHub:    cfg.SSEHub,
		spkiPin:   cfg.SPKIPin,
	}

	return ws, nil
}

// Start starts the HTTP server
func (ws *WebServer) Start(ctx context.Context, port, certPEM, keyPEM string) error {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ws.server = &http.Server{
		Addr:      ":" + port,
		Handler:   ws.routes(),
		TLSConfig: tlsConfig,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws.server.Shutdown(shutdownCtx)
	}()

	log.Printf("Web interface starting on https://0.0.0.0:%s", port)
	return ws.server.ListenAndServeTLS("", "")
}

// routes sets up the HTTP routes
func (ws *WebServer) routes() http.Handler {
	mux := http.NewServeMux()

	// Dashboard
	mux.HandleFunc("GET /", ws.handleIndex)

	// API endpoints for HTMX
	mux.HandleFunc("GET /api/status", ws.handleGetStatus)
	mux.HandleFunc("GET /api/devices", ws.handleListDevices)
	mux.HandleFunc("POST /api/devices", ws.handleAddDevice)
	mux.HandleFunc("DELETE /api/devices/{id}", ws.handleDeleteDevice)
	mux.HandleFunc("POST /api/devices/{id}/approve", ws.handleApproveDevice)
	mux.HandleFunc("GET /api/audit", ws.handleGetAuditLog)

	// Settings
	mux.HandleFunc("GET /api/settings/auto-approve", ws.handleGetAutoApprove)
	mux.HandleFunc("PUT /api/settings/auto-approve", ws.handleSetAutoApprove)

	// SSE endpoint
	mux.HandleFunc("GET /events", ws.handleSSE)

	return ws.withMiddleware(mux)
}

// withMiddleware wraps the handler with logging and recovery middleware
func (ws *WebServer) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic in %s %s: %v", r.Method, r.URL.Path, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
