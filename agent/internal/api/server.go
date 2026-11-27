package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restore"
)

// Server is the HTTP server for the agent API.
type Server struct {
	cfg    *config.Config
	router chi.Router
	srv    *http.Server
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, version string, opts ...ServerOption) *Server {
	o := &serverOptions{}
	for _, opt := range opts {
		opt(o)
	}

	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RealIP)
	r.Use(RequestLogger)

	// Health endpoints (no auth)
	health := NewHealthHandler(cfg, version)
	if o.resourceMgr != nil {
		health.SetResources(o.resourceMgr)
	}
	health.SetActivation(o.activation)
	health.vmAvailable = o.vmAvailable
	r.Get("/health", health.Health)
	r.Get("/health/ready", health.Ready)

	// Metrics endpoint (no auth)
	r.Handle("/metrics", MetricsHandler())

	// Authenticated API routes
	r.Route("/api", func(r chi.Router) {
		// IP whitelist + orchestrator key auth
		if len(cfg.AllowedOrchestratorIPs) > 0 {
			r.Use(IPWhitelist(cfg.AllowedOrchestratorIPs))
		}
		if cfg.EnableAPIKeyValidation && cfg.OrchestratorAPIKey != "" {
			r.Use(OrchestratorKeyAuth(cfg.OrchestratorAPIKey))
		}

		vm := r.With(controllerAuth(cfg, o.tlsConfig, config.VMController))
		files := r.With(controllerAuth(cfg, o.tlsConfig, config.FileController))
		common := r.With(controllerAuth(cfg, o.tlsConfig, config.EitherController))

		r.Get("/health/detailed", health.Detailed)
		r.Get("/health/capacity", health.Capacity)
		common.Get("/version", health.Version)

		if o.vmAvailable != nil && o.vmProvider == nil {
			// A mixed installation still owns its VM operations while libvirt is down.
			// An unavailable response lets callers keep their accepted work for recovery.
			unavailable := func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "VM workload unavailable. Restart the agent after libvirt recovers."})
			}
			for _, prefix := range []string{"/vms", "/backups", "/restores", "/verifications"} {
				r.HandleFunc(prefix, unavailable)
				r.HandleFunc(prefix+"/*", unavailable)
			}
		}

		// VM endpoints
		if o.vmProvider != nil {
			vmh := NewVMHandler(o.vmProvider)
			r.Get("/vms", requireVMAvailability(o.vmAvailable, vmh.ListVMs))
			r.Get("/vms/discover", requireVMAvailability(o.vmAvailable, vmh.DiscoverVMs))
			r.Get("/vms/{name}", requireVMAvailability(o.vmAvailable, vmh.GetVM))
		}

		// Backup endpoints
		if o.backupExecutor != nil {
			bh := NewBackupHandler(o.backupExecutor)
			// The ordinary API can still serve other provider endpoints under
			// their existing settings. Transaction activation never inherits its
			// empty-key or HTTP fallback.
			bh.storageTransactionsSecure = cfg.EnableAPIKeyValidation && cfg.OrchestratorAPIKey != "" && o.tlsConfig != nil
			vm.Post("/backups", requireVMAvailability(o.vmAvailable, bh.StartBackup))
			vm.Post("/backups/{id}/retire", bh.RetireStorageTransaction)
			r.Get("/backups/{id}", bh.GetBackup)
			r.Delete("/backups/{id}", bh.CancelBackup)
			vm.Post("/backups/{id}/upload", bh.StartUpload)
			r.Get("/backups/{id}/stream", bh.StreamProgress)
		}

		// Restore endpoints
		if o.restoreExecutor != nil {
			rh := NewRestoreHandler(o.restoreExecutor)
			rh.freshSecure = cfg.EnableAPIKeyValidation && cfg.OrchestratorAPIKey != "" && o.tlsConfig != nil
			vm.Post("/restores", requireVMAvailability(o.vmAvailable, rh.StartRestore))
			vm.Get("/restores/{id}", rh.GetRestore)
			r.Get("/restores/{id}/stream", rh.StreamProgress)
		}
		if o.fileBackupExecutor != nil {
			h := fileBackupHandler{executor: o.fileBackupExecutor}
			files.Post("/file-backups", h.submit)
			files.Get("/file-backups/{id}", h.get)
		}
		if o.verificationExecutor != nil {
			h := &VerificationHandler{executor: o.verificationExecutor, secure: cfg.EnableAPIKeyValidation && cfg.OrchestratorAPIKey != "" && o.tlsConfig != nil, agentID: cfg.AgentID, provider: cfg.Provider}
			vm.Get("/verifications/capability", h.Capability)
			vm.Post("/verifications", h.Submit)
			vm.Get("/verifications/{id}", h.Get)
			vm.Post("/verifications/{id}/cancel", h.Cancel)
		}
	})

	s := &Server{
		cfg:    cfg,
		router: r,
	}

	s.srv = &http.Server{
		Addr: cfg.ListenAddr(),
		// otelhttp instruments the inbound API (server spans + traceparent
		// extraction). Silent pass-through when OTel tracing is disabled.
		Handler:      otelhttp.NewHandler(r, "vesta-agent"),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE requires no write timeout
		IdleTimeout:  120 * time.Second,
	}

	if o.tlsConfig != nil {
		s.srv.TLSConfig = o.tlsConfig
	}

	return s
}

// ServerOption configures optional server dependencies.
type ServerOption func(*serverOptions)

type serverOptions struct {
	vmProvider           provider.VMProvider
	vmAvailable          func() bool
	backupExecutor       backup.ExecutorIface
	restoreExecutor      restore.ExecutorIface
	fileBackupExecutor   fileBackupExecutor
	verificationExecutor VerificationExecutor
	resourceMgr          *resources.Manager
	tlsConfig            *tls.Config
	activation           map[string]string
}

// WithVMProvider sets the VM provider for the server.
func WithVMProvider(p provider.VMProvider) ServerOption {
	return func(o *serverOptions) {
		o.vmProvider = p
	}
}

// WithVMAvailability gates new VM operations and reports readiness on mixed hosts.
func WithVMAvailability(available func() bool) ServerOption {
	return func(o *serverOptions) { o.vmAvailable = available }
}

func requireVMAvailability(available func() bool, next http.HandlerFunc) http.HandlerFunc {
	if available == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !available() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"detail": "VM workload unavailable. Restart vesta-agent after libvirt recovers.",
			})
			return
		}
		next(w, r)
	}
}

// WithBackupExecutor sets the backup executor for the server.
func WithBackupExecutor(e backup.ExecutorIface) ServerOption {
	return func(o *serverOptions) {
		o.backupExecutor = e
	}
}

// WithRestoreExecutor sets the restore executor for the server.
func WithRestoreExecutor(e restore.ExecutorIface) ServerOption {
	return func(o *serverOptions) {
		o.restoreExecutor = e
	}
}

func WithFileBackupExecutor(e fileBackupExecutor) ServerOption {
	return func(o *serverOptions) { o.fileBackupExecutor = e }
}

func WithVerificationExecutor(e VerificationExecutor) ServerOption {
	return func(o *serverOptions) { o.verificationExecutor = e }
}

// WithResourceManager sets the resource manager for capacity reporting.
func WithResourceManager(r *resources.Manager) ServerOption {
	return func(o *serverOptions) {
		o.resourceMgr = r
	}
}

// WithActivationStatus exposes startup executor availability in authenticated
// detailed health. It does not alter liveness or readiness for other services.
func WithActivationStatus(status map[string]string) ServerOption {
	return func(o *serverOptions) {
		o.activation = status
	}
}

// WithTLSConfig sets the TLS configuration for HTTPS server mode.
func WithTLSConfig(tc *tls.Config) ServerOption {
	return func(o *serverOptions) {
		o.tlsConfig = tc
	}
}

// Start begins listening. Blocks until the server stops.
func (s *Server) Start() error {
	if s.srv.TLSConfig != nil {
		slog.Info("starting HTTPS server (mTLS)", "addr", s.srv.Addr)
		err := s.srv.ListenAndServeTLS("", "") // certs already in TLSConfig
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("server error: %w", err)
	}

	slog.Info("starting HTTP server", "addr", s.srv.Addr)
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return fmt.Errorf("server error: %w", err)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down HTTP server")
	return s.srv.Shutdown(ctx)
}
