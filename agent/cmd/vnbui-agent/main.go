package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"vnbui/agent/internal/api"
	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/heartbeat"
	"vnbui/agent/internal/keystore"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/provider/mock"
	"vnbui/agent/internal/reconcile"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restore"
	tlspkg "vnbui/agent/internal/tls"
	"vnbui/agent/internal/verification"
)

var version = "dev"

// newLibvirtProvider is set by provider_libvirt.go when built with -tags libvirt.
var newLibvirtProvider func(uri string) provider.VMProvider

// newKubevirtProvider is set by provider_kubevirt.go when built with -tags kubevirt.
var newKubevirtProvider func(*config.Config) provider.VMProvider

// newKubevirtBackupExecutor is set by provider_kubevirt.go when built with -tags kubevirt.
var newKubevirtBackupExecutor func(cfg *config.Config, res *resources.Manager, dynClient interface{}, namespace string) backup.ExecutorIface

// newKubevirtRestoreExecutor is set by provider_kubevirt.go when built with -tags kubevirt.
var newKubevirtRestoreExecutor func(cfg *config.Config, res *resources.Manager, dynClient interface{}, namespace string) restore.ExecutorIface

// newKubevirtReconciler is set by provider_kubevirt.go when built with -tags kubevirt.
var newKubevirtReconciler func(dynClient interface{}, namespace string) reconcile.ReconcileFunc

// selectExecutors wires startup from the provider's actual capabilities.
// Historical vmexport providers retain the same KubeVirt executor selection.
func selectExecutors(cfg *config.Config, resMgr *resources.Manager, vmProvider provider.VMProvider) (backup.ExecutorIface, restore.ExecutorIface, reconcile.ReconcileFunc, error) {
	var backupExec backup.ExecutorIface
	var restoreExec restore.ExecutorIface
	var reconcileFunc reconcile.ReconcileFunc

	switch vmProvider.Capabilities().BackupMethod {
	case "kubevirt_pull_transaction", "vmexport":
		kvp, ok := vmProvider.(interface{ DynamicClient() interface{} })
		if !ok {
			return nil, nil, nil, fmt.Errorf("kubevirt provider does not expose DynamicClient")
		}
		dynClient := kvp.DynamicClient()

		if newKubevirtBackupExecutor != nil {
			backupExec = newKubevirtBackupExecutor(cfg, resMgr, dynClient, cfg.KubeNamespace)
			if source, ok := vmProvider.(interface{ CoreClient() interface{} }); ok {
				if sink, ok := backupExec.(interface{ SetCoreClient(interface{}) }); ok {
					sink.SetCoreClient(source.CoreClient())
				}
			}
		} else {
			return nil, nil, nil, fmt.Errorf("kubevirt backup executor not available (binary built without kubevirt tag)")
		}
		if newKubevirtRestoreExecutor != nil {
			restoreExec = newKubevirtRestoreExecutor(cfg, resMgr, dynClient, cfg.KubeNamespace)
		} else {
			restoreExec = restore.NewExecutor(cfg, resMgr)
		}
		if newKubevirtReconciler != nil {
			reconcileFunc = newKubevirtReconciler(dynClient, cfg.KubeNamespace)
		} else {
			reconcileFunc = reconcile.NewLibvirtReconciler(vmProvider)
		}
	case "virtnbdbackup":
		backupExec = backup.NewExecutor(cfg, resMgr)
		restoreExec = restore.NewExecutor(cfg, resMgr)
		reconcileFunc = reconcile.NewLibvirtReconciler(vmProvider)
	default:
		backupExec = backup.NewExecutor(cfg, resMgr)
		restoreExec = restore.NewExecutor(cfg, resMgr)
		reconcileFunc = reconcile.NewLibvirtReconciler(vmProvider)
	}
	return backupExec, restoreExec, reconcileFunc, nil
}

func registrationTLSConfig(cfg *config.Config, journal *tlspkg.Manager) (*tls.Config, error) {
	if cfg.CallbackClientCertFile == "" && cfg.CallbackClientKeyFile == "" {
		return cfg.OutboundTLSConfig()
	}
	if cfg.CallbackClientCertFile == "" || cfg.CallbackClientKeyFile == "" {
		return nil, fmt.Errorf("callback mTLS requires a certificate/key pair")
	}
	if cfg.CallbackClientCertFile != journal.CertPath() || cfg.CallbackClientKeyFile != journal.KeyPath() {
		return nil, fmt.Errorf("fresh callback identity must use journal certificate paths")
	}
	for _, path := range []string{journal.CertPath(), journal.KeyPath()} {
		if _, err := os.Stat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("fresh callback identity requires an empty certificate journal")
		}
	}
	orchestrator, err := url.Parse(cfg.OrchestratorURL)
	if err != nil || orchestrator.Scheme != "https" || orchestrator.Host == "" {
		return nil, fmt.Errorf("certificate bootstrap requires verified HTTPS")
	}
	if cfg.RegistrationKey == "" {
		return nil, fmt.Errorf("certificate bootstrap requires a registration key")
	}
	// Bootstrap needs only immutable server-trust inputs. Config owns runtime
	// locks and scope state; never copy it or clear the live callback identity.
	bootstrap := &config.Config{
		OrchestratorVerifySSL: cfg.OrchestratorVerifySSL,
		TLSCAFile:             cfg.TLSCAFile,
	}
	return bootstrap.OutboundTLSConfig()
}

func orchestratorHTTPClient(callbackTLS *tls.Config) *http.Client {
	// The instrumentation is pass-through when tracing is disabled.
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: otelhttp.NewTransport(&http.Transport{
			TLSClientConfig: callbackTLS,
		}),
	}
}

func main() {
	flag.CommandLine = flag.NewFlagSet("vesta-agent", flag.ExitOnError)
	showVersion := flag.Bool("version", false, "Print version and exit")
	scratchProbe := flag.Bool("scratch-probe", false, "Measure the read-only /scratch mount for backup admission")
	probeReadyFlag := flag.Bool("probe-ready", false, "Probe the local HTTPS listener with the configured client identity")
	enrollClientCertFlag := flag.Bool("enroll-client-cert", false, "Enroll a journal-owned callback certificate while API-key mode is active")
	providerFlag := flag.String("provider", "", "VM provider: libvirt or mock")
	flag.Parse()
	if *scratchProbe {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		if err := operationbudget.ProbeScratch(ctx, "/scratch", os.Stdout); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "scratch filesystem measurement unavailable")
			os.Exit(1)
		}
		return
	}

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Load config
	cfg := config.Load()
	if *probeReadyFlag {
		if err := probeReady(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "agent readiness probe failed:", err)
			os.Exit(1)
		}
		return
	}
	if *enrollClientCertFlag {
		if err := enrollClientCert(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "agent client certificate enrollment failed:", err)
			os.Exit(1)
		}
		fmt.Println("agent client certificate enrolled in journal")
		return
	}
	if *providerFlag != "" {
		cfg.Provider = *providerFlag
	}

	// Setup structured logging
	level := slog.LevelInfo
	switch strings.ToUpper(cfg.LogLevel) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}

	cfg.LogLevelControl = new(slog.LevelVar)
	cfg.LogLevelControl.Set(level)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevelControl})
	slog.SetDefault(slog.New(handler))

	slog.Info("starting vesta-agent",
		"version", version,
		"provider", cfg.Provider,
		"listen", cfg.ListenAddr(),
	)

	// APM / OpenTelemetry (Stage 1 — #33). Complete no-op when
	// OTEL_EXPORTER_OTLP_ENDPOINT is unset — the common customer-site / air-gap
	// case: no exporter, no network, no goroutine.
	otelShutdown, otelErr := initOTel("vesta-agent", slog.Default())
	if otelErr != nil {
		slog.Warn("otel init failed; continuing without tracing", "error", otelErr)
	}
	defer func() { _ = otelShutdown(context.Background()) }()

	// Validate production config
	if err := cfg.ValidateProduction(); err != nil {
		slog.Error("production validation failed", "error", err)
		os.Exit(1)
	}

	// Set agent info metric
	metrics.AgentInfo.WithLabelValues(version, cfg.Hostname).Set(1)

	// Initialize VM provider
	var vmProvider provider.VMProvider
	switch cfg.Provider {
	case "libvirt":
		if newLibvirtProvider != nil {
			slog.Info("using libvirt VM provider", "uri", cfg.LibvirtURI)
			vmProvider = newLibvirtProvider(cfg.LibvirtURI)
		} else {
			slog.Error("libvirt provider not available (binary built without CGO/libvirt tag)")
			os.Exit(1)
		}
	case "kubevirt":
		if newKubevirtProvider != nil {
			slog.Info("using kubevirt VM provider",
				"kubeconfig", cfg.KubeconfigPath,
				"namespace", cfg.KubeNamespace,
			)
			vmProvider = newKubevirtProvider(cfg)
			if scoped, ok := vmProvider.(interface {
				SetNamespaceScope(func() []string, []string)
			}); ok && cfg.NamespaceScope != nil {
				scoped.SetNamespaceScope(cfg.SelectedSourceNamespaces, cfg.NamespaceScope.SourceNamespaces)
			}
		} else {
			slog.Error("kubevirt provider not available (binary built without kubevirt tag)")
			os.Exit(1)
		}
	case "mock":
		slog.Info("using mock VM provider")
		vmProvider = mock.New()
	default:
		slog.Info("using mock VM provider (default)")
		vmProvider = mock.New()
	}

	if err := vmProvider.Connect(); err != nil {
		slog.Error("failed to connect to VM provider", "error", err)
		os.Exit(1)
	}
	defer vmProvider.Disconnect()

	tlsMgr := tlspkg.New("")

	// --- Credential loading ---
	// Priority: env vars > keystore > fresh registration
	// Matches Python: KeyManager.has_key() → load, else register, else warn and continue
	ks := keystore.New(cfg.KeyFilePath, cfg.KeystoreIdentity)
	registered := cfg.AgentID != "" && cfg.AgentAPIKey != ""

	if !registered && ks.Exists() {
		data, err := ks.Load()
		if err != nil {
			slog.Warn("keystore unreadable, will re-register", "error", err)
		} else {
			cfg.AgentID = data.AgentID
			cfg.AgentAPIKey = data.AgentAPIKey
			if data.OrchestratorAPIKey != "" {
				cfg.OrchestratorAPIKey = data.OrchestratorAPIKey
			}
			registered = true
			slog.Info("loaded credentials from keystore", "agent_id", cfg.AgentID)
		}
	}

	// A fresh agent has no journal-owned callback certificate yet. Its scoped
	// registration key may bootstrap over verified HTTPS; all subsequent agent
	// requests must use the certificate returned by that registration. Existing
	// agents never take this branch, even if a registration key remains set.
	var callbackTLS *tls.Config
	var err error
	if registered {
		callbackTLS, err = cfg.OutboundTLSConfig()
	} else {
		callbackTLS, err = registrationTLSConfig(cfg, tlsMgr)
	}
	if err != nil {
		slog.Error("orchestrator TLS configuration unavailable", "error", err)
		os.Exit(1)
	}
	httpClient := orchestratorHTTPClient(callbackTLS)

	if !registered {
		if cfg.RegistrationKey == "" {
			slog.Error("no credentials: set AGENT_ID+AGENT_API_KEY, provide keystore, or set REGISTRATION_KEY")
			os.Exit(1)
		}
		slog.Info("registering with orchestrator", "url", cfg.OrchestratorURL)
		result, err := heartbeat.Register(cfg, vmProvider, version, httpClient)
		if err != nil {
			slog.Error("registration failed", "error", err)
			os.Exit(1)
		}
		cfg.AgentID = result.AgentID
		cfg.AgentAPIKey = result.APIKey
		registered = true
		if err := ks.Save(&keystore.Data{
			AgentID:            result.AgentID,
			AgentAPIKey:        result.APIKey,
			OrchestratorAPIKey: cfg.OrchestratorAPIKey,
		}); err != nil {
			slog.Warn("failed to save keystore (will need re-registration on restart)", "error", err)
		}
		if result.TLS != nil {
			if err := tlsMgr.SaveCerts(
				[]byte(result.TLS.AgentCert),
				[]byte(result.TLS.AgentKey),
				[]byte(result.TLS.CACert),
			); err != nil {
				slog.Error("registered agent certificate could not be saved", "error", err)
				os.Exit(1)
			}
		}
		slog.Info("registered successfully", "agent_id", cfg.AgentID)

		// Registration has committed a new certificate to the durable journal.
		// Refuse to sync inventory or start heartbeat if the configured callback
		// identity is still missing or invalid; never carry bootstrap transport
		// into the normal agent lifetime.
		callbackTLS, err = cfg.OutboundTLSConfig()
		if err != nil {
			slog.Error("registered callback TLS unavailable", "error", err)
			os.Exit(1)
		}
		httpClient.CloseIdleConnections()
		httpClient = orchestratorHTTPClient(callbackTLS)
	}

	// --- VM sync (non-fatal) ---
	if err := heartbeat.SyncVMs(cfg, vmProvider, httpClient); err != nil {
		slog.Warn("initial VM sync failed", "error", err)
	}

	// Resource manager for concurrency control
	resMgr := resources.New(cfg.MaxConcurrentBackups, 1)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Select the provider executors before reporting their activation.
	backupExec, restoreExec, reconcileFunc, err := selectExecutors(cfg, resMgr, vmProvider)
	if err != nil {
		slog.Error("provider executor selection failed", "error", err)
		os.Exit(1)
	}
	transactions, transactional := backupExec.(interface {
		StartStorageTransactions(context.Context) error
		CloseStorageTransactions() error
	})
	activation := map[string]string{}
	if transactional {
		if err := transactions.StartStorageTransactions(ctx); err != nil {
			slog.Error("storage transaction activation unavailable", "error", err)
			activation["storage_transactions"] = "unavailable"
		} else {
			activation["storage_transactions"] = "available"
			defer func() { _ = transactions.CloseStorageTransactions() }()
		}
	}
	if fresh, ok := restoreExec.(interface {
		StartRestores(context.Context) error
		CloseRestores() error
	}); ok {
		if err := fresh.StartRestores(ctx); err != nil {
			slog.Error("fresh restore activation unavailable", "error", err)
			activation["fresh_restore"] = "unavailable"
		} else {
			activation["fresh_restore"] = "available"
			defer func() { _ = fresh.CloseRestores() }()
		}
	}

	// --- Reconciliation (before heartbeat, after registration) ---
	// Matches Python: reconcile_backup_jobs() called before heartbeat.start()
	hbService := heartbeat.New(cfg, httpClient, version)
	hbService.SetDiskAdmissionThreshold(resMgr.DiskAdmissionThreshold)
	hbService.SetCallbacks(
		backupExec.ActiveCount,
		restoreExec.ActiveCount,
		vmProvider.IsConnected,
	)
	if !transactional {
		hbService.SetS3ConfigCallback(backupExec.SetS3Config)
	}

	// Wire backup/restore completion events → heartbeat (triggers immediate delivery)
	eventCb := func(event map[string]interface{}) {
		hbService.QueueEvent(event)
		hbService.SendImmediate()
	}
	backupExec.SetEventCallback(eventCb)
	if observations, ok := backupExec.(interface {
		NativeHoldEvents() []map[string]interface{}
	}); ok {
		hbService.SetBackupObservations(observations.NativeHoldEvents)
	}
	if observations, ok := backupExec.(interface {
		StorageObservationEvents() []map[string]interface{}
	}); ok {
		hbService.SetBackupObservations(observations.StorageObservationEvents)
	}
	restoreExec.SetEventCallback(eventCb)

	resMgr.SetStoragePath(cfg.StorageMeasurementPath())
	if !transactional {
		reconcileResult, err := reconcileFunc(cfg, httpClient, resMgr)
		if err != nil {
			slog.Warn("reconciliation failed", "error", err)
		} else if len(reconcileResult.Events) > 0 {
			// Queue reconciliation events for delivery on first heartbeat.
			for _, event := range reconcileResult.Events {
				hbService.QueueEvent(event)
			}
		}
	}

	// TLS manager for mTLS server mode
	serverOpts := []api.ServerOption{
		api.WithVMProvider(vmProvider),
		api.WithBackupExecutor(backupExec),
		api.WithRestoreExecutor(restoreExec),
		api.WithResourceManager(resMgr),
		api.WithActivationStatus(activation),
	}
	serverTLS, err := agentServerTLSConfig(cfg, tlsMgr)
	if err != nil {
		slog.Error("agent HTTPS configuration unavailable", "error", err)
		os.Exit(1)
	}
	if serverTLS != nil {
		serverOpts = append(serverOpts, api.WithTLSConfig(serverTLS))
		slog.Info("HTTPS server mode enabled", "verify_client", cfg.TLSVerifyClient)
	}
	activation["verification"] = "unavailable"
	if serverTLS != nil && cfg.EnableAPIKeyValidation && cfg.OrchestratorAPIKey != "" && cfg.VerificationTimeoutSeconds > 0 && cfg.VerificationTimeoutSeconds <= 604800 {
		caFile := cfg.NativeRestoreCAFile
		if cfg.Provider == "kubevirt" {
			caFile = cfg.KubevirtRestoreCAFile
		}
		verifier := verification.New(verification.Config{Root: filepath.Join(filepath.Dir(cfg.KeyFilePath), "verifications"), AgentID: cfg.AgentID, Provider: cfg.Provider, CAFile: caFile, Timeout: time.Duration(cfg.VerificationTimeoutSeconds) * time.Second, BudgetPolicy: cfg.SafetyPolicy()})
		if err := verifier.Start(ctx); err != nil {
			slog.Warn("verification activation unavailable")
		} else {
			activation["verification"] = "available"
			serverOpts = append(serverOpts, api.WithVerificationExecutor(verifier))
			defer func() { _ = verifier.Close() }()
		}
	}

	// Renew a journal-managed callback identity even during API-key bootstrap
	// and when the HTTPS serving certificate is a separate site Secret. A
	// site-mounted callback keypair remains the operator's rotation responsibility.
	if (cfg.CallbackClientCertFile == "" && cfg.CallbackClientKeyFile == "") ||
		(cfg.CallbackClientCertFile == tlsMgr.CertPath() && cfg.CallbackClientKeyFile == tlsMgr.KeyPath()) {
		hbService.SetTLSManager(tlsMgr)
	}

	// Create HTTP(S) server with all components
	srv := api.NewServer(cfg, version, serverOpts...)

	// Wire VM lifecycle events → heartbeat
	vmSyncRequests := make(chan struct{}, 1)
	hbService.SetScopeAppliedCallback(func() { heartbeat.RequestVMSync(vmSyncRequests) })
	go heartbeat.RunVMSyncLoop(ctx, vmSyncRequests, cfg, vmProvider, httpClient)
	if err := vmProvider.SubscribeEvents(func(evt provider.VMEvent) {
		heartbeat.RequestVMSync(vmSyncRequests)
		hbService.QueueEvent(map[string]interface{}{
			"type":      string(evt.Type),
			"vm_name":   evt.VMName,
			"detail":    evt.Detail,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		hbService.SendImmediate()
	}); err != nil {
		slog.Warn("failed to subscribe to VM events", "error", err)
	}
	// Cover changes between the startup snapshot and lifecycle subscription.
	// Periodic reconciliation also repairs a failed delivery without a new event.
	heartbeat.RequestVMSync(vmSyncRequests)

	// --- Start heartbeat loop (after reconciliation) ---
	if cfg.HeartbeatEnabled {
		go hbService.Run(ctx)
		slog.Info("heartbeat started", "interval_s", cfg.HeartbeatInterval)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		slog.Info("received shutdown signal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
	case err := <-errCh:
		if err != nil {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	slog.Info("agent stopped")
}

func probeReady(cfg *config.Config) error {
	if !cfg.TLSEnabled || cfg.CallbackClientCertFile == "" || cfg.CallbackClientKeyFile == "" {
		return fmt.Errorf("verified HTTPS client identity required")
	}
	host := cfg.AgentIP
	if host == "" {
		host = cfg.Hostname
	}
	if host == "" {
		return fmt.Errorf("agent address required")
	}
	callbackTLS, err := cfg.OutboundTLSConfig()
	if err != nil {
		return err
	}
	// Probe this pod, not the Service: an unready pod is deliberately absent
	// from Service endpoints. Verify its site certificate against the advertised
	// DNS identity even though the TCP connection stays on loopback.
	callbackTLS.ServerName = host
	endpoint := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.AgentPort)),
		Path:   "/health/ready",
	}
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{TLSClientConfig: callbackTLS},
	}
	response, err := client.Get(endpoint.String())
	if err != nil {
		return fmt.Errorf("verified readiness request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness returned HTTP %d", response.StatusCode)
	}
	return nil
}

func enrollClientCert(cfg *config.Config) error {
	if cfg.CallbackClientCertFile != "" || cfg.CallbackClientKeyFile != "" {
		return fmt.Errorf("enrollment requires API-key bootstrap mode")
	}
	orchestrator, err := url.Parse(cfg.OrchestratorURL)
	if err != nil || orchestrator.Scheme != "https" || orchestrator.Host == "" {
		return fmt.Errorf("verified HTTPS orchestrator URL required")
	}
	if cfg.AgentAPIKey == "" {
		credentials, err := keystore.New(cfg.KeyFilePath, cfg.KeystoreIdentity).Load()
		if err != nil {
			return fmt.Errorf("load registered agent credentials: %w", err)
		}
		cfg.AgentAPIKey = credentials.AgentAPIKey
	}
	if cfg.AgentAPIKey == "" || cfg.Hostname == "" {
		return fmt.Errorf("registered agent key and hostname required")
	}
	callbackTLS, err := cfg.OutboundTLSConfig()
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: callbackTLS},
	}
	return heartbeat.EnrollClientCertificate(cfg, client, tlspkg.New(""))
}

// agentServerTLSConfig accepts either site-mounted certificates or the
// journal-managed certificate pair. An enabled HTTPS listener must never
// degrade to HTTP because a certificate is absent or malformed.
func agentServerTLSConfig(cfg *config.Config, manager *tlspkg.Manager) (*tls.Config, error) {
	if !cfg.TLSEnabled {
		return nil, nil
	}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		return tlspkg.ServerTLSConfigFromFiles(
			cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSClientCAFile, cfg.TLSVerifyClient,
		)
	}
	if !manager.HasCerts() {
		return nil, fmt.Errorf("HTTPS enabled but no agent certificate/key pair is available")
	}
	return manager.ServerTLSConfig(cfg.TLSVerifyClient)
}
