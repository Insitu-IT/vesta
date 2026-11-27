package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/sysutil"
	tlspkg "vnbui/agent/internal/tls"
)

// TLSRenewer abstracts TLS certificate renewal operations.
type TLSRenewer interface {
	HasCerts() bool
	NeedsRenewal() (bool, error)
	GenerateCSR(hostname string) ([]byte, error)
	SaveCerts(cert, key, ca []byte) error
}

// Service manages the heartbeat loop.
type Service struct {
	cfg     *config.Config
	client  *http.Client
	version string

	mu                sync.Mutex
	events            []map[string]interface{}
	backoffFactor     float64
	maxBackoff        float64
	controllerRequest uint64
	controllerApplied uint64

	// Callbacks for dynamic state
	activeBackups          func() int
	activeRestores         func() int
	providerAlive          func() bool
	diskAdmissionThreshold func() float64
	onS3Config             func(map[string]interface{})
	onScopeApplied         func()
	backupObservations     func() []map[string]interface{}

	// TLS certificate renewal
	tlsManager TLSRenewer
}

// New creates a heartbeat service.
func New(cfg *config.Config, client *http.Client, version string) *Service {
	// Callback credentials belong to the configured controller origin.
	clientForHeartbeat := *client
	clientForHeartbeat.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Service{
		cfg:            cfg,
		client:         &clientForHeartbeat,
		version:        version,
		events:         make([]map[string]interface{}, 0),
		backoffFactor:  1.0,
		maxBackoff:     8.0,
		activeBackups:  func() int { return 0 },
		activeRestores: func() int { return 0 },
		providerAlive:  func() bool { return true },
	}
}

// SetCallbacks sets dynamic state callbacks.
func (s *Service) SetCallbacks(backups, restores func() int, providerAlive func() bool) {
	s.activeBackups = backups
	s.activeRestores = restores
	s.providerAlive = providerAlive
}

// SetS3ConfigCallback sets a callback for when S3 config arrives via heartbeat.
func (s *Service) SetS3ConfigCallback(cb func(map[string]interface{})) {
	s.onS3Config = cb
}

// SetScopeAppliedCallback refreshes inventory when an acknowledged selection changes.
func (s *Service) SetScopeAppliedCallback(cb func()) { s.onScopeApplied = cb }

// SetBackupObservations supplies repeatable snapshots on every heartbeat.
// Unlike queued events, failed delivery does not consume these observations.
// Configure before starting the heartbeat service.
func (s *Service) SetBackupObservations(cb func() []map[string]interface{}) {
	s.backupObservations = cb
}

// SetDiskAdmissionThreshold reports the active manager's policy alongside its measurements.
func (s *Service) SetDiskAdmissionThreshold(read func() float64) {
	s.diskAdmissionThreshold = read
}

// SetTLSManager sets the TLS manager for certificate renewal.
func (s *Service) SetTLSManager(m TLSRenewer) {
	s.tlsManager = m
}

// QueueEvent adds an event to be delivered on the next heartbeat.
func (s *Service) QueueEvent(event map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

// Run starts the heartbeat loop. Blocks until context is cancelled.
func (s *Service) Run(ctx context.Context) {
	// Initial heartbeat
	s.sendHeartbeat()

	for {
		interval := time.Duration(s.cfg.HeartbeatIntervalSeconds()) * time.Second
		if interval <= 0 {
			interval = 30 * time.Second
		}
		wait := s.nextHeartbeatWait(interval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			s.sendHeartbeat()
		}
	}
}

// SendImmediate triggers an immediate heartbeat (e.g., after VM event).
func (s *Service) SendImmediate() {
	go s.sendHeartbeat()
}

func (s *Service) observeControllers(sequence uint64, vm, files string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence > s.controllerApplied {
		s.cfg.ObserveControllers(vm, files)
		s.controllerApplied = sequence
	}
}

func (s *Service) sendHeartbeat() {
	// Collect events atomically
	s.mu.Lock()
	queuedEvents := s.events
	s.events = make([]map[string]interface{}, 0)
	s.controllerRequest++
	controllerRequest := s.controllerRequest
	s.mu.Unlock()

	// Repeatable snapshots are regenerated on every send. Keep them out of the
	// retry queue so a long outage cannot accumulate stale copies.
	events := make([]map[string]interface{}, len(queuedEvents))
	copy(events, queuedEvents)
	if s.backupObservations != nil {
		events = append(events, s.backupObservations()...)
	}
	info, _ := sysutil.GetSystemInfo(s.cfg.StorageMeasurementPath())

	ip := s.cfg.AgentIP
	if ip == "" {
		ip = sysutil.PrimaryIP()
	}

	port := s.cfg.AgentPort
	v := s.version
	cpuCores := info.CPUCores
	load15m := info.LoadAverage15m
	storagePath := s.cfg.StorageMeasurementPath()
	storageFree, storageTotal, diskPercent := info.DiskValues()
	capabilities := s.cfg.CapabilityReport()
	providerAlive := s.providerAlive()
	if s.cfg.Provider == "libvirt" && len(s.cfg.ManagedFileSets) > 0 {
		capabilities["vm_workload_available"] = providerAlive
	}
	if capabilities != nil && s.diskAdmissionThreshold != nil {
		if limit := s.diskAdmissionThreshold(); limit > 0 && limit <= 100 {
			capabilities["storage_admission_used_percent"] = limit
		}
	}

	hb := models.AgentHeartbeat{
		Scope:                   s.cfg.ScopeReport(),
		Capabilities:            capabilities,
		Provider:                s.cfg.Provider,
		StorageRole:             s.cfg.StorageRole(),
		StorageMeasurementError: info.DiskError,
		Status:                  "online",
		Version:                 &v,
		IPAddress:               &ip,
		Port:                    &port,
		ActiveBackups:           s.activeBackups(),
		ActiveRestores:          s.activeRestores(),
		CPUUsagePercent:         &info.CPUPercent,
		MemoryUsagePercent:      &info.MemoryPercent,
		CPUCores:                &cpuCores,
		LoadAverage15m:          &load15m,
		DiskUsagePercent:        diskPercent,
		BackupStoragePath:       &storagePath,
		BackupStorageFreeBytes:  storageFree,
		BackupStorageTotalBytes: storageTotal,
		LibvirtAccessible:       providerAlive,
		ProviderAccessible:      providerAlive,
		Events:                  events,
	}

	// Update Prometheus gauges
	metrics.SystemCPUPercent.Set(info.CPUPercent)
	metrics.SystemMemoryPercent.Set(info.MemoryPercent)
	if info.DiskKnown {
		metrics.SystemDiskPercent.WithLabelValues(storagePath).Set(info.DiskPercent)
		metrics.SystemDiskBytes.WithLabelValues(storagePath, "free").Set(float64(info.DiskFreeBytes))
		metrics.SystemDiskBytes.WithLabelValues(storagePath, "total").Set(float64(info.DiskTotalBytes))
	} else {
		metrics.SystemDiskPercent.DeleteLabelValues(storagePath)
		metrics.SystemDiskBytes.DeleteLabelValues(storagePath, "free")
		metrics.SystemDiskBytes.DeleteLabelValues(storagePath, "total")
	}
	metrics.SystemUptimeSeconds.Set(float64(info.UptimeSeconds))
	metrics.ActiveBackups.Set(float64(hb.ActiveBackups))
	metrics.ActiveRestores.Set(float64(hb.ActiveRestores))
	if providerAlive {
		metrics.LibvirtConnectionStatus.Set(1)
		metrics.ProviderConnectionStatus.Set(1)
	} else {
		metrics.LibvirtConnectionStatus.Set(0)
		metrics.ProviderConnectionStatus.Set(0)
	}

	body, err := json.Marshal(hb)
	if err != nil {
		slog.Error("marshal heartbeat", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/health/agents/%s/heartbeat", s.cfg.OrchestratorURL, s.cfg.AgentID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		slog.Error("create heartbeat request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", s.cfg.AgentAPIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("heartbeat failed", "error", err)
		s.increaseBackoff()
		metrics.HeartbeatFailureTotal.WithLabelValues("connection").Inc()

		// Re-queue events for next attempt
		if len(queuedEvents) > 0 {
			s.mu.Lock()
			s.events = append(queuedEvents, s.events...)
			s.mu.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	verified := req.URL.Scheme == "https" && req.URL.User == nil && resp.Request != nil &&
		resp.Request.URL != nil && resp.Request.URL.String() == req.URL.String() && resp.TLS != nil &&
		len(resp.TLS.VerifiedChains) > 0 && len(resp.TLS.VerifiedChains[0]) > 0 &&
		s.cfg.AgentID != "" && s.cfg.AgentAPIKey != ""
	if resp.StatusCode != http.StatusOK {
		if verified && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			s.observeControllers(controllerRequest, "", "")
		}
		respBody, _ := io.ReadAll(resp.Body)
		slog.Warn("heartbeat rejected",
			"status", resp.StatusCode,
			"body", string(respBody),
		)
		s.increaseBackoff()
		metrics.HeartbeatFailureTotal.WithLabelValues(fmt.Sprintf("http_%d", resp.StatusCode)).Inc()
		return
	}

	// Parse response
	var hbResp models.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hbResp); err != nil {
		if verified {
			s.observeControllers(controllerRequest, "", "")
		}
		slog.Warn("parse heartbeat response", "error", err)
		return
	}

	filePin, _ := hbResp.Config["file_controller_sha256"].(string)
	vmPin, _ := hbResp.Config["vm_controller_sha256"].(string)
	delete(hbResp.Config, "file_controller_sha256")
	delete(hbResp.Config, "vm_controller_sha256")
	trustedReply := verified && hbResp.Status == "ok" && hbResp.AgentID == s.cfg.AgentID
	if !trustedReply {
		vmPin, filePin = "", ""
	}
	s.observeControllers(controllerRequest, vmPin, filePin)

	// Apply remote config
	if len(hbResp.Config) > 0 {
		priorScope := s.cfg.ScopeReport()
		applied, skipped := s.cfg.ApplyRemoteConfig(hbResp.Config)
		currentScope := s.cfg.ScopeReport()
		if s.onScopeApplied != nil && currentScope != nil && priorScope["applied_revision"] != currentScope["applied_revision"] {
			s.onScopeApplied()
		}
		if len(applied) > 0 {
			slog.Info("applied remote config", "applied", applied, "skipped", skipped)
		}
	}

	// Apply S3 config from heartbeat response
	if trustedReply && s.onS3Config != nil && hbResp.S3Config != nil {
		s.onS3Config(hbResp.S3Config)
	}

	// Reset backoff on success
	s.resetBackoff()
	metrics.HeartbeatSuccessTotal.Inc()

	// Check certificate renewal
	if s.tlsManager != nil && s.tlsManager.HasCerts() {
		if needs, _ := s.tlsManager.NeedsRenewal(); needs {
			s.renewCertificate()
		}
	}

	slog.Debug("heartbeat sent",
		"events_delivered", len(events),
		"config_keys", len(hbResp.Config),
	)
}

func (s *Service) renewCertificate() {
	slog.Info("certificate needs renewal, generating CSR")

	csrPEM, err := s.tlsManager.GenerateCSR(s.cfg.Hostname)
	if err != nil {
		slog.Warn("CSR generation failed", "error", err)
		return
	}
	certificate, err := requestCertificate(s.cfg, s.client, csrPEM)
	if err != nil {
		slog.Warn("certificate renewal failed", "error", err)
		return
	}
	if err := s.tlsManager.SaveCerts(certificate, nil, nil); err != nil {
		slog.Warn("save renewed certificate failed", "error", err)
		return
	}

	slog.Info("certificate renewed successfully")
}

// EnrollClientCertificate issues a first journal-owned callback identity for
// an already registered agent while API-key bootstrap is still active.
func EnrollClientCertificate(cfg *config.Config, client *http.Client, manager *tlspkg.Manager) error {
	if manager.HasCerts() {
		return fmt.Errorf("agent client certificate already exists")
	}
	if _, err := manager.GenerateKeyPair(); err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	csr, err := manager.GenerateCSR(cfg.Hostname)
	if err != nil {
		return err
	}
	caURL := fmt.Sprintf("%s/api/v1/pki/ca", cfg.OrchestratorURL)
	response, err := client.Get(caURL)
	if err != nil {
		return fmt.Errorf("download agent CA: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download agent CA: HTTP %d", response.StatusCode)
	}
	ca, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read agent CA: %w", err)
	}
	certificate, err := requestCertificate(cfg, client, csr)
	if err != nil {
		return err
	}
	if err := manager.SaveCerts(certificate, nil, ca); err != nil {
		return fmt.Errorf("save client certificate: %w", err)
	}
	return nil
}

func requestCertificate(cfg *config.Config, client *http.Client, csrPEM []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/pki/renew", cfg.OrchestratorURL)
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", cfg.AgentAPIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificate request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate request rejected: HTTP %d", resp.StatusCode)
	}
	var result struct {
		Certificate string `json:"cert_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse certificate response: %w", err)
	}
	if result.Certificate == "" {
		return nil, fmt.Errorf("certificate response is empty")
	}
	return []byte(result.Certificate), nil
}

func (s *Service) increaseBackoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backoffFactor = math.Min(s.backoffFactor*2, s.maxBackoff)
	slog.Debug("heartbeat backoff increased", "factor", s.backoffFactor)
}

func (s *Service) resetBackoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backoffFactor = 1.0
}

// Snapshot backoff under the same lock used by immediate and regular sends.
// Do not retain the lock while waiting or performing network I/O.
func (s *Service) nextHeartbeatWait(interval time.Duration) time.Duration {
	s.mu.Lock()
	factor := s.backoffFactor
	s.mu.Unlock()
	return time.Duration(float64(interval) * factor)
}
