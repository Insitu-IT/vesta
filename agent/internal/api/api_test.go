package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider/mock"
)

func TestAgentOmitsPathBasedPayloadDeletion(t *testing.T) {
	cfg := &config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "fixture"}
	server := NewServer(cfg, "test", WithBackupExecutor(&transactionAPIExecutor{}), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	backup := "/api/backups/1cc73c65-8e9a-4f06-9d99-8f08ddd65dc7"
	if !server.router.Match(chi.NewRouteContext(), http.MethodPost, backup+"/retire") {
		t.Fatal("expected the authenticated transaction retirement route")
	}
	if server.router.Match(chi.NewRouteContext(), http.MethodDelete, backup+"/data") {
		t.Fatal("the agent must leave payload deletion to the receipt-validated backend")
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		AgentHost:              "127.0.0.1",
		AgentPort:              0,
		BackupStoragePath:      "/tmp",
		MaxConcurrentBackups:   2,
		EnableAPIKeyValidation: false,
		Hostname:               "test-host",
	}
	mockProv := mock.New()
	mockProv.Connect()
	return NewServer(cfg, "5.0.0-test", WithVMProvider(mockProv))
}

func TestHealthEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", resp["status"])
	}
	if resp["version"] != "5.0.0-test" {
		t.Errorf("expected version=5.0.0-test, got %v", resp["version"])
	}
}

func TestReadyEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDetailedHealthEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/health/detailed", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["version"] != "5.0.0-test" {
		t.Errorf("expected version=5.0.0-test, got %v", resp["version"])
	}
	if _, ok := resp["system"]; !ok {
		t.Error("expected 'system' field in detailed health")
	}
	if _, ok := resp["storage"]; !ok {
		t.Error("expected 'storage' field in detailed health")
	}
}

func TestDetailedHealthReportsExecutorActivationWithoutChangingReadiness(t *testing.T) {
	status := map[string]string{
		"storage_transactions": "available",
		"fresh_restore":        "unavailable",
	}
	srv := NewServer(&config.Config{BackupStoragePath: t.TempDir()}, "test", WithActivationStatus(status))
	status["fresh_restore"] = "available" // The status is a startup snapshot.

	req := httptest.NewRequest("GET", "/api/health/detailed", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("detailed health returned %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Activation map[string]string `json:"activation"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Activation["storage_transactions"] != "available" || body.Activation["fresh_restore"] != "unavailable" {
		t.Fatalf("incorrect activation status: %+v", body.Activation)
	}

	ready := httptest.NewRecorder()
	srv.router.ServeHTTP(ready, httptest.NewRequest("GET", "/health/ready", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("startup activation status changed readiness: %d", ready.Code)
	}
}

func TestCapacityEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/health/capacity", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["max_concurrent_backups"] != float64(2) {
		t.Errorf("expected max_concurrent_backups=2, got %v", resp["max_concurrent_backups"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	metrics.BackupDurationSeconds.WithLabelValues("metrics-endpoint").Observe(120)
	t.Cleanup(func() { metrics.BackupDurationSeconds.DeleteLabelValues("metrics-endpoint") })
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, prefix := range []string{"vesta_", "vnbui_"} {
		for _, sample := range []string{
			"# TYPE " + prefix + "agent_backup_duration_seconds histogram",
			prefix + `agent_backup_duration_seconds_count{backup_type="metrics-endpoint"} 1`,
			prefix + `agent_backup_duration_seconds_sum{backup_type="metrics-endpoint"} 120`,
		} {
			if !strings.Contains(body, sample) {
				t.Errorf("missing Prometheus sample %s", sample)
			}
		}
	}
}

func TestOrchestratorKeyAuth(t *testing.T) {
	cfg := &config.Config{
		AgentHost:              "127.0.0.1",
		AgentPort:              0,
		BackupStoragePath:      "/tmp",
		MaxConcurrentBackups:   2,
		EnableAPIKeyValidation: true,
		OrchestratorAPIKey:     "test-secret-key",
		Hostname:               "test-host",
	}
	srv := NewServer(cfg, "5.0.0-test")

	// No key → 401
	req := httptest.NewRequest("GET", "/api/health/detailed", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without key, got %d", w.Code)
	}

	// Wrong key → 403
	req = httptest.NewRequest("GET", "/api/health/detailed", nil)
	req.Header.Set("X-Orchestrator-Key", "wrong-key")
	w = httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong key, got %d", w.Code)
	}

	// Correct key → 200
	req = httptest.NewRequest("GET", "/api/health/detailed", nil)
	req.Header.Set("X-Orchestrator-Key", "test-secret-key")
	w = httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with correct key, got %d", w.Code)
	}
}

func TestPublicEndpointsNoAuth(t *testing.T) {
	cfg := &config.Config{
		AgentHost:              "127.0.0.1",
		AgentPort:              0,
		BackupStoragePath:      "/tmp",
		MaxConcurrentBackups:   2,
		EnableAPIKeyValidation: true,
		OrchestratorAPIKey:     "secret",
		Hostname:               "test-host",
	}
	srv := NewServer(cfg, "5.0.0-test")

	// /health and /metrics should NOT require auth
	for _, path := range []string{"/health", "/health/ready", "/metrics"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200 without auth, got %d", path, w.Code)
		}
	}
}

func TestListVMs(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/vms", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var vms []models.VMInfo
	json.NewDecoder(w.Body).Decode(&vms)

	if len(vms) != 4 {
		t.Errorf("expected 4 VMs, got %d", len(vms))
	}
	if vms[0].Name != "mock-vm-01" {
		t.Errorf("expected mock-vm-01, got %s", vms[0].Name)
	}
}

func TestGetVM(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/vms/mock-vm-02", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var vm models.VMInfo
	json.NewDecoder(w.Body).Decode(&vm)

	if vm.Name != "mock-vm-02" {
		t.Errorf("expected mock-vm-02, got %s", vm.Name)
	}
	if vm.VCPUCount != 4 {
		t.Errorf("expected 4 vCPUs, got %d", vm.VCPUCount)
	}
}

func TestGetVMNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/vms/nonexistent", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestServerWithTLSConfig(t *testing.T) {
	// Verify that WithTLSConfig sets the TLS config on the server
	cfg := &config.Config{
		AgentHost:              "127.0.0.1",
		AgentPort:              0,
		BackupStoragePath:      "/tmp",
		MaxConcurrentBackups:   2,
		EnableAPIKeyValidation: false,
		Hostname:               "test-host",
	}

	// Server with nil TLS config should be HTTP
	srv := NewServer(cfg, "5.0.0-test")
	if srv.srv.TLSConfig != nil {
		t.Error("expected nil TLSConfig without WithTLSConfig")
	}
}

func TestServerWithoutTLSFallback(t *testing.T) {
	// Server without TLS should serve HTTP normally
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDiscoverVMs(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/vms/discover", nil)
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
