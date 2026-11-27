package api

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/filebackup"
	"vnbui/agent/internal/provider/mock"
)

type fileBackupProbe struct{ called int }

func (p *fileBackupProbe) Submit(id, fileSet string, _ *filebackup.ExpectedStorage) (filebackup.Result, error) {
	p.called++
	return filebackup.Result{BackupID: id, FileSet: fileSet, Status: "pending"}, nil
}

func (p *fileBackupProbe) Get(id string) (filebackup.Result, error) {
	p.called++
	return filebackup.Result{BackupID: id, Status: "completed"}, nil
}

func TestManagedFileBackupAuthentication(t *testing.T) {
	cfg := &config.Config{AgentID: "agent-a", EnableAPIKeyValidation: true, OrchestratorAPIKey: "orchestrator-secret"}
	leaf := []byte("controller leaf")
	pin := sha256.Sum256(leaf)
	cfg.ObserveControllers(hex.EncodeToString(pin[:]), hex.EncodeToString(pin[:]))
	probe := &fileBackupProbe{}
	server := NewServer(cfg, "test", WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}), WithFileBackupExecutor(probe))
	for _, tc := range []struct {
		name, agent, key, body string
		mtls                   bool
		want                   int
	}{
		{"no mTLS", "agent-a", "orchestrator-secret", "{}", false, http.StatusForbidden},
		{"no key", "agent-a", "", "{}", true, http.StatusUnauthorized},
		{"different host", "agent-b", "orchestrator-secret", "{}", true, http.StatusForbidden},
		{"missing host", "", "orchestrator-secret", "{}", true, http.StatusForbidden},
		{"remote path", "agent-a", "orchestrator-secret", `{"file_set":"documents","path":"/srv"}`, true, http.StatusUnprocessableEntity},
		{"missing storage", "agent-a", "orchestrator-secret", `{"file_set":"documents","backup_id":"job"}`, true, http.StatusUnprocessableEntity},
		{"different client leaf", "agent-a", "orchestrator-secret", "{}", true, http.StatusForbidden},
		{"authorized", "agent-a", "orchestrator-secret", `{"file_set":"documents","backup_id":"job","storage":{"bucket":"test","prefix":"docs"}}`, true, http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/file-backups", strings.NewReader(tc.body))
			req.Header.Set("X-Orchestrator-Key", tc.key)
			req.Header.Set("X-Vesta-Agent-ID", tc.agent)
			if tc.mtls {
				peer := leaf
				if tc.name == "different client leaf" {
					peer = []byte("another enrolled agent")
				}
				req.TLS = testVerifiedControllerLeaf(peer)
			}
			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	if probe.called != 1 {
		t.Fatalf("authorized calls = %d, want 1", probe.called)
	}
}

func TestMixedAgentVMOutageLeavesFileRoutesAvailable(t *testing.T) {
	cfg := &config.Config{AgentID: "agent-a", EnableAPIKeyValidation: true, OrchestratorAPIKey: "orchestrator-secret"}
	leaf := []byte("controller leaf")
	pin := sha256.Sum256(leaf)
	cfg.ObserveControllers(hex.EncodeToString(pin[:]), hex.EncodeToString(pin[:]))
	probe := &fileBackupProbe{}
	server := NewServer(cfg, "test", WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}),
		WithFileBackupExecutor(probe), WithVMProvider(mock.New()), WithVMAvailability(func() bool { return false }),
		WithActivationStatus(map[string]string{"managed_file_backups": "available"}))
	for path, status := range map[string]int{
		"/api/vms": http.StatusServiceUnavailable, "/api/file-backups/job": http.StatusOK,
		"/api/health/detailed": http.StatusOK,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Orchestrator-Key", "orchestrator-secret")
		req.Header.Set("X-Vesta-Agent-ID", "agent-a")
		req.TLS = testVerifiedControllerLeaf(leaf)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: status %d, want %d: %s", path, w.Code, status, w.Body.String())
		}
		if path == "/api/health/detailed" {
			var health struct {
				Activation map[string]string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil ||
				health.Activation["vm_workload"] != "unavailable" || health.Activation["managed_file_backups"] != "available" {
				t.Fatalf("unexpected activation health: %s", w.Body.String())
			}
		}
	}
	cold := NewServer(cfg, "test", WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}), WithFileBackupExecutor(probe), WithVMAvailability(func() bool { return false }))
	for _, path := range []string{"/api/vms", "/api/backups/accepted", "/api/restores/accepted"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Orchestrator-Key", "orchestrator-secret")
		req.Header.Set("X-Vesta-Agent-ID", "agent-a")
		req.TLS = testVerifiedControllerLeaf(leaf)
		w := httptest.NewRecorder()
		cold.router.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("cold degraded host %s: %d", path, w.Code)
		}
	}
	if probe.called != 1 {
		t.Fatalf("file status calls = %d, want 1", probe.called)
	}
}
