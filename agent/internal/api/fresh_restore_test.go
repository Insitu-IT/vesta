package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/restore"
	"net/http"
	"net/http/httptest"
	"testing"
)

type freshRestoreExecutor struct {
	restore.ExecutorIface
	calls int
	err   error
}

type freshNativeExecutor struct {
	restore.ExecutorIface
	calls int
}

func (e *freshNativeExecutor) FreshNativeRestore() {}
func (e *freshNativeExecutor) StartRestore(req *models.RestoreRequest) (*models.RestoreProgress, error) {
	e.calls++
	return &models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning}, nil
}

func TestFreshNativeRequiresAuthenticatedTLSAndMatchingProvider(t *testing.T) {
	for _, problem := range []string{"valid", "http", "no-key", "kubevirt", "both"} {
		t.Run(problem, func(t *testing.T) {
			cfg := &config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"}
			executor := &freshNativeExecutor{}
			server := NewServer(cfg, "test", WithRestoreExecutor(executor), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
			body := []byte(`{"restore_id":"one","native":{"schema":"vnbui-native-vm-restore/1"}}`)
			if problem == "kubevirt" {
				body = []byte(`{"restore_id":"one","kubevirt":{}}`)
			}
			if problem == "both" {
				body = []byte(`{"restore_id":"one","kubevirt":{},"native":{}}`)
			}
			request := httptest.NewRequest(http.MethodPost, "https://agent/api/restores", bytes.NewReader(body))
			request.Header.Set("X-Orchestrator-Key", "expected")
			if problem == "http" {
				request.TLS = nil
			}
			if problem == "no-key" {
				request.Header.Del("X-Orchestrator-Key")
			}
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, request)
			if (response.Code == http.StatusAccepted) != (problem == "valid") || (executor.calls == 1) != (problem == "valid") {
				t.Fatal(problem, response.Code, response.Body.String(), executor.calls)
			}
		})
	}
}

func (e *freshRestoreExecutor) FreshKubeVirtRestore() {}
func (e *freshRestoreExecutor) StartRestore(req *models.RestoreRequest) (*models.RestoreProgress, error) {
	e.calls++
	if e.err != nil {
		return nil, e.err
	}
	return &models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning}, nil
}

func TestFreshRestorePreJournalConflictIsExactAndNoStore(t *testing.T) {
	for _, problem := range []string{"typed", "generic"} {
		t.Run(problem, func(t *testing.T) {
			err := restore.ErrPreJournalTargetReserved
			if problem == "generic" {
				err = errors.New("unproven error")
			}
			executor := &freshRestoreExecutor{err: err}
			cfg := &config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"}
			server := NewServer(cfg, "test", WithRestoreExecutor(executor), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
			body := []byte(`{"restore_id":"restore-one","kubevirt":{"schema":"vnbui-kubevirt-vm-restore/1","restore_id":"restore-one","target":{"vm_name":"fresh","disks":[{"pvc_name":"z"},{"pvc_name":"a"}]}}}`)
			request := httptest.NewRequest(http.MethodPost, "https://agent/api/restores", bytes.NewReader(body))
			request.Header.Set("X-Orchestrator-Key", "expected")
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, request)
			if problem == "generic" {
				if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("prejournal_target_reserved")) {
					t.Fatal("unproven error was promoted", response.Code, response.Body.String())
				}
				return
			}
			var proof map[string]interface{}
			if response.Code != http.StatusConflict || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &proof) != nil {
				t.Fatal("missing exact pre-journal response", response.Code, response.Body.String())
			}
			if len(proof) != 5 || proof["code"] != "prejournal_target_reserved" || proof["restore_id"] != "restore-one" || proof["target_vm_name"] != "fresh" || proof["journal_created"] != false {
				t.Fatal("invalid pre-journal proof", proof)
			}
			pvc, ok := proof["target_pvc_names"].([]interface{})
			if !ok || len(pvc) != 2 || pvc[0] != "a" || pvc[1] != "z" {
				t.Fatal("target PVC identity not canonical", proof)
			}
		})
	}
}

func TestFreshRestoreRequiresAuthenticatedHTTPS(t *testing.T) {
	for _, problem := range []string{"valid", "no-key", "auth-disabled", "http", "server-http", "unknown-field"} {
		t.Run(problem, func(t *testing.T) {
			cfg := &config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"}
			executor := &freshRestoreExecutor{}
			options := []ServerOption{WithRestoreExecutor(executor)}
			if problem != "server-http" {
				options = append(options, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
			}
			if problem == "auth-disabled" {
				cfg.EnableAPIKeyValidation = false
			}
			body := []byte(`{"restore_id":"restore-one","kubevirt":{"schema":"vnbui-kubevirt-vm-restore/1"}}`)
			if problem == "unknown-field" {
				body = []byte(`{"restore_id":"restore-one","sensitive_unknown":"must-not-echo"}`)
			}
			req := httptest.NewRequest(http.MethodPost, "https://agent/api/restores", bytes.NewReader(body))
			req.Header.Set("X-Orchestrator-Key", "expected")
			if problem == "no-key" {
				req.Header.Del("X-Orchestrator-Key")
			}
			if problem == "http" {
				req.TLS = nil
			}
			server := NewServer(cfg, "test", options...)
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, req)
			want := http.StatusLocked
			if problem == "valid" {
				want = http.StatusAccepted
			}
			if problem == "no-key" {
				want = http.StatusUnauthorized
			}
			if problem == "unknown-field" {
				want = http.StatusBadRequest
			}
			if response.Code != want {
				t.Fatal(response.Code, response.Body.String())
			}
			if (executor.calls == 1) != (problem == "valid") {
				t.Fatal("unexpected restore activation", executor.calls)
			}
			if bytes.Contains(response.Body.Bytes(), []byte("must-not-echo")) {
				t.Fatal("request material leaked")
			}
		})
	}
}
