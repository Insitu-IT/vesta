package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

type transactionAPIExecutor struct {
	backup.ExecutorIface // A nil legacy implementation traps accidental fallback.
	calls                int
	retireCalls          int
	err                  error
}

func (e *transactionAPIExecutor) StartStorageTransaction(context.Context, []byte) error {
	e.calls++
	return e.err
}

func (e *transactionAPIExecutor) RetireStorageTransaction(_ context.Context, backupID, reservationID string) error {
	e.retireCalls++
	if backupID != "backup" || reservationID != "reservation" {
		return errors.New("wrong retirement identity")
	}
	return e.err
}

func TestRetirementRequiresAuthenticatedHTTPSAndExactIdentity(t *testing.T) {
	for _, variant := range []string{"accepted", "no-key", "wrong-key", "http", "no-server-tls", "bad-body", "held"} {
		t.Run(variant, func(t *testing.T) {
			cfg := testControllerConfig(&config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"})
			executor := &transactionAPIExecutor{}
			options := []ServerOption{WithBackupExecutor(executor)}
			if variant != "no-server-tls" {
				options = append(options, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}))
			}
			if variant == "held" {
				executor.err = errors.New("not reviewed")
			}
			server := NewServer(cfg, "test", options...)
			body := `{"reservation_id":"reservation"}`
			if variant == "bad-body" {
				body = `{"reservation_id":"reservation","proof":"forged"}`
			}
			request := httptest.NewRequest(http.MethodPost, "https://agent/api/backups/backup/retire", bytes.NewBufferString(body))
			certifyTestController(request)
			request.Header.Set("X-Orchestrator-Key", "expected")
			if variant == "no-key" {
				request.Header.Del("X-Orchestrator-Key")
			}
			if variant == "wrong-key" {
				request.Header.Set("X-Orchestrator-Key", "wrong")
			}
			if variant == "http" {
				request.TLS = nil
			}
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, request)
			wanted := http.StatusLocked
			switch variant {
			case "accepted":
				wanted = http.StatusOK
			case "no-key":
				wanted = http.StatusUnauthorized
			case "http", "wrong-key":
				wanted = http.StatusForbidden
			case "bad-body":
				wanted = http.StatusBadRequest
			}
			if response.Code != wanted {
				t.Fatalf("HTTP %d, want %d", response.Code, wanted)
			}
			calls := 0
			if variant == "accepted" || variant == "held" {
				calls = 1
			}
			if executor.retireCalls != calls {
				t.Fatal("retirement reached executor outside authenticated exact request")
			}
		})
	}
}

func TestStorageTransactionHTTPSAuthenticatedAdmission(t *testing.T) {
	body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	transaction, _ := models.DecodeStorageTransaction(body)
	for _, variant := range []string{"accepted", "no-header", "wrong-header", "empty-key", "auth-disabled", "http", "no-server-tls", "held"} {
		t.Run(variant, func(t *testing.T) {
			cfg := testControllerConfig(&config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"})
			executor := &transactionAPIExecutor{}
			options := []ServerOption{WithBackupExecutor(executor)}
			if variant != "no-server-tls" {
				options = append(options, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}))
			}
			if variant == "empty-key" {
				cfg.OrchestratorAPIKey = ""
			}
			if variant == "auth-disabled" {
				cfg.EnableAPIKeyValidation = false
			}
			if variant == "held" {
				executor.err = errors.New("retain journal")
			}
			server := NewServer(cfg, "test", options...)
			request := httptest.NewRequest(http.MethodPost, "https://agent/api/backups", bytes.NewReader(body))
			certifyTestController(request)
			request.Header.Set("X-Orchestrator-Key", "expected")
			if variant == "no-header" {
				request.Header.Del("X-Orchestrator-Key")
			}
			if variant == "wrong-header" {
				request.Header.Set("X-Orchestrator-Key", "wrong")
			}
			if variant == "http" {
				request.TLS = nil
			}
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, request)
			wanted := http.StatusLocked
			switch variant {
			case "accepted":
				wanted = http.StatusAccepted
			case "no-header":
				wanted = http.StatusUnauthorized
			case "http", "wrong-header":
				wanted = http.StatusForbidden
			}
			if response.Code != wanted {
				t.Fatalf("HTTP %d, want %d: %s", response.Code, wanted, response.Body.String())
			}
			if variant == "accepted" {
				var result map[string]string
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result) != 4 || result["status"] != "accepted" || result["backup_id"] != transaction.BackupID || result["reservation_id"] != transaction.ReservationID || result["plan_sha256"] != transaction.PlanSHA256 {
					t.Fatal("wrong durable acceptance response", response.Body.String())
				}
			}
			wantCalls := 0
			if variant == "accepted" || variant == "held" {
				wantCalls = 1
			}
			if executor.calls != wantCalls {
				t.Fatal("insecure API reached transaction runner")
			}
		})
	}
}

func TestTransactionalExecutorDoesNotFallBackToLegacyBackup(t *testing.T) {
	executor := &transactionAPIExecutor{}
	handler := NewBackupHandler(executor)
	response := httptest.NewRecorder()
	handler.StartBackup(response, httptest.NewRequest(http.MethodPost, "/api/backups", bytes.NewBufferString(`{"backup_id":"legacy","vm_name":"vm"}`)))
	if response.Code != http.StatusLocked || executor.calls != 0 {
		t.Fatal("legacy request reached transaction executor")
	}
}
