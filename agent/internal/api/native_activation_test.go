//go:build linux

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

type nativeAPIExecutor struct {
	backup.ExecutorIface
	calls int
}

func (e *nativeAPIExecutor) StartNativeJob(context.Context, []byte) error { e.calls++; return nil }

func TestNativeIntentRequiresAuthenticatedHTTPSAndExactACK(t *testing.T) {
	actor := "actor"
	i := backup.NativeJobIntent{Schema: 1, OrgID: "org", ActorID: &actor, BackupID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AgentID: "agent", AttemptID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Producer: backup.NativePushFormat}
	i.JobID = "vnbui-native-" + i.AttemptID
	i.Checkpoint = "vnbui-" + i.AttemptID
	i.Target = backup.NativeJobTarget{Endpoint: "https://fixture.invalid", Bucket: "backups", Region: "test", CapabilityProfile: "db-rooted-consumer-verified/1"}
	i.Encryption = models.StorageEncryption{Format: "none"}
	i.Source = backup.NativeJobSource{VMID: "vm", DomainUUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", AgentID: i.AgentID, BackupType: "full", Exclusions: []string{}, Disks: []backup.NativeSourceDisk{{Target: "vda", Source: "/vm/disk", Bus: "virtio", Format: "qcow2"}}}
	canonical, _ := models.StorageCanonical(i)
	digest := sha256.Sum256(canonical)
	envelope := backup.NativeJobRequest{Protocol: "vnbui-native-job/1", Intent: i, IntentSHA256: hex.EncodeToString(digest[:])}
	body, _ := json.Marshal(envelope)
	for _, mode := range []string{"accepted", "http", "no-key", "auth-disabled", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testControllerConfig(&config.Config{EnableAPIKeyValidation: mode != "auth-disabled", OrchestratorAPIKey: "expected"})
			executor := &nativeAPIExecutor{}
			server := NewServer(cfg, "test", WithBackupExecutor(executor), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}))
			input := body
			if mode == "tampered" {
				input = bytes.Replace(body, []byte("/vm/disk"), []byte("/vm/other"), 1)
			}
			request := httptest.NewRequest(http.MethodPost, "https://agent/api/backups", bytes.NewReader(input))
			certifyTestController(request)
			request.Header.Set("X-Orchestrator-Key", "expected")
			if mode == "http" {
				request.TLS = nil
			}
			if mode == "no-key" {
				request.Header.Del("X-Orchestrator-Key")
			}
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, request)
			if mode == "accepted" {
				var ack map[string]string
				_ = json.Unmarshal(response.Body.Bytes(), &ack)
				if response.Code != 202 || executor.calls != 1 || len(ack) != 4 || ack["intent_sha256"] != envelope.IntentSHA256 || ack["attempt_id"] != i.AttemptID {
					t.Fatal(response.Code, response.Body.String())
				}
			} else if response.Code < 400 || executor.calls != 0 {
				t.Fatal("unsafe native admission", response.Code, response.Body.String())
			}
		})
	}
}
