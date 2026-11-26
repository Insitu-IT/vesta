package reconcile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/provider/mock"
	"vnbui/agent/internal/resources"
)

func TestPendingJobsResponseParsing(t *testing.T) {
	// Backend returns {"backups": [{id, vm_name, storage_path, status}]}
	var gotPath, gotMethod, gotKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotKey = r.Header.Get("X-Agent-Key")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": []map[string]interface{}{
				{
					"id":           "backup-001",
					"vm_name":      "vm-web",
					"storage_path": "/backups/backup-001",
					"started_at":   "2026-03-10T00:00:00Z",
					"status":       "running",
				},
				{
					"id":           "backup-002",
					"vm_name":      "vm-db",
					"storage_path": "/backups/backup-002",
					"started_at":   "2026-03-09T23:00:00Z",
					"status":       "pending",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentID:           "agent-abc",
		AgentAPIKey:       "secret-key",
		OrchestratorURL:   srv.URL,
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, err := Reconcile(cfg, mockProvider, srv.Client(), nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Verify request
	if gotMethod != "GET" {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/api/v1/agents/agent-abc/pending-jobs" {
		t.Errorf("path = %q, want /api/v1/agents/agent-abc/pending-jobs", gotPath)
	}
	if gotKey != "secret-key" {
		t.Errorf("X-Agent-Key = %q, want secret-key", gotKey)
	}

	// Two pending jobs, none running locally → both reconciled as failed
	if result.PendingJobs != 2 {
		t.Errorf("PendingJobs = %d, want 2", result.PendingJobs)
	}
	if result.Reconciled != 2 {
		t.Errorf("Reconciled = %d, want 2", result.Reconciled)
	}
}

func TestReconcileEventsFormat(t *testing.T) {
	// No systemd units running, no output files → should generate "failed" events
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": []map[string]interface{}{
				{
					"id":           "backup-lost",
					"vm_name":      "vm-test",
					"storage_path": "/nonexistent/path",
					"status":       "running",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentID:           "agent-1",
		AgentAPIKey:       "key",
		OrchestratorURL:   srv.URL,
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, err := Reconcile(cfg, mockProvider, srv.Client(), nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(result.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(result.Events))
	}

	event := result.Events[0]

	// Backend expects these exact field names (health.py lines 221-226)
	if event["type"] != "backup_reconciled" {
		t.Errorf("type = %v, want backup_reconciled", event["type"])
	}
	if event["backup_id"] != "backup-lost" {
		t.Errorf("backup_id = %v, want backup-lost", event["backup_id"])
	}
	if event["new_status"] != "cleanup_required" {
		t.Errorf("new_status = %v, want cleanup_required", event["new_status"])
	}
	if event["old_status"] != "running" {
		t.Errorf("old_status = %v, want running", event["old_status"])
	}
	if _, ok := event["reason"]; !ok {
		t.Error("missing 'reason' field")
	}
}

func TestReconcileNoPendingJobs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": []interface{}{},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentID:           "agent-1",
		AgentAPIKey:       "key",
		OrchestratorURL:   srv.URL,
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, err := Reconcile(cfg, mockProvider, srv.Client(), nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.PendingJobs != 0 {
		t.Errorf("PendingJobs = %d, want 0", result.PendingJobs)
	}
	if result.Reconciled != 0 {
		t.Errorf("Reconciled = %d, want 0", result.Reconciled)
	}
	if len(result.Events) != 0 {
		t.Errorf("events = %d, want 0", len(result.Events))
	}
}

func TestReconcileOrchestratorUnreachable(t *testing.T) {
	cfg := &config.Config{
		AgentID:           "agent-1",
		AgentAPIKey:       "key",
		OrchestratorURL:   "http://127.0.0.1:1", // unreachable
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	// Should not return error — orchestrator failure is non-fatal
	result, err := Reconcile(cfg, mockProvider, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("reconcile should not fail: %v", err)
	}

	if result.PendingJobs != 0 {
		t.Errorf("PendingJobs = %d, want 0", result.PendingJobs)
	}
}

func TestReconcileNoAgentID(t *testing.T) {
	cfg := &config.Config{
		AgentID:           "", // Not registered
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	// Should gracefully handle missing agent ID
	result, err := Reconcile(cfg, mockProvider, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("reconcile should not fail: %v", err)
	}

	if result.PendingJobs != 0 {
		t.Errorf("PendingJobs = %d, want 0", result.PendingJobs)
	}
}

func TestReconcileStoragePathFallback(t *testing.T) {
	// When job.StoragePath is empty, should use cfg.BackupStoragePath + backup_id
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": []map[string]interface{}{
				{
					"id":           "backup-xyz",
					"vm_name":      "vm1",
					"storage_path": "", // empty
					"status":       "running",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentID:           "agent-1",
		AgentAPIKey:       "key",
		OrchestratorURL:   srv.URL,
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, _ := Reconcile(cfg, mockProvider, srv.Client(), nil)

	// Should still reconcile (and fail because path doesn't exist)
	if result.Reconciled != 1 {
		t.Errorf("Reconciled = %d, want 1", result.Reconciled)
	}
}

func TestPendingJobFieldMapping(t *testing.T) {
	// Verify the JSON field mapping matches what backend returns
	raw := `{"id":"abc-123","vm_name":"web-01","storage_path":"/backups/abc-123","status":"running"}`

	var job PendingJob
	if err := json.Unmarshal([]byte(raw), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if job.BackupID != "abc-123" {
		t.Errorf("BackupID = %q, want abc-123 (mapped from 'id')", job.BackupID)
	}
	if job.VMName != "web-01" {
		t.Errorf("VMName = %q, want web-01", job.VMName)
	}
	if job.StoragePath != "/backups/abc-123" {
		t.Errorf("StoragePath = %q, want /backups/abc-123", job.StoragePath)
	}
	if job.Status != "running" {
		t.Errorf("Status = %q, want running", job.Status)
	}
}

func TestPendingJobsResponseWrapper(t *testing.T) {
	// Verify the wrapper struct parses correctly
	raw := `{"backups":[{"id":"b1","vm_name":"v1","storage_path":"/p","status":"running"}]}`

	var wrapper pendingJobsResponse
	if err := json.Unmarshal([]byte(raw), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(wrapper.Backups) != 1 {
		t.Fatalf("backups count = %d, want 1", len(wrapper.Backups))
	}
	if wrapper.Backups[0].BackupID != "b1" {
		t.Errorf("BackupID = %q, want b1", wrapper.Backups[0].BackupID)
	}
}

func TestReconcileWithResourceManager(t *testing.T) {
	// The reconciler should pass resMgr.AdoptBackupSlot() without error
	// when resMgr is nil or provided. With nil, it should not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": []interface{}{},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentID:           "agent-1",
		AgentAPIKey:       "key",
		OrchestratorURL:   srv.URL,
		BackupStoragePath: "/var/lib/vnbui/backups",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	resMgr := resources.New(2, 1)

	// Should work with resMgr provided
	result, err := Reconcile(cfg, mockProvider, srv.Client(), resMgr)
	if err != nil {
		t.Fatalf("reconcile with resMgr: %v", err)
	}
	if result.PendingJobs != 0 {
		t.Errorf("PendingJobs = %d, want 0", result.PendingJobs)
	}
}
