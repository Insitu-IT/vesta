package heartbeat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

// jsonFieldNames extracts all json tag names from a struct type.
// Follows the actual struct definition so tests stay in sync automatically.
func jsonFieldNames(v interface{}) []string {
	t := reflect.TypeOf(v)
	var fields []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" && !strings.Contains(tag, ",omitempty") {
			fields = append(fields, name)
		}
	}
	return fields
}

func testConfig(orchestratorURL string) *config.Config {
	return &config.Config{
		AgentID:           "test-agent-id",
		AgentAPIKey:       "test-api-key",
		OrchestratorURL:   orchestratorURL,
		HeartbeatInterval: 1,
		BackupStoragePath: "/tmp",
		AgentPort:         8090,
		Hostname:          "test-host",
	}
}

func TestHeartbeatRepeatsHoldSnapshotAfterLostDelivery(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		var payload models.AgentHeartbeat
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if len(payload.Events) != 1 || payload.Events[0]["type"] != "native_attempt_held" {
			t.Errorf("missing repeated snapshot on delivery %d: %#v", attempts, payload.Events)
		}
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()
	svc := New(testConfig(srv.URL), srv.Client(), "6.0.20")
	svc.SetBackupObservations(func() []map[string]interface{} {
		return []map[string]interface{}{{"type": "native_attempt_held"}}
	})
	svc.sendHeartbeat()
	svc.sendHeartbeat()
	if attempts != 2 {
		t.Fatal("heartbeat retry missing", attempts)
	}
}

type heartbeatRoundTrip func(*http.Request) (*http.Response, error)

func (f heartbeatRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConnectionRetriesRegenerateSnapshotsWithoutDuplicatingQueuedEvents(t *testing.T) {
	var svc *Service
	attempts, snapshots := 0, 0
	client := &http.Client{Transport: heartbeatRoundTrip(func(r *http.Request) (*http.Response, error) {
		attempts++
		var payload models.AgentHeartbeat
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		want := 3
		if attempts == 1 {
			want = 2
		} else if attempts == 5 {
			want = 1
		}
		if len(payload.Events) != want {
			t.Fatalf("attempt %d: accumulated or lost events: %#v", attempts, payload.Events)
		}
		last := payload.Events[len(payload.Events)-1]
		if last["type"] != "storage_transaction_progress" || last["bytes_transferred"] != float64(attempts) {
			t.Fatalf("attempt %d: stale snapshot: %#v", attempts, last)
		}
		if attempts <= 4 && payload.Events[0]["type"] != "original_event" {
			t.Fatal("original event lost during connection retry")
		}
		if attempts >= 2 && attempts <= 4 && payload.Events[1]["type"] != "concurrent_event" {
			t.Fatal("event queued during failed delivery was lost or reordered")
		}
		if attempts == 1 {
			svc.QueueEvent(map[string]interface{}{"type": "concurrent_event"})
		}
		if attempts <= 3 {
			return nil, errors.New("connection interrupted")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"status":"ok"}`))}, nil
	})}
	svc = New(testConfig("https://example.test"), client, "test")
	svc.QueueEvent(map[string]interface{}{"type": "original_event"})
	svc.SetBackupObservations(func() []map[string]interface{} {
		snapshots++
		return []map[string]interface{}{{"type": "storage_transaction_progress", "bytes_transferred": snapshots}}
	})
	for range 5 {
		svc.sendHeartbeat()
	}
	if len(svc.events) != 0 || snapshots != 5 {
		t.Fatal("successful delivery retained retry events or stopped sampling")
	}
}

func TestHeartbeatPayloadFields(t *testing.T) {
	// Verify the heartbeat JSON matches what the backend expects.
	// Uses both raw map (for field presence) and typed struct (for values).
	var rawPayload map[string]interface{}
	var typedPayload models.AgentHeartbeat

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &rawPayload)
		json.Unmarshal(body, &typedPayload)
		json.NewEncoder(w).Encode(models.HeartbeatResponse{
			Status: "ok",
			Config: map[string]interface{}{},
		})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Provider = "libvirt"
	svc := New(cfg, srv.Client(), "5.0.3")
	svc.SetDiskAdmissionThreshold(func() float64 { return 91.5 })
	svc.SetCallbacks(
		func() int { return 2 },
		func() int { return 1 },
		func() bool { return true },
	)

	svc.sendHeartbeat()
	if typedPayload.Capabilities["storage_admission_used_percent"] != 91.5 {
		t.Fatal("heartbeat omitted the active manager threshold")
	}

	// Derive expected fields from the actual AgentHeartbeat struct tags.
	// If a field is added/renamed in the struct, this test adapts automatically.
	for _, field := range jsonFieldNames(models.AgentHeartbeat{}) {
		if _, ok := rawPayload[field]; !ok {
			t.Errorf("missing field %q in heartbeat payload (defined in AgentHeartbeat struct)", field)
		}
	}

	// Check values via the typed struct — compiler catches field renames
	if typedPayload.Status != "online" {
		t.Errorf("Status = %v, want online", typedPayload.Status)
	}
	if typedPayload.ActiveBackups != 2 {
		t.Errorf("ActiveBackups = %v, want 2", typedPayload.ActiveBackups)
	}
	if typedPayload.ActiveRestores != 1 {
		t.Errorf("ActiveRestores = %v, want 1", typedPayload.ActiveRestores)
	}
	if !typedPayload.LibvirtAccessible {
		t.Error("LibvirtAccessible = false, want true")
	}
}

func TestHeartbeatHeaders(t *testing.T) {
	var gotHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.AgentAPIKey = "my-secret-key"

	svc := New(cfg, srv.Client(), "5.0.3")
	svc.sendHeartbeat()

	if gotHeaders.Get("X-Agent-Key") != "my-secret-key" {
		t.Errorf("X-Agent-Key = %q, want %q", gotHeaders.Get("X-Agent-Key"), "my-secret-key")
	}
	if gotHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotHeaders.Get("Content-Type"))
	}
}

func TestHeartbeatURL(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.AgentID = "abc-123"

	svc := New(cfg, srv.Client(), "5.0.3")
	svc.sendHeartbeat()

	want := "/api/v1/health/agents/abc-123/heartbeat"
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestHeartbeatEventsDelivered(t *testing.T) {
	var received map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	svc.QueueEvent(map[string]interface{}{"type": "backup_reconciled", "backup_id": "b1"})
	svc.QueueEvent(map[string]interface{}{"type": "vm_lifecycle", "vm_name": "vm1"})

	svc.sendHeartbeat()

	events, ok := received["events"].([]interface{})
	if !ok {
		t.Fatal("events not a list")
	}
	if len(events) != 2 {
		t.Errorf("events count = %d, want 2", len(events))
	}

	// Events should be cleared after delivery
	svc.sendHeartbeat()
	events2, _ := received["events"].([]interface{})
	if len(events2) != 0 {
		t.Errorf("events not cleared after delivery, got %d", len(events2))
	}
}

func TestHeartbeatEventsRequeueOnFailure(t *testing.T) {
	callCount := 0
	var received map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(500) // First call fails
			return
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	svc.QueueEvent(map[string]interface{}{"type": "test_event"})

	// First heartbeat fails — events should NOT be re-queued on HTTP error
	// (re-queue only happens on connection error)
	svc.sendHeartbeat()

	// Events were consumed from the queue but not re-queued (HTTP 500 is not connection error)
	svc.sendHeartbeat()
	events, _ := received["events"].([]interface{})
	if len(events) != 0 {
		t.Errorf("events = %d on retry, want 0 (HTTP errors don't re-queue)", len(events))
	}
}

func TestBackoffOnFailure(t *testing.T) {
	svc := &Service{
		backoffFactor: 1.0,
		maxBackoff:    8.0,
	}

	svc.increaseBackoff()
	if svc.backoffFactor != 2.0 {
		t.Errorf("backoff = %f, want 2.0", svc.backoffFactor)
	}

	svc.increaseBackoff()
	if svc.backoffFactor != 4.0 {
		t.Errorf("backoff = %f, want 4.0", svc.backoffFactor)
	}

	svc.increaseBackoff()
	if svc.backoffFactor != 8.0 {
		t.Errorf("backoff = %f, want 8.0 (max)", svc.backoffFactor)
	}

	// Should cap at max
	svc.increaseBackoff()
	if svc.backoffFactor != 8.0 {
		t.Errorf("backoff = %f, want 8.0 (capped)", svc.backoffFactor)
	}

	svc.resetBackoff()
	if svc.backoffFactor != 1.0 {
		t.Errorf("backoff = %f after reset, want 1.0", svc.backoffFactor)
	}
}

func TestBackoffResetOnSuccess(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	// Two failures
	svc.sendHeartbeat()
	svc.sendHeartbeat()
	if svc.backoffFactor != 4.0 {
		t.Errorf("backoff = %f after 2 failures, want 4.0", svc.backoffFactor)
	}

	// Success resets
	svc.sendHeartbeat()
	if svc.backoffFactor != 1.0 {
		t.Errorf("backoff = %f after success, want 1.0", svc.backoffFactor)
	}
}

func TestApplyRemoteConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(models.HeartbeatResponse{
			Status: "ok",
			Config: map[string]interface{}{
				"heartbeat_interval":     15,
				"max_concurrent_backups": 5,
				"log_level":              "DEBUG",
			},
		})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.HeartbeatInterval = 30
	cfg.MaxConcurrentBackups = 2

	svc := New(cfg, srv.Client(), "5.0.3")
	svc.sendHeartbeat()

	if cfg.HeartbeatInterval != 15 {
		t.Errorf("HeartbeatInterval = %d, want 15", cfg.HeartbeatInterval)
	}
	if cfg.MaxConcurrentBackups != 2 {
		t.Errorf("startup-only MaxConcurrentBackups changed: %d", cfg.MaxConcurrentBackups)
	}
	if cfg.LogLevel != "DEBUG" {
		t.Errorf("LogLevel = %q, want DEBUG", cfg.LogLevel)
	}
}

// mockTLSManager implements TLSRenewer for testing.
type mockTLSManager struct {
	hasCerts     bool
	needsRenewal bool
	csrCalled    bool
	saveCalled   bool
}

func (m *mockTLSManager) HasCerts() bool              { return m.hasCerts }
func (m *mockTLSManager) NeedsRenewal() (bool, error) { return m.needsRenewal, nil }
func (m *mockTLSManager) GenerateCSR(hostname string) ([]byte, error) {
	m.csrCalled = true
	return []byte("mock-csr"), nil
}
func (m *mockTLSManager) SaveCerts(cert, key, ca []byte) error {
	m.saveCalled = true
	return nil
}

func TestCertRenewalTriggered(t *testing.T) {
	renewCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pki/renew" {
			renewCalled = true
			json.NewEncoder(w).Encode(map[string]string{
				"cert_pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
			})
			return
		}
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	tlsMgr := &mockTLSManager{hasCerts: true, needsRenewal: true}
	svc.SetTLSManager(tlsMgr)

	svc.sendHeartbeat()

	if !renewCalled {
		t.Error("expected PKI renew endpoint to be called")
	}
	if !tlsMgr.csrCalled {
		t.Error("expected GenerateCSR to be called")
	}
	if !tlsMgr.saveCalled {
		t.Error("expected SaveCerts to be called")
	}
}

func TestCertRenewalNotTriggeredWhenNotNeeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pki/renew" {
			t.Error("renewal should not be called")
		}
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	tlsMgr := &mockTLSManager{hasCerts: true, needsRenewal: false}
	svc.SetTLSManager(tlsMgr)

	svc.sendHeartbeat()

	if tlsMgr.csrCalled {
		t.Error("GenerateCSR should not be called when renewal not needed")
	}
}

func TestCertRenewalSkippedWithoutCerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	svc := New(cfg, srv.Client(), "5.0.3")

	tlsMgr := &mockTLSManager{hasCerts: false, needsRenewal: true}
	svc.SetTLSManager(tlsMgr)

	svc.sendHeartbeat()

	if tlsMgr.csrCalled {
		t.Error("GenerateCSR should not be called when no certs exist")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.HeartbeatInterval = 1

	svc := New(cfg, srv.Client(), "5.0.3")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestScopeAppliedCallbackRunsAfterUnlockAndOnlyOnNewRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(`{"source_namespaces":["one"],"default_selected_namespaces":["one"],"restore_namespaces":[],"scratch_pvcs":{"one":"scratch"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(models.HeartbeatResponse{Config: map[string]interface{}{"selected_source_namespaces": []interface{}{}, "scope_revision": "changed"}})
	}))
	defer srv.Close()
	cfg := testConfig(srv.URL)
	cfg.Provider = "kubevirt"
	if err := cfg.LoadNamespacePolicy(path); err != nil {
		t.Fatal(err)
	}
	svc := New(cfg, srv.Client(), "test")
	count := 0
	svc.SetScopeAppliedCallback(func() {
		count++
		if cfg.SourceNamespaceAllowed("one") {
			t.Error("callback saw stale selection")
		}
	})
	svc.sendHeartbeat()
	svc.sendHeartbeat()
	if count != 1 {
		t.Fatalf("scope callback count=%d want1", count)
	}
}

// Exercise the same snapshots Run uses while immediate sends change backoff.
// Run this case with -race; policy assertions also cover the cap and recovery.
func TestConcurrentHeartbeatBackoff(t *testing.T) {
	var responseMu sync.Mutex
	fail := true
	requests := make(chan struct{}, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseMu.Lock()
		failing := fail
		responseMu.Unlock()
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			json.NewEncoder(w).Encode(models.HeartbeatResponse{Status: "ok"})
		}
		requests <- struct{}{}
	}))
	defer srv.Close()
	svc := New(testConfig(srv.URL), srv.Client(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() { svc.Run(ctx); close(stopped) }()
	select {
	case <-requests:
	case <-time.After(5 * time.Second):
		t.Fatal("initial heartbeat missing")
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); svc.sendHeartbeat() }()
	}
	for i := 0; i < 10000; i++ {
		wait := svc.nextHeartbeatWait(time.Second)
		if wait < time.Second || wait > 8*time.Second {
			t.Fatalf("wait outside policy: %v", wait)
		}
	}
	workers.Wait()
	if got := svc.nextHeartbeatWait(time.Second); got != 8*time.Second {
		t.Fatalf("failure cap: %v", got)
	}
	responseMu.Lock()
	fail = false
	responseMu.Unlock()
	svc.SendImmediate()
	// A synchronous send lets recovery complete without reading state unsafely.
	svc.sendHeartbeat()
	if got := svc.nextHeartbeatWait(time.Second); got != time.Second {
		t.Fatalf("recovery: %v", got)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not cancel during backoff")
	}
}
