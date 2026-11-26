package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider/mock"
)

type emptyVMProvider struct {
	*mock.Provider
}

func (p *emptyVMProvider) ListVMs() ([]models.VMInfo, error) {
	return nil, nil
}

func TestRegisterRequestHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotMethod string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotMethod = r.Method
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": "new-id",
			"api_key":  "new-key",
			"hostname": "test-host",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "my-reg-key",
		Hostname:        "test-host",
		AgentPort:       8090,
		LibvirtURI:      "qemu:///system",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, err := Register(cfg, mockProvider, "5.0.3", srv.Client())
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Must use POST
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}

	// Must send X-API-Key (not X-Registration-Key)
	if gotHeaders.Get("X-API-Key") != "my-reg-key" {
		t.Errorf("X-API-Key = %q, want %q", gotHeaders.Get("X-API-Key"), "my-reg-key")
	}

	// Must NOT send X-Registration-Key
	if gotHeaders.Get("X-Registration-Key") != "" {
		t.Error("should not send X-Registration-Key header")
	}

	// Parse response correctly
	if result.AgentID != "new-id" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "new-id")
	}
	if result.APIKey != "new-key" {
		t.Errorf("APIKey = %q, want %q", result.APIKey, "new-key")
	}
}

func TestRegisterRequestBody(t *testing.T) {
	var received models.AgentRegistration

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": "id",
			"api_key":  "key",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "key",
		Hostname:        "kvm-host-01",
		AgentPort:       8090,
		AgentIP:         "10.0.0.5",
		LibvirtURI:      "qemu:///system",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	Register(cfg, mockProvider, "5.0.3", srv.Client())

	if received.Hostname != "kvm-host-01" {
		t.Errorf("hostname = %q, want kvm-host-01", received.Hostname)
	}
	if received.IPAddress != "10.0.0.5" {
		t.Errorf("ip_address = %q, want 10.0.0.5", received.IPAddress)
	}
	if received.Port != 8090 {
		t.Errorf("port = %d, want 8090", received.Port)
	}
	if received.LibvirtURI != "qemu:///system" {
		t.Errorf("libvirt_uri = %q, want qemu:///system", received.LibvirtURI)
	}
	if received.Version != "5.0.3" {
		t.Errorf("version = %q, want 5.0.3", received.Version)
	}
}

func TestRegisterEndpointPath(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": "id",
			"api_key":  "key",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "key",
		Hostname:        "h",
		AgentPort:       8090,
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	Register(cfg, mockProvider, "1.0", srv.Client())

	if gotPath != "/api/v1/agents/register" {
		t.Errorf("path = %q, want /api/v1/agents/register", gotPath)
	}
}

func TestRegisterNoKeyHeader(t *testing.T) {
	var gotHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": "id",
			"api_key":  "key",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "", // No key
		Hostname:        "h",
		AgentPort:       8090,
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	Register(cfg, mockProvider, "1.0", srv.Client())

	// Should not send X-API-Key if registration key is empty
	if gotHeaders.Get("X-API-Key") != "" {
		t.Errorf("X-API-Key should be empty when no registration key, got %q", gotHeaders.Get("X-API-Key"))
	}
}

func TestRegister401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"detail":"Invalid registration key."}`))
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "bad-key",
		Hostname:        "h",
		AgentPort:       8090,
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	_, err := Register(cfg, mockProvider, "1.0", srv.Client())
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestRegisterWithTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": "id",
			"api_key":  "key",
			"tls": map[string]interface{}{
				"ca_cert":     "-----BEGIN CERTIFICATE-----\n...",
				"agent_cert":  "-----BEGIN CERTIFICATE-----\n...",
				"agent_key":   "-----BEGIN PRIVATE KEY-----\n...",
				"fingerprint": "AA:BB:CC",
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		RegistrationKey: "key",
		Hostname:        "h",
		AgentPort:       8090,
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	result, err := Register(cfg, mockProvider, "1.0", srv.Client())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if result.TLS.Fingerprint != "AA:BB:CC" {
		t.Errorf("fingerprint = %q, want AA:BB:CC", result.TLS.Fingerprint)
	}
}

func TestSyncVMs(t *testing.T) {
	var gotPath, gotMethod string
	var received map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		Hostname:        "kvm-host-01",
		AgentAPIKey:     "agent-key",
	}

	mockProvider := &emptyVMProvider{Provider: mock.New()}
	mockProvider.Connect()

	err := SyncVMs(cfg, mockProvider, srv.Client())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Must use POST (not PUT)
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}

	// Path must use hostname (not agent_id)
	if gotPath != "/api/v1/agents/kvm-host-01/vms" {
		t.Errorf("path = %q, want /api/v1/agents/kvm-host-01/vms", gotPath)
	}

	// Body must be wrapped in {"vms": [...]}
	if received["complete"] != true {
		t.Fatal("complete inventory snapshot not declared")
	}
	vms, ok := received["vms"].([]interface{})
	if !ok {
		t.Fatalf("body vms = %#v, want JSON array", received["vms"])
	}
	if len(vms) != 0 {
		t.Errorf("body vms length = %d, want 0", len(vms))
	}
}

func TestSyncVMsAuthHeader(t *testing.T) {
	var gotKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Agent-Key")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		Hostname:        "h",
		AgentAPIKey:     "secret-agent-key",
	}

	mockProvider := mock.New()
	mockProvider.Connect()

	SyncVMs(cfg, mockProvider, srv.Client())

	if gotKey != "secret-agent-key" {
		t.Errorf("X-Agent-Key = %q, want secret-agent-key", gotKey)
	}
}

func TestEventDrivenVMSync(t *testing.T) {
	requests := make(chan struct{}, 1)
	RequestVMSync(requests)
	RequestVMSync(requests)
	if len(requests) != 1 {
		t.Fatalf("pending requests = %d, want coalesced single request", len(requests))
	}

	synced := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		synced <- struct{}{}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := &config.Config{
		OrchestratorURL: srv.URL,
		Hostname:        "kubevirt-agent",
		AgentAPIKey:     "agent-key",
	}
	mockProvider := mock.New()
	mockProvider.Connect()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunVMSyncLoop(ctx, requests, cfg, mockProvider, srv.Client())

	select {
	case <-synced:
	case <-time.After(time.Second):
		t.Fatal("event-driven VM sync did not run")
	}
}

func TestInventoryReconciliationWithoutLifecycleEvent(t *testing.T) {
	requests := make(chan struct{}, 1)
	close(requests) // A closed event stream must not spin or disable reconciliation.
	synced := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Complete bool `json:"complete"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Complete {
			t.Error("reconciliation must send a complete current inventory")
		}
		select {
		case synced <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	mockProvider := mock.New()
	if err := mockProvider.Connect(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runVMSyncLoop(ctx, requests, &config.Config{OrchestratorURL: srv.URL, Hostname: "inventory-agent", AgentAPIKey: "test-key"}, mockProvider, srv.Client(), 10*time.Millisecond)
	}()
	select {
	case <-synced:
	case <-time.After(time.Second):
		t.Fatal("lost lifecycle event left inventory permanently stale")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inventory reconciler did not stop with a closed event stream")
	}
}

func TestInventoryReconciliationRetriesFailedDeliveryAndStops(t *testing.T) {
	var calls atomic.Int32
	synced := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		select {
		case synced <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	mockProvider := mock.New()
	if err := mockProvider.Connect(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runVMSyncLoop(ctx, make(chan struct{}), &config.Config{OrchestratorURL: srv.URL, Hostname: "inventory-agent", AgentAPIKey: "test-key"}, mockProvider, srv.Client(), 10*time.Millisecond)
	}()
	select {
	case <-synced:
	case <-time.After(time.Second):
		t.Fatal("failed inventory delivery was never reconciled without another VM event")
	}
	if calls.Load() < 2 {
		t.Fatal("delivery retry was not exercised")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inventory reconciler did not stop with its context")
	}
}
