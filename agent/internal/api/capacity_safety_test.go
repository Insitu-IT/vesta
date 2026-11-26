package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/resources"
)

func TestCapacityIncludesResourceAdmissionFailure(t *testing.T) {
	manager := resources.New(1, 1)
	manager.SetStoragePath(t.TempDir() + "/missing")
	h := NewHealthHandler(&config.Config{MaxConcurrentBackups: 1, BackupStoragePath: t.TempDir()}, "test")
	h.SetResources(manager)
	w := httptest.NewRecorder()
	h.Capacity(w, httptest.NewRequest("GET", "/api/health/capacity", nil))
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["available_slots"] != float64(1) || body["can_accept_backup"] != false ||
		body["resources_available"] != false || body["admission_reason"] != "storage measurement unavailable" {
		t.Fatalf("capacity hid the blocking resource gate: %s", w.Body.String())
	}
}
