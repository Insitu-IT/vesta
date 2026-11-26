package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func TestSemanticRefusalBeforeExecutorWithValidDigest(t *testing.T) {
	body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	server := &BackupHandler{} // nil executor traps both provider/legacy dispatch
	response := httptest.NewRecorder()
	server.StartBackup(response, httptest.NewRequest("POST", "/api/backups", bytes.NewReader(body)))
	if response.Code != 423 {
		t.Fatalf("valid transaction did not remain held: %d", response.Code)
	}
	var request models.StorageTransactionRequest
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	// Top-level agent is outside the plan digest; signature remains valid.
	request.AgentID = "66666666-6666-4666-8666-666666666666"
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.StartBackup(response, httptest.NewRequest("POST", "/api/backups", bytes.NewReader(body)))
	if response.Code != 422 {
		t.Fatalf("unbound agent escaped semantic admission: %d", response.Code)
	}
}

func TestTransactionCannotFallThroughToLegacyExecutor(t *testing.T) {
	// Nil executor is an explicit trap: malformed new messages must never call it.
	server := &BackupHandler{}
	for _, body := range []string{
		`{"protocol":"vnbui-storage-transaction/2"}`,
		`{"protocol":"vnbui-storage-transaction/1","protocol":"other"}`,
		`{"reservation_id":"new-envelope-with-missing-protocol"}`,
	} {
		response := httptest.NewRecorder()
		server.StartBackup(response, httptest.NewRequest("POST", "/api/backups", strings.NewReader(body)))
		if response.Code != 400 && response.Code != 422 {
			t.Fatalf("unexpected admission: %d", response.Code)
		}
	}
}

func TestWrongPlanDigestCannotReachProviderOrLegacyExecutor(t *testing.T) {
	request := models.StorageTransactionRequest{
		Protocol: models.StorageProtocol, PlanSHA256: strings.Repeat("0", 64),
		Plan: models.StorageTransactionPlan{
			CapabilityProfile: "db-rooted-consumer-verified/1", Provider: "kubevirt",
			Source:     models.StorageSource{Schema: 1, Volumes: []models.StorageVolume{}},
			Exclusions: []string{}, Artifacts: []models.StorageArtifact{},
		},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	// Correct complete JSON shape, wrong digest; nil executor traps fallthrough.
	server := &BackupHandler{}
	response := httptest.NewRecorder()
	server.StartBackup(response, httptest.NewRequest("POST", "/api/backups", bytes.NewReader(body)))
	if response.Code != 422 {
		t.Fatalf("wrong digest not refused before execution: %d", response.Code)
	}
}
