//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func TestRetirementProofRequiresExactVerifiedCallback(t *testing.T) {
	for _, variant := range []string{"exact", "wrong-journal", "error", "no-store-missing", "extra-field"} {
		t.Run(variant, func(t *testing.T) {
			e, body, request := runnerFixture(t)
			journalHash := strings.Repeat("a", 64)
			var calls int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/backups/"+request.BackupID+"/storage-retirement" ||
					r.Header.Get("X-Agent-Key") != e.cfg.AgentAPIKey || r.Header.Get("Content-Type") != "application/json" {
					t.Error("retirement callback lacked registered transport binding")
				}
				var binding map[string]string
				if json.NewDecoder(r.Body).Decode(&binding) != nil || len(binding) != 4 ||
					binding["reservation_id"] != request.ReservationID || binding["attempt_id"] != request.Plan.AttemptID ||
					binding["plan_sha256"] != request.PlanSHA256 || binding["journal_sha256"] != journalHash {
					t.Error("retirement callback had wrong held-journal binding")
				}
				if variant == "error" {
					w.WriteHeader(http.StatusConflict)
					return
				}
				if variant != "no-store-missing" {
					w.Header().Set("Cache-Control", "no-store")
				}
				proof := storageupload.RetirementProof{
					Schema: 1, OrgID: request.OrgID, BackupID: request.BackupID,
					ReservationID: request.ReservationID, AttemptID: request.Plan.AttemptID,
					PlanSHA256: request.PlanSHA256, OperationID: "11111111-1111-4111-8111-111111111111",
					CapacityID: "22222222-2222-4222-8222-222222222222", JournalSHA256: journalHash,
					ReleaseSHA256: strings.Repeat("b", 64),
				}
				if variant == "wrong-journal" {
					proof.JournalSHA256 = strings.Repeat("c", 64)
				}
				if variant == "extra-field" {
					value := map[string]any{}
					encoded, _ := json.Marshal(proof)
					_ = json.Unmarshal(encoded, &value)
					value["forged"] = true
					_ = json.NewEncoder(w).Encode(value)
					return
				}
				_ = json.NewEncoder(w).Encode(proof)
			}))
			defer server.Close()
			e.cfg.OrchestratorURL = server.URL
			r := &transactionRunner{executor: e, backend: server.Client(), key: e.cfg.AgentAPIKey}
			decoded, err := models.DecodeStorageTransaction(body)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := r.retirementProof(context.Background(), &transactionWork{request: decoded}, journalHash)
			if variant == "exact" {
				if err != nil || proof.JournalSHA256 != journalHash {
					t.Fatal("exact verified proof refused", err)
				}
			} else if err == nil {
				t.Fatal("unverified proof accepted")
			}
			if calls != 1 {
				t.Fatal("unexpected callback count", calls)
			}
		})
	}
}
