//go:build linux

package storageupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeFencedFailureAcknowledgmentBindsExactAttempt(t *testing.T) {
	for _, fault := range []string{"none", "attempt", "intent", "fence", "capacity", "settled", "extra"} {
		t.Run(fault, func(t *testing.T) {
			hash := func(value string) string {
				digest := sha256.Sum256([]byte(value))
				return hex.EncodeToString(digest[:])
			}
			binding := map[string]string{"intent_canonical": `{"attempt_id":"attempt","backup_id":"backup"}`, "fence_canonical": `{"schema":"fixture"}`}
			binding["intent_sha256"], binding["fence_sha256"] = hash(binding["intent_canonical"]), hash(binding["fence_canonical"])
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/agents/backups/backup/native-fenced-failure" || r.Header.Get("X-Agent-Key") != "fixture" {
					t.Error("wrong callback")
				}
				var got map[string]string
				if json.NewDecoder(r.Body).Decode(&got) != nil || got["fence_sha256"] != binding["fence_sha256"] || len(got) != 4 {
					t.Error("changed original binding")
				}
				reply := map[string]any{"settled": true, "attempt_id": "attempt", "intent_sha256": binding["intent_sha256"], "fence_sha256": binding["fence_sha256"], "capacity_id": "capacity"}
				switch fault {
				case "attempt":
					reply["attempt_id"] = "foreign"
				case "intent":
					reply["intent_sha256"] = "foreign"
				case "fence":
					reply["fence_sha256"] = "foreign"
				case "capacity":
					reply["capacity_id"] = ""
				case "settled":
					reply["settled"] = false
				case "extra":
					reply["unknown"] = true
				}
				w.Header().Set("Cache-Control", "no-store")
				json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			key := func(context.Context) (string, error) { return "fixture", nil }
			err := SettleNativeFencedFailure(context.Background(), server.URL, "backup", binding, server.Client(), key)
			if (err == nil) != (fault == "none") {
				t.Fatal("incorrect settlement acknowledgement", err)
			}
		})
	}
}
