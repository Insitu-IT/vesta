//go:build linux

package storageupload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeAdmissionBindsProducerHashAndRejectsWrongAcknowledgment(t *testing.T) {
	for _, fault := range []string{"none", "wrong", "missing"} {
		t.Run(fault, func(t *testing.T) {
			producer := strings.Repeat("a", 64)
			intent := strings.Repeat("b", 64)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/agents/backups/backup/native-admission" || r.Header.Get("X-Agent-Key") != "fixture" {
					t.Error("wrong callback identity")
				}
				var value map[string]string
				if json.NewDecoder(r.Body).Decode(&value) != nil || len(value) != 3 || value["producer_request_sha256"] != producer || value["intent_sha256"] != intent || value["attempt_id"] != "attempt" {
					t.Error("producer binding omitted or changed")
				}
				reply := map[string]any{"attempt_id": "attempt", "intent_sha256": intent, "producer_request_sha256": producer, "admitted": true}
				if fault == "wrong" {
					reply["producer_request_sha256"] = strings.Repeat("c", 64)
				}
				if fault == "missing" {
					delete(reply, "producer_request_sha256")
				}
				w.Header().Set("Cache-Control", "no-store")
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			key := func(context.Context) (string, error) { return "fixture", nil }
			err := AdmitNativeProducer(context.Background(), server.URL, "backup", "attempt", intent, producer, server.Client(), key)
			if (err == nil) != (fault == "none") {
				t.Fatal("incorrect admission binding verdict", err)
			}
		})
	}
}
