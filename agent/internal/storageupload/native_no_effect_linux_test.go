//go:build linux

package storageupload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestNativeNoEffectRequiresExactAuthenticatedAcknowledgement(t *testing.T) {
	for _, fault := range []string{"", "attempt", "intent", "refusal", "capacity", "settled", "extra", "cache", "redirect"} {
		t.Run(fault, func(t *testing.T) {
			binding := map[string]string{"intent_canonical": "{}", "intent_sha256": strings.Repeat("a", 64), "refusal_canonical": `{"attempt_id":"original"}`, "refusal_sha256": strings.Repeat("b", 64)}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/v1/agents/backups/backup/native-no-effect" || r.Header.Get("X-Agent-Key") != "test-only" {
					t.Error("callback transport identity changed")
				}
				var got map[string]string
				if json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, binding) {
					t.Error("callback evidence changed")
				}
				w.Header().Set("Cache-Control", "no-store")
				result := map[string]interface{}{"settled": true, "attempt_id": "original", "intent_sha256": binding["intent_sha256"], "refusal_sha256": binding["refusal_sha256"], "capacity_id": "original-capacity"}
				switch fault {
				case "attempt":
					result["attempt_id"] = "other"
				case "intent":
					result["intent_sha256"] = strings.Repeat("c", 64)
				case "refusal":
					result["refusal_sha256"] = strings.Repeat("d", 64)
				case "capacity":
					result["capacity_id"] = ""
				case "settled":
					result["settled"] = false
				case "extra":
					result["unbound"] = true
				case "cache":
					w.Header().Set("Cache-Control", "public")
				case "redirect":
					w.Header().Set("Location", "https://other.invalid")
					w.WriteHeader(302)
					return
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			err := SettleNativeNoEffect(context.Background(), server.URL, "backup", binding, server.Client(), func(context.Context) (string, error) { return "test-only", nil })
			if (err == nil) != (fault == "") {
				t.Fatal("incorrect settlement acknowledgement", fault, err)
			}
		})
	}
}

func TestNativeClosedFailureRequiresExactAuthenticatedAcknowledgement(t *testing.T) {
	for _, fault := range []string{"", "attempt_id", "intent_sha256", "closure_sha256", "capacity_id", "settled", "extra", "cache", "redirect"} {
		t.Run(fault, func(t *testing.T) {
			binding := map[string]string{"intent_canonical": "{}", "intent_sha256": strings.Repeat("a", 64), "closure_canonical": `{"attempt_id":"original"}`, "closure_sha256": strings.Repeat("b", 64)}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/v1/agents/backups/backup/native-closed-failure" || r.Header.Get("X-Agent-Key") != "test-only" {
					t.Error("callback identity changed")
				}
				var got map[string]string
				if json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, binding) {
					t.Error("closure changed")
				}
				w.Header().Set("Cache-Control", "no-store")
				result := map[string]interface{}{"settled": true, "attempt_id": "original", "intent_sha256": binding["intent_sha256"], "closure_sha256": binding["closure_sha256"], "capacity_id": "original-capacity"}
				switch fault {
				case "attempt_id", "intent_sha256", "closure_sha256":
					result[fault] = "other"
				case "capacity_id":
					result[fault] = ""
				case "settled":
					result[fault] = false
				case "extra":
					result["unknown"] = true
				case "cache":
					w.Header().Set("Cache-Control", "public")
				case "redirect":
					w.Header().Set("Location", "https://other.invalid")
					w.WriteHeader(302)
					return
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			err := SettleNativeClosedFailure(context.Background(), server.URL, "backup", binding, server.Client(), func(context.Context) (string, error) { return "test-only", nil })
			if (err == nil) != (fault == "") {
				t.Fatal("incorrect closure acknowledgement", fault, err)
			}
		})
	}
}
