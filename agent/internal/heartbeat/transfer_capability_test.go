package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider/mock"
)

func TestRegistrationAdvertisesTransferProfile(t *testing.T) {
	var received models.AgentRegistration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "fixture", "api_key": "fixture"})
	}))
	defer server.Close()
	cfg := &config.Config{Provider: "kubevirt", AgentIP: "127.0.0.1", OrchestratorURL: server.URL}
	provider := mock.New()
	if _, err := Register(cfg, provider, "6.0.65", server.Client()); err != nil {
		t.Fatal(err)
	}
	restoreProfiles, ok := received.Capabilities["kubevirt_restore_profiles"].([]any)
	if !ok || len(restoreProfiles) != 1 || restoreProfiles[0] != models.KubeVirtSelectedDiskRestore {
		t.Fatal("registration lacks selected-disk restore profile")
	}
	nativeProfiles, ok := received.Capabilities["kubevirt_native_disk_profiles"].([]any)
	if !ok || len(nativeProfiles) != 1 || nativeProfiles[0] != models.KubevirtNativeDisks {
		t.Fatal("registration lacks native-disk selection profile")
	}
	profiles, ok := received.Capabilities["kubevirt_transfer_profiles"].([]any)
	if !ok || len(profiles) != 1 || profiles[0] != models.KubevirtTransfer32 {
		t.Fatal("registration lacks profile")
	}
}
