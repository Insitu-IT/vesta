package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure no env vars interfere
	os.Unsetenv("AGENT_PORT")
	os.Unsetenv("ORCHESTRATOR_URL")

	cfg := Load()

	if cfg.AgentPort != 8090 {
		t.Errorf("AgentPort: got %d, want 8090", cfg.AgentPort)
	}
	if cfg.OrchestratorURL != "http://localhost:8000" {
		t.Errorf("OrchestratorURL: got %q", cfg.OrchestratorURL)
	}
	if cfg.MaxConcurrentBackups != 2 {
		t.Errorf("MaxConcurrentBackups: got %d, want 2", cfg.MaxConcurrentBackups)
	}
	if cfg.HeartbeatInterval != 30 {
		t.Errorf("HeartbeatInterval: got %d, want 30", cfg.HeartbeatInterval)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel: got %q, want INFO", cfg.LogLevel)
	}
	if cfg.LibvirtURI != "qemu:///system" {
		t.Errorf("LibvirtURI: got %q", cfg.LibvirtURI)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("AGENT_PORT", "9090")
	t.Setenv("MAX_CONCURRENT_BACKUPS", "4")
	t.Setenv("MOCK_LIBVIRT", "true")
	t.Setenv("ORCHESTRATOR_URL", "https://backend.example.com")
	t.Setenv("KUBEVIRT_BACKUP_SCRATCH_PVC", "vnbui-backup-scratch")
	t.Setenv("KEYSTORE_IDENTITY", "vnbui-kubevirt")

	cfg := Load()

	if cfg.AgentPort != 9090 {
		t.Errorf("AgentPort: got %d, want 9090", cfg.AgentPort)
	}
	if cfg.MaxConcurrentBackups != 4 {
		t.Errorf("MaxConcurrentBackups: got %d, want 4", cfg.MaxConcurrentBackups)
	}
	if !cfg.MockLibvirt {
		t.Error("MockLibvirt should be true")
	}
	if cfg.OrchestratorURL != "https://backend.example.com" {
		t.Errorf("OrchestratorURL: got %q", cfg.OrchestratorURL)
	}
	if cfg.KubevirtBackupScratchPVC != "vnbui-backup-scratch" {
		t.Errorf("KubevirtBackupScratchPVC: got %q", cfg.KubevirtBackupScratchPVC)
	}
	if cfg.KeystoreIdentity != "vnbui-kubevirt" {
		t.Errorf("KeystoreIdentity: got %q", cfg.KeystoreIdentity)
	}
}

func TestListenAddr(t *testing.T) {
	cfg := &Config{AgentHost: "0.0.0.0", AgentPort: 8090}
	if cfg.ListenAddr() != "0.0.0.0:8090" {
		t.Errorf("ListenAddr: got %q", cfg.ListenAddr())
	}
}

func TestApplyRemoteConfig(t *testing.T) {
	cfg := Load()
	cfg.HeartbeatInterval = 30

	remote := map[string]interface{}{
		"heartbeat_interval": float64(15),
		"unknown_setting":    "ignored",
	}

	applied, skipped := cfg.ApplyRemoteConfig(remote)

	if cfg.HeartbeatInterval != 15 {
		t.Errorf("HeartbeatInterval: got %d, want 15", cfg.HeartbeatInterval)
	}
	if len(applied) != 1 {
		t.Errorf("applied: got %d, want 1", len(applied))
	}
	if len(skipped) != 1 {
		t.Errorf("skipped: got %d, want 1", len(skipped))
	}
}

func TestApplyRemoteConfigLocalOverride(t *testing.T) {
	t.Setenv("MAX_CONCURRENT_BACKUPS", "8")

	cfg := Load()

	remote := map[string]interface{}{
		"max_concurrent_backups": float64(4),
	}

	applied, skipped := cfg.ApplyRemoteConfig(remote)

	// Should NOT be changed because env var overrides
	if cfg.MaxConcurrentBackups != 8 {
		t.Errorf("MaxConcurrentBackups: got %d, want 8 (env override)", cfg.MaxConcurrentBackups)
	}
	if len(applied) != 0 {
		t.Errorf("applied: got %d, want 0", len(applied))
	}
	if len(skipped) != 1 {
		t.Errorf("skipped: got %d, want 1", len(skipped))
	}
}

func TestValidateProduction(t *testing.T) {
	cfg := &Config{Environment: "development", MockLibvirt: true}
	if err := cfg.ValidateProduction(); err != nil {
		t.Errorf("dev should not fail validation: %v", err)
	}

	cfg = &Config{Environment: "production", MockLibvirt: true}
	if err := cfg.ValidateProduction(); err == nil {
		t.Error("production with mock should fail validation")
	}
}

func TestKubeAPIAndTransactionBudgets(t *testing.T) {
	t.Setenv("PROVIDER", "kubevirt")
	t.Setenv("KUBE_NAMESPACE", "test")
	t.Setenv("KUBE_API_QPS", "50")
	t.Setenv("KUBE_API_BURST", "100")
	t.Setenv("KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS", "0")
	t.Setenv("KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS", "64800")
	cfg := Load()
	if err := cfg.ValidateProduction(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"KUBE_API_QPS", "KUBE_API_BURST", "KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS", "KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "invalid")
			if Load().ValidateProduction() == nil {
				t.Fatal("invalid startup budget silently defaulted")
			}
		})
	}
	applied, _ := cfg.ApplyRemoteConfig(map[string]interface{}{"kube_api_qps": 1, "kube_api_burst": 1, "kubevirt_transaction_timeout_seconds": 1, "kubevirt_native_backup_ttl_seconds": 1})
	if len(applied) != 0 || cfg.KubeAPIQPS != 50 || cfg.KubeAPIBurst != 100 || cfg.KubevirtTransactionTimeoutSeconds != 0 || cfg.KubevirtNativeTTLSeconds != 64800 {
		t.Fatal("heartbeat changed installation-owned budget")
	}
}
