package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func policyConfig(t *testing.T) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(`{"source_namespaces":["one","two"],"default_selected_namespaces":["one"],"restore_namespaces":["recovery"],"scratch_pvcs":{"one":"scratch-one","two":"scratch-two"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Config{Provider: "kubevirt"}
	if err := c.LoadNamespacePolicy(path); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestInstalledScopeSubsetAndEmptySelection(t *testing.T) {
	c := policyConfig(t)
	if !c.SourceNamespaceAllowed("one") || c.SourceNamespaceAllowed("two") || c.SourceNamespaceAllowed("recovery") {
		t.Fatal("source and restore scopes mixed")
	}
	if c.ApplySourceSelection([]string{"outside"}, "r1") {
		t.Fatal("widening installation admitted")
	}
	applied, _ := c.ApplyRemoteConfig(map[string]interface{}{"selected_source_namespaces": []interface{}{}, "scope_revision": "r2"})
	if len(applied) != 2 || c.SourceNamespaceAllowed("one") || len(c.SelectedSourceNamespaces()) != 0 {
		t.Fatal("empty selection must protect none")
	}
	if c.ScopeReport()["applied_revision"] != "r2" {
		t.Fatal("selection not acknowledged")
	}
	if c.ScratchPVC("two") != "scratch-two" {
		t.Fatal("wrong namespace scratch")
	}
}
func TestKubevirtRejectsProviderSettings(t *testing.T) {
	c := policyConfig(t)
	c.LibvirtURI = "unchanged"
	applied, skipped := c.ApplyRemoteConfig(map[string]interface{}{"libvirt_uri": "qemu:///other", "virtnbdbackup_path": "/bad", "compression_type": "none"})
	if len(applied) != 0 || len(skipped) != 3 || c.LibvirtURI != "unchanged" {
		t.Fatal("inapplicable setting applied")
	}
}
func TestKubevirtMeasuresJournal(t *testing.T) {
	c := &Config{Provider: "kubevirt", KeyFilePath: "/journal/agent.key", BackupStoragePath: "/does-not-exist"}
	if c.StorageMeasurementPath() != "/journal" || c.StorageRole() != "journal" {
		t.Fatal("KubeVirt measured native payload path")
	}
}

func TestLiveLogControlAndUnsupportedCompression(t *testing.T) {
	control := new(slog.LevelVar)
	cfg := &Config{Provider: "libvirt", LogLevelControl: control, HeartbeatInterval: 30}
	applied, skipped := cfg.ApplyRemoteConfig(map[string]interface{}{"log_level": "DEBUG", "heartbeat_interval": 15, "compression_type": "none"})
	if len(applied) != 2 || len(skipped) != 1 || control.Level() != slog.LevelDebug || cfg.HeartbeatInterval != 15 {
		t.Fatal("live settings not applied, or unused compression accepted")
	}
	cfg.ApplyRemoteConfig(map[string]interface{}{"heartbeat_interval": 0, "log_level": "invalid"})
	if cfg.HeartbeatInterval != 15 || control.Level() != slog.LevelDebug {
		t.Fatal("invalid setting changed effective control")
	}
}

func TestConcurrentScopeAndRuntimeReports(t *testing.T) {
	cfg := policyConfig(t)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				cfg.ApplyRemoteConfig(map[string]interface{}{"selected_source_namespaces": []string{"one"}, "scope_revision": "r", "heartbeat_interval": 15})
				cfg.ScopeReport()
				cfg.SelectedSourceNamespaces()
				cfg.HeartbeatIntervalSeconds()
			}
		}()
	}
	workers.Wait()
}

func TestUnconfiguredSourceScopeNeverAllowsAnyNamespace(t *testing.T) {
	cfg := &Config{Provider: "kubevirt"}
	for _, ns := range []string{"", "one", "outside"} {
		if cfg.SourceNamespaceAllowed(ns) {
			t.Fatalf("unconfigured scope allowed %q", ns)
		}
	}
	cfg.KubeNamespace = "one"
	if !cfg.SourceNamespaceAllowed("one") || cfg.SourceNamespaceAllowed("outside") {
		t.Fatal("explicit singleton not enforced")
	}
}
func TestProviderCaptureCapabilityRoles(t *testing.T) {
	native := (&Config{Provider: "libvirt"}).CapabilityReport()
	pull := (&Config{Provider: "kubevirt"}).CapabilityReport()
	if native["stream_through"] != false || native["local_output"] != true || native["backup_method"] != "native_push" {
		t.Fatal("native staged capture mislabeled", native)
	}
	if pull["stream_through"] != true || pull["local_output"] != false || pull["backup_method"] != "kubevirt_pull_transaction" {
		t.Fatal("KubeVirt pull mislabeled", pull)
	}
}
