package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

const testIdentity = "vnbui-kubevirt-test"

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	ks := New(path, testIdentity)

	data := &Data{
		AgentID:            "agent-123",
		AgentAPIKey:        "secret-key-456",
		OrchestratorAPIKey: "orch-key-789",
	}

	if err := ks.Save(data); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := ks.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.AgentID != data.AgentID {
		t.Errorf("AgentID = %q, want %q", loaded.AgentID, data.AgentID)
	}
	if loaded.AgentAPIKey != data.AgentAPIKey {
		t.Errorf("AgentAPIKey = %q, want %q", loaded.AgentAPIKey, data.AgentAPIKey)
	}
	if loaded.OrchestratorAPIKey != data.OrchestratorAPIKey {
		t.Errorf("OrchestratorAPIKey = %q, want %q", loaded.OrchestratorAPIKey, data.OrchestratorAPIKey)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	ks := New(path, testIdentity)

	if ks.Exists() {
		t.Error("Exists() = true before save")
	}

	ks.Save(&Data{AgentID: "x", AgentAPIKey: "y"})

	if !ks.Exists() {
		t.Error("Exists() = false after save")
	}
}

func TestLoadNonexistent(t *testing.T) {
	ks := New("/tmp/does-not-exist-vnbui-test.key", testIdentity)
	_, err := ks.Load()
	if err == nil {
		t.Error("expected error loading nonexistent keystore")
	}
}

func TestLoadCorrupted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.key")
	os.WriteFile(path, []byte("not encrypted data"), 0o600)

	ks := New(path, testIdentity)
	_, err := ks.Load()
	if err == nil {
		t.Error("expected error loading corrupted keystore")
	}
}

func TestOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	ks := New(path, testIdentity)

	ks.Save(&Data{AgentID: "old-id", AgentAPIKey: "old-key"})
	ks.Save(&Data{AgentID: "new-id", AgentAPIKey: "new-key"})

	loaded, err := ks.Load()
	if err != nil {
		t.Fatalf("load after overwrite: %v", err)
	}
	if loaded.AgentID != "new-id" {
		t.Errorf("AgentID = %q, want %q", loaded.AgentID, "new-id")
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	ks := New(path, testIdentity)

	ks.Save(&Data{AgentID: "x", AgentAPIKey: "y"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}
}

func TestCreatesMissingDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.key")
	ks := New(path, testIdentity)

	if err := ks.Save(&Data{AgentID: "x", AgentAPIKey: "y"}); err != nil {
		t.Fatalf("save with nested dirs: %v", err)
	}

	loaded, err := ks.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.AgentID != "x" {
		t.Errorf("AgentID = %q, want %q", loaded.AgentID, "x")
	}
}

func TestStableIdentitySurvivesStoreReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")
	first := New(path, testIdentity)
	if err := first.Save(&Data{AgentID: "agent-123", AgentAPIKey: "secret"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	replacement := New(path, testIdentity)
	loaded, err := replacement.Load()
	if err != nil {
		t.Fatalf("load after replacement: %v", err)
	}
	if loaded.AgentID != "agent-123" {
		t.Fatalf("AgentID = %q, want agent-123", loaded.AgentID)
	}
}

func TestDifferentIdentityCannotDecrypt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")
	if err := New(path, testIdentity).Save(&Data{AgentID: "agent-123"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	if _, err := New(path, "different-agent").Load(); err == nil {
		t.Fatal("load with a different identity succeeded")
	}
}
