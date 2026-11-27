package backup

import (
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
)

func TestLegacyPathOnlyMethodsRequireExplicitMockProvider(t *testing.T) {
	executor := NewExecutor(&config.Config{Provider: "libvirt", MockVirtnbdbackup: true}, resources.New(1, 1))
	if _, err := executor.StartBackup(&models.BackupRequest{VMName: "fixture"}); err == nil {
		t.Fatal("live libvirt admitted the mock path")
	}
	if _, err := executor.StartUpload("fixture", t.TempDir()); err == nil {
		t.Fatal("live libvirt admitted a path-only upload")
	}
}

func TestMockBackupRefusesMissingRequiredKeyBeforeCollecting(t *testing.T) {
	root := t.TempDir()
	executor := NewExecutor(&config.Config{
		Provider: "mock", MockVirtnbdbackup: true, VirtnbdbackupPath: filepath.Join(root, "fixture-executable"),
	}, resources.New(1, 1))
	destination := filepath.Join(root, "never-created")
	_, err := executor.StartBackup(&models.BackupRequest{
		BackupID: "fixture", VMName: "fixture", OutputPath: destination, EncryptionType: models.EncryptionTypeAES256GCM,
	})
	if err == nil {
		t.Fatal("admitted mock backup without required encryption key")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("incomplete encryption config created a stage: %v", err)
	}
}

func TestMockUploadRequiresUnchangedClosedStage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-stage")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vmconfig.xml"), []byte("<domain/>"), 0600); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(&config.Config{Provider: "mock", MockVirtnbdbackup: true}, resources.New(1, 1))
	executor.s3Config = &S3Config{Endpoint: "unused.example.invalid", UseSSL: true}
	if _, err := executor.StartUpload("fixture", root); err == nil {
		t.Fatal("accepted a stage without a completed backup")
	}
	if _, err := closeMockStage(root, true); err == nil {
		t.Fatal("closed a metadata-only stage")
	}
	if err := os.WriteFile(filepath.Join(root, "disk.raw.enc"), []byte("closed test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	stage, err := closeMockStage(root, true)
	if err != nil {
		t.Fatal(err)
	}
	executor.mockStages["fixture"] = stage
	if err := os.WriteFile(filepath.Join(root, "additional.raw"), []byte("ordinary fixture data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.StartUpload("fixture", root); err == nil {
		t.Fatal("accepted a changed encrypted stage containing plaintext")
	}
}
