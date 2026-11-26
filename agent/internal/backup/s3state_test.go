package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadState(t *testing.T) {
	dir := t.TempDir()

	state := &MultipartUploadState{
		Version:  1,
		BackupID: "test-123",
		Bucket:   "my-bucket",
		Created:  time.Now().UTC(),
		Files: []FileUploadState{
			{
				LocalPath: "/tmp/test.data",
				ObjectKey: "backups/test-123/test.data",
				FileSize:  1024 * 1024 * 1024,
				PartSize:  128 * 1024 * 1024,
				UploadID:  "upload-abc",
				Status:    "in_progress",
				CompletedParts: []CompletedPart{
					{PartNumber: 1, ETag: "etag1", Size: 128 * 1024 * 1024},
					{PartNumber: 2, ETag: "etag2", Size: 128 * 1024 * 1024},
				},
			},
		},
	}

	if err := SaveUploadState(dir, state); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadUploadState(dir, "test-123")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil state")
	}
	if loaded.BackupID != "test-123" {
		t.Fatalf("backup_id: got %q, want test-123", loaded.BackupID)
	}
	if len(loaded.Files) != 1 {
		t.Fatalf("files: got %d, want 1", len(loaded.Files))
	}
	if len(loaded.Files[0].CompletedParts) != 2 {
		t.Fatalf("parts: got %d, want 2", len(loaded.Files[0].CompletedParts))
	}
	if loaded.Files[0].UploadID != "upload-abc" {
		t.Fatalf("upload_id: got %q", loaded.Files[0].UploadID)
	}
}

func TestSaveStateRestrictsExistingDirectoryAndFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := &MultipartUploadState{Version: 1, BackupID: "private", Bucket: "b"}
	if err := SaveUploadState(dir, state); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{dir, 0o700},
		{filepath.Join(dir, "private.json"), 0o600},
	} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != tc.mode {
			t.Errorf("%s mode = %#o, want %#o", tc.path, got, tc.mode)
		}
	}
}

func TestSaveStateDoesNotFollowPredictableTempSymlink(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "private.json.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := SaveUploadState(dir, &MultipartUploadState{Version: 1, BackupID: "private", Bucket: "b"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("predictable temp symlink changed target: %q, %v", data, err)
	}
}

func TestLoadStateNotFound(t *testing.T) {
	dir := t.TempDir()
	state, err := LoadUploadState(dir, "nonexistent")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if state != nil {
		t.Fatal("expected nil state")
	}
}

func TestDeleteState(t *testing.T) {
	dir := t.TempDir()

	state := &MultipartUploadState{Version: 1, BackupID: "del-test", Bucket: "b"}
	SaveUploadState(dir, state)

	if err := DeleteUploadState(dir, "del-test"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	loaded, _ := LoadUploadState(dir, "del-test")
	if loaded != nil {
		t.Fatal("state should be deleted")
	}
}

func TestListUploadStates(t *testing.T) {
	dir := t.TempDir()

	for _, id := range []string{"aaa", "bbb", "ccc"} {
		SaveUploadState(dir, &MultipartUploadState{Version: 1, BackupID: id, Bucket: "b"})
	}

	ids, err := ListUploadStates(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 states, got %d", len(ids))
	}
}

func TestCompletedBytes(t *testing.T) {
	fs := FileUploadState{
		CompletedParts: []CompletedPart{
			{Size: 128 * 1024 * 1024},
			{Size: 128 * 1024 * 1024},
			{Size: 64 * 1024 * 1024}, // last part smaller
		},
	}
	expected := int64(320 * 1024 * 1024)
	if got := fs.CompletedBytes(); got != expected {
		t.Fatalf("CompletedBytes: got %d, want %d", got, expected)
	}
}

func TestAtomicSave(t *testing.T) {
	dir := t.TempDir()

	state := &MultipartUploadState{Version: 1, BackupID: "atomic-test", Bucket: "b"}
	if err := SaveUploadState(dir, state); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify no .tmp file remains
	tmpPath := filepath.Join(dir, "atomic-test.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("tmp file should not exist after save")
	}
}
