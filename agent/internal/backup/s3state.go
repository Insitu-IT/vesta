package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MultipartUploadState persists S3 multipart upload state to survive agent restarts.
type MultipartUploadState struct {
	Version  int               `json:"version"`
	BackupID string            `json:"backup_id"`
	Bucket   string            `json:"bucket"`
	Created  time.Time         `json:"created_at"`
	Updated  time.Time         `json:"updated_at"`
	Files    []FileUploadState `json:"files"`
}

// FileUploadState tracks multipart upload progress for a single file.
type FileUploadState struct {
	LocalPath      string          `json:"local_path"`
	ObjectKey      string          `json:"object_key"`
	FileSize       int64           `json:"file_size"`
	PartSize       int64           `json:"part_size"`
	UploadID       string          `json:"upload_id"`
	CompletedParts []CompletedPart `json:"completed_parts"`
	Status         string          `json:"status"` // "pending", "in_progress", "completed"
}

// CompletedPart records a successfully uploaded S3 multipart part.
type CompletedPart struct {
	PartNumber int    `json:"part_number"`
	ETag       string `json:"etag"`
	Size       int64  `json:"size"`
}

// CompletedBytes returns total bytes uploaded across all completed parts.
func (f *FileUploadState) CompletedBytes() int64 {
	var total int64
	for _, p := range f.CompletedParts {
		total += p.Size
	}
	return total
}

// TotalCompletedBytes returns total bytes uploaded across all files.
func (s *MultipartUploadState) TotalCompletedBytes() int64 {
	var total int64
	for _, f := range s.Files {
		total += f.CompletedBytes()
	}
	return total
}

// TotalBytes returns total file sizes across all files.
func (s *MultipartUploadState) TotalBytes() int64 {
	var total int64
	for _, f := range s.Files {
		total += f.FileSize
	}
	return total
}

// FindFile returns the FileUploadState for a given object key, or nil.
func (s *MultipartUploadState) FindFile(objectKey string) *FileUploadState {
	for i := range s.Files {
		if s.Files[i].ObjectKey == objectKey {
			return &s.Files[i]
		}
	}
	return nil
}

// statePath returns the path to the state file.
func statePath(stateDir, backupID string) string {
	return filepath.Join(stateDir, backupID+".json")
}

// LoadUploadState reads the state file for a backup. Returns nil if not found.
func LoadUploadState(stateDir, backupID string) (*MultipartUploadState, error) {
	path := statePath(stateDir, backupID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}

	var state MultipartUploadState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if state.Version != 1 {
		return nil, fmt.Errorf("unsupported state version: %d", state.Version)
	}
	return &state, nil
}

// SaveUploadState durably replaces private upload state through a random temp file.
func SaveUploadState(stateDir string, state *MultipartUploadState) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return fmt.Errorf("inspect state dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path is not a directory")
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("restrict state dir: %w", err)
	}

	state.Updated = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := statePath(stateDir, state.BackupID)
	tmp, err := os.CreateTemp(stateDir, ".upload-state-*")
	if err != nil {
		return fmt.Errorf("create tmp state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync tmp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open state dir for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync state dir: %w", err)
	}
	return nil
}

// DeleteUploadState removes the state file for a backup.
func DeleteUploadState(stateDir, backupID string) error {
	path := statePath(stateDir, backupID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete state: %w", err)
	}
	return nil
}

// ListUploadStates returns backup IDs with pending upload state files.
func ListUploadStates(stateDir string) ([]string, error) {
	entries, err := os.ReadDir(stateDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state dir: %w", err)
	}

	var ids []string
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) == ".json" && !e.IsDir() {
			ids = append(ids, name[:len(name)-5]) // strip .json
		}
	}
	return ids, nil
}
