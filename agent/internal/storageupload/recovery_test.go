package storageupload

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/models"
)

func TestRecoverRequestsCurrentPrivateJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	requests, err := RecoverRequests(root)
	if err != nil || len(requests) != 0 {
		t.Fatal("empty root", err)
	}
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverRequests(root); err == nil {
		t.Fatal("recovered a journal owned by another live handle")
	}
	path := j.path
	_ = j.Close()
	before, _ := os.ReadFile(path)
	requests, err = RecoverRequests(root)
	if err != nil || len(requests) != 1 {
		t.Fatal("recover current request", err)
	}
	request, err := models.DecodeStorageTransaction(requests[0])
	if err != nil || request.BackupID != "33333333-3333-4333-8333-333333333333" {
		t.Fatal("recovered wrong request", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("enumerating requests rewrote the journal")
	}
}

func TestRecoverRequestsRefusesCorruptionAndOlderSchema(t *testing.T) {
	for _, variant := range []string{"checksum", "older-schema", "public-file", "symlink", "missing-state"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
			if err != nil {
				t.Fatal(err)
			}
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			path := j.path
			_ = j.Close()
			data, _ := os.ReadFile(path)
			switch variant {
			case "checksum", "older-schema":
				var disk diskJournal
				if err := json.Unmarshal(data, &disk); err != nil {
					t.Fatal(err)
				}
				if variant == "checksum" {
					disk.State.Request.Plan.VMName = "changed"
				} else {
					disk.State.Schema = 4
					canonical, _ := models.StorageCanonical(disk.State)
					disk.SHA256 = digest(canonical)
				}
				data, _ = json.Marshal(disk)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Dir(path), filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			case "missing-state":
				if err := os.Mkdir(filepath.Join(root, "unfinished"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RecoverRequests(root); err == nil {
				t.Fatal("unusable custody accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("refusal removed original journal", err)
			}
		})
	}
}
