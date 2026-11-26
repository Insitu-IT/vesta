package storageupload

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func TestTransferProfileSizingMatchesSharedContract(t *testing.T) {
	data, err := os.ReadFile("../../contracts/storage_transfer_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Profile *string `json:"profile"`
		Role    string  `json:"role"`
		Maximum int64   `json:"ciphertext_max"`
		Part    int     `json:"part_bytes"`
		Range   uint64  `json:"range_bytes"`
	}
	if json.Unmarshal(data, &vectors) != nil {
		t.Fatal("invalid vectors")
	}
	for _, v := range vectors {
		profile := ""
		if v.Profile != nil {
			profile = *v.Profile
		}
		got, err := plannedPartSize(models.StorageArtifact{Role: v.Role, CiphertextMax: v.Maximum}, profile)
		source, readErr := models.StorageSourceRangeBytes(profile)
		if err != nil || readErr != nil || got != v.Part || source != v.Range || int64(got)*10000 < v.Maximum {
			t.Fatalf("sizing drift: %+v %d %v", v, got, err)
		}
	}
	for _, profile := range []string{"", models.KubevirtTransfer32, "unknown"} {
		for _, maximum := range []int64{-1, int64(maxPartSize)*10000 + 1} {
			if _, err := plannedPartSize(models.StorageArtifact{Role: "volume_payload", CiphertextMax: maximum}, profile); err == nil {
				t.Fatal("unsupported maximum")
			}
		}
	}
	if _, err := plannedPartSize(models.StorageArtifact{CiphertextMax: 1}, "unknown"); err == nil {
		t.Fatal("unknown profile")
	}
}

func TestTransferProfileJournalCompatibilityAndFsyncRefusal(t *testing.T) {
	for _, profile := range []string{"", models.KubevirtTransfer32} {
		body := request(t, true)
		r, err := models.DecodeStorageTransaction(body)
		if err != nil {
			t.Fatal(err)
		}
		r.Plan.TransferProfile = profile
		canonical, _ := models.StorageCanonical(r.Plan)
		r.PlanSHA256 = digest(canonical)
		body, _ = json.Marshal(r)
		root := t.TempDir()
		j, err := Create(root, body)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := j.Snapshot()
		j.Close()
		reopened, err := Open(root, body)
		if err != nil {
			t.Fatal("original journal refused", err)
		}
		after, _ := reopened.Snapshot()
		if !reflect.DeepEqual(before, after) {
			t.Fatal("journal rewritten under other sizing rule")
		}
		// A failed durable intent must not authorize even the first provider call.
		store := store(t, body)
		reopened.syncFile = func(*os.File) error { return os.ErrPermission }
		opens := 0
		streams := inputs(*r, 7, &opens)
		if reopened.UploadAll(context.Background(), store, streams, make([]byte, 32)) == nil || len(store.calls) != 0 || opens != 0 {
			t.Fatal("fsync refusal reached provider")
		}
		reopened.Close()
	}
}
