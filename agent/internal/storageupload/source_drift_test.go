package storageupload

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"vnbui/agent/internal/models"
)

func parentDriftRequest(t *testing.T) []byte {
	t.Helper()
	var r models.StorageTransactionRequest
	if err := json.Unmarshal(request(t, false), &r); err != nil {
		t.Fatal(err)
	}
	r.Plan.BackupType = "incremental"
	r.Plan.Parent = &models.StorageParent{BackupID: "77777777-7777-4777-8777-777777777777", RootBackupID: "77777777-7777-4777-8777-777777777777", GenerationID: "88888888-8888-4888-8888-888888888888", ReceiptSHA256: strings.Repeat("a", 64), TrackerUID: "ancestor-tracker", Checkpoint: "ancestor-checkpoint"}
	canonical, err := models.StorageCanonical(r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r.PlanSHA256 = digest(canonical)
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = models.DecodeStorageTransaction(body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPreNativeSourceDriftPersistsWithoutRelease(t *testing.T) {
	root, body := t.TempDir(), parentDriftRequest(t)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	before, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = j.HoldPreNativeSourceDrift(); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	after, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	before.Phase = "held"
	if !reflect.DeepEqual(before, after) {
		t.Fatal("hold rewrote request, resources or custody")
	}
	if j.HoldPreNativeSourceDrift() == nil {
		t.Fatal("held attempt became retryable")
	}
}

func TestPreNativeSourceDriftRefusesLaterEffects(t *testing.T) {
	for _, variant := range []string{"full", "native", "upload", "acceptance", "export", "compensation", "fsync"} {
		t.Run(variant, func(t *testing.T) {
			body := parentDriftRequest(t)
			if variant == "full" {
				body = request(t, false)
			}
			j, err := Create(t.TempDir(), body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			switch variant {
			case "native":
				j.state.Native = &NativeState{}
			case "upload":
				j.state.Objects[0].Phase = "create_intent"
			case "acceptance":
				j.state.Acceptance = &models.StorageAcceptance{}
			case "export":
				j.state.Export = &ExportState{}
			case "compensation":
				j.state.Compensation = &CompensationState{}
			case "fsync":
				j.syncFile = func(*os.File) error { return errors.New("injected fsync failure") }
			}
			if j.HoldPreNativeSourceDrift() == nil {
				t.Fatal("unsafe or unpersisted hold accepted")
			}
			if variant == "fsync" {
				if _, err = j.Snapshot(); err == nil {
					t.Fatal("failed persistence left usable handle")
				}
			} else if j.state.Phase != "uploading" {
				t.Fatal("refusal changed phase")
			}
		})
	}
}
