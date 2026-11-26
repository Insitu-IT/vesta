package storageupload

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/models"
)

func pristineRequest(t *testing.T, incremental bool) []byte {
	t.Helper()
	body := request(t, false)
	if !incremental {
		return body
	}
	r, err := models.DecodeStorageTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	r.Plan.BackupType = "incremental"
	r.Plan.Parent = &models.StorageParent{
		BackupID: "11111111-1111-4111-8111-111111111111", RootBackupID: "11111111-1111-4111-8111-111111111111",
		GenerationID:  "22222222-2222-4222-8222-222222222222",
		ReceiptSHA256: digest([]byte("accepted-parent")), TrackerUID: "tracker", Checkpoint: "accepted-checkpoint",
	}
	plan, _ := models.StorageCanonical(r.Plan)
	r.PlanSHA256 = digest(plan)
	body, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.DecodeStorageTransaction(body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHoldStoppedPreNativeFullAndIncrementalPreservesRequest(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			body := pristineRequest(t, incremental)
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			path := j.path
			_ = j.Close()
			before, _ := os.ReadFile(path)
			eligible, err := HoldStoppedPreNative(root, body)
			if !eligible || err != nil {
				t.Fatal("pristine stop did not seal", eligible, err)
			}
			after, _ := os.ReadFile(path)
			if bytes.Equal(before, after) {
				t.Fatal("new hold was not durable")
			}
			current, err := lock(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			original, err := recoveredRequest(current, saved.Request.ReservationID)
			if err != nil || !bytes.Equal(original, body) {
				t.Fatal("original request changed", err)
			}
			saved.Phase = "held"
			expected, _ := models.StorageCanonical(saved)
			actual, _ := models.StorageCanonical(current.state)
			if !bytes.Equal(expected, actual) {
				t.Fatal("hold changed fields outside phase")
			}
			_ = current.Close()
			statBefore, _ := os.Stat(path)
			if eligible, err := HoldStoppedPreNative(root, body); !eligible || err != nil {
				t.Fatal("exact hold did not remain idempotent", err)
			}
			statAfter, _ := os.Stat(path)
			stable, _ := os.ReadFile(path)
			if !os.SameFile(statBefore, statAfter) || !bytes.Equal(after, stable) {
				t.Fatal("existing held journal was rewritten")
			}
			if _, err := HeldJournalSHA256(root, body); err != nil {
				t.Fatal("held journal is not reviewable", err)
			}
			requests, err := RecoverRequests(root)
			if err != nil || len(requests) != 1 || !bytes.Equal(requests[0], body) {
				t.Fatal("hold was lost on restart", err)
			}
		})
	}
}

func TestHoldStoppedPreNativeRefusesConcurrentOwnerAndConflictingRequest(t *testing.T) {
	root, body := t.TempDir(), request(t, false)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	path := j.path
	before, _ := os.ReadFile(path)
	if eligible, err := HoldStoppedPreNative(root, body); eligible || err == nil {
		t.Fatal("sealed a journal with a live exclusive owner")
	}
	_ = j.Close()
	r, _ := models.DecodeStorageTransaction(body)
	r.BackupID = "99999999-9999-4999-8999-999999999999"
	wrong, _ := json.Marshal(r)
	if eligible, err := HoldStoppedPreNative(root, wrong); eligible || err == nil {
		t.Fatal("sealed a different request")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused journal changed")
	}
}

func TestPristineHoldRefusesEveryEffectBoundary(t *testing.T) {
	j, err := Create(t.TempDir(), request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	base, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*State){
		"native preparation": func(s *State) { n := nativePlan(); s.Native = &n },
		"borrowed utility":   func(s *State) { s.Utility = &BorrowedUtility{} },
		"bound export":       func(s *State) { s.Export = &ExportState{} },
		"mapped cursor":      func(s *State) { s.Maps = []ExportMap{{}} },
		"receipt":            func(s *State) { s.Receipt = &models.StorageReceipt{} },
		"acceptance":         func(s *State) { s.Acceptance = &models.StorageAcceptance{} },
		"finalization":       func(s *State) { s.Finalize = &FinalizeState{} },
		"compensation":       func(s *State) { s.Compensation = &CompensationState{} },
		"artifact intent":    func(s *State) { s.Objects[0].Phase = "create_intent" },
		"upload identity":    func(s *State) { s.Objects[0].UploadID = "unknown-upload" },
		"part":               func(s *State) { s.Objects[0].Parts = []Part{{Number: 1}} },
		"pending part":       func(s *State) { s.Objects[0].PendingPart = &Part{Number: 1} },
		"artifact receipt":   func(s *State) { s.Objects[0].Receipt = &models.StorageObjectReceipt{} },
		"provider evidence":  func(s *State) { s.Objects[0].Provider = &ObjectInfo{} },
		"assurance":          func(s *State) { s.Objects[0].Assurance = "provider_checksum_verified" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var state State
			_ = json.Unmarshal(raw, &state)
			mutate(&state)
			if pristinePreNative(&state) {
				t.Fatal("effect-bearing state qualified")
			}
		})
	}
	if err := j.PrepareNative(nativePlan()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(j.path)
	path := j.path
	_ = j.Close()
	if eligible, err := HoldStoppedPreNative(filepath.Dir(filepath.Dir(path)), request(t, false)); eligible || err == nil {
		t.Fatal("valid native preparation qualified")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused native state changed")
	}
}

func TestHoldStoppedPreNativePersistenceFailureAndRestart(t *testing.T) {
	for _, failDirectory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[failDirectory], func(t *testing.T) {
			root, body := t.TempDir(), request(t, false)
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(j.path)
			j.syncFile = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				if info.IsDir() == failDirectory {
					return errors.New("injected fsync failure")
				}
				return f.Sync()
			}
			eligible, err := holdStoppedPreNative(j, j.state.Request.ReservationID, body)
			if !eligible || err == nil || !j.poisoned {
				t.Fatal("failed persistence was acknowledged", eligible, err)
			}
			if err := j.save(); err == nil {
				t.Fatal("poisoned handle remained usable")
			}
			path := j.path
			_ = j.Close()
			after, _ := os.ReadFile(path)
			if !failDirectory && !bytes.Equal(before, after) {
				t.Fatal("failed file sync changed original journal")
			}
			if eligible, err := HoldStoppedPreNative(root, body); !eligible || err != nil {
				t.Fatal("restart did not preserve local stopped custody", err)
			}
		})
	}
}
