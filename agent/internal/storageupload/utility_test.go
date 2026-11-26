package storageupload

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func utilityJournal(t *testing.T) (*Journal, string, []byte, BorrowedUtility) {
	t.Helper()
	root, body := t.TempDir(), request(t, false)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.PrepareNative(nativePlan()); err != nil {
		t.Fatal(err)
	}
	owner := j.state.Request.Plan.Source.VMUID
	for _, role := range []string{"tracker", "backup", "export_token"} {
		if err := j.BeginNativeCreate(role, owner); err != nil {
			t.Fatal(err)
		}
		uid := role + "-uid"
		if err := j.ObserveNative(role, uid, owner, true); err != nil {
			t.Fatal(err)
		}
		owner = uid
	}
	if j.state.Request.Plan.Source.VMIUID == nil {
		t.Fatal("fixture VMI absent")
	}
	u := BorrowedUtility{VMIUID: *j.state.Request.Plan.Source.VMIUID, TrackerUID: "tracker-uid", BackupUID: "backup-uid", ScratchUID: "scratch-uid", Name: "backup-backup-target-pvc", ClaimName: "scratch", Type: "Backup"}
	u.StartedAt, u.BackupType = "2026-09-14T01:02:03Z", j.state.Request.Plan.BackupType
	return j, root, body, u
}

func TestUtilityJournalDurabilityAndNoReplacement(t *testing.T) {
	j, root, body, u := utilityJournal(t)
	if err := j.BindUtility(u); err != nil {
		t.Fatal(err)
	}
	if err := j.BindUtility(u); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"VMIUID", "TrackerUID", "BackupUID", "ScratchUID", "Name", "ClaimName", "Type", "StartedAt", "BackupType"} {
		other := u
		reflect.ValueOf(&other).Elem().FieldByName(field).SetString("replacement")
		if j.BindUtility(other) == nil {
			t.Fatalf("rewrote %s", field)
		}
	}
	_ = j.Close()
	j, err := Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil || s.Utility == nil || *s.Utility != u {
		t.Fatal("projection lost")
	}
}

func TestUtilityJournalFailedSyncBeforeAcknowledgment(t *testing.T) {
	j, root, body, u := utilityJournal(t)
	j.syncFile = func(*os.File) error { return errors.New("injected fsync refusal") }
	if j.BindUtility(u) == nil {
		t.Fatal("acknowledged uncommitted projection")
	}
	if _, err := j.Snapshot(); err == nil {
		t.Fatal("poisoned handle usable")
	}
	_ = j.Close()
	j, err := Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil || s.Utility != nil {
		t.Fatal("failed write invented binding")
	}
}

func TestNativeSchemaTwoUpgradePreservesOnlyExistingAuthority(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			j, root, body, _ := utilityJournal(t)
			s, _ := j.Snapshot()
			path := j.path
			_ = j.Close()
			// Construct precisely the previous on-disk shape, with no utility
			// field. Integrity is checked over that shape before upgrade.
			b, _ := json.Marshal(s)
			var old map[string]interface{}
			if json.Unmarshal(b, &old) != nil {
				t.Fatal("fixture")
			}
			delete(old, "utility")
			delete(old, "export")
			delete(old, "maps")
			delete(old, "finalize")
			old["schema"] = 2
			canonical, err := models.StorageCanonical(old)
			if err != nil {
				t.Fatal(err)
			}
			checksum := digest(canonical)
			if corrupt {
				checksum = "invalid"
			}
			data, _ := json.Marshal(map[string]interface{}{"sha256": checksum, "state": old})
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			j, err = Open(root, body)
			if corrupt {
				if err == nil {
					j.Close()
					t.Fatal("corrupt v2 accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			x, _ := j.Snapshot()
			if x.Schema != 5 || x.Finalize != nil || x.Utility != nil || !reflect.DeepEqual(x.Native, s.Native) || !reflect.DeepEqual(x.Request, s.Request) {
				t.Fatal("upgraded authority drift")
			}
		})
	}
}
