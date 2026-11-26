package storageupload

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func nativePlan() NativeState {
	return NativeState{ScratchName: "scratch", ScratchUID: "scratch-uid", Objects: []NativeObject{
		{Role: "tracker", Name: "tracker", Phase: "planned"}, {Role: "backup", Name: "backup", Phase: "planned"}, {Role: "export_token", Name: "token", Phase: "planned"},
	}}
}

func TestNativeIntentFailureAndRestart(t *testing.T) {
	for _, point := range []string{"prepare", "create", "observed"} {
		t.Run(point, func(t *testing.T) {
			root, body := t.TempDir(), request(t, false)
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			if point != "prepare" {
				if err = j.PrepareNative(nativePlan()); err != nil {
					t.Fatal(err)
				}
			}
			if point == "observed" {
				if err = j.BeginNativeCreate("tracker", j.state.Request.Plan.Source.VMUID); err != nil {
					t.Fatal(err)
				}
			}
			j.syncFile = func(*os.File) error { return errors.New("injected fsync refusal") }
			switch point {
			case "prepare":
				err = j.PrepareNative(nativePlan())
			case "create":
				err = j.BeginNativeCreate("tracker", j.state.Request.Plan.Source.VMUID)
			case "observed":
				err = j.ObserveNative("tracker", "created-uid", j.state.Request.Plan.Source.VMUID, true)
			}
			if err == nil {
				t.Fatal("acknowledged failed persistence")
			}
			if _, err = j.Snapshot(); err == nil {
				t.Fatal("poisoned handle usable")
			}
			_ = j.Close()
			j, err = Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if point == "observed" {
				if s.Phase != "held" || s.Native.Objects[0].Phase != "create_intent" {
					t.Fatal("lost response adopted")
				}
				if j.ObserveNative("tracker", "created-uid", s.Request.Plan.Source.VMUID, true) == nil {
					t.Fatal("reopen promoted uncertain create")
				}
			} else if point == "create" && s.Native.Objects[0].Phase != "planned" {
				t.Fatal("uncommitted intent")
			}
		})
	}
}

func TestNativeUnobservedOwnerPoisonsHandle(t *testing.T) {
	j, err := Create(t.TempDir(), request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.PrepareNative(nativePlan()); err != nil {
		t.Fatal(err)
	}
	owner := j.state.Request.Plan.Source.VMUID
	if j.BeginNativeCreate("backup", "unobserved-tracker") == nil {
		t.Fatal("unbound owner")
	}
	// Refused malformed transition poisons this handle, never permitting I/O.
	if j.BeginNativeCreate("tracker", owner) == nil {
		t.Fatal("poisoned handle")
	}
}

func TestNativeBoundUIDCannotBeRewritten(t *testing.T) {
	root, body := t.TempDir(), request(t, false)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	owner := j.state.Request.Plan.Source.VMUID
	if err = j.PrepareNative(nativePlan()); err != nil {
		t.Fatal(err)
	}
	if err = j.BeginNativeCreate("tracker", owner); err != nil {
		t.Fatal(err)
	}
	if err = j.ObserveNative("tracker", "original-uid", owner, true); err != nil {
		t.Fatal(err)
	}
	if err = j.ObserveNative("tracker", "replacement-uid", owner, true); err == nil {
		t.Fatal("replacement accepted")
	}
	_ = j.Close()
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil || s.Native.Objects[0].UID != "original-uid" {
		t.Fatal("durable original identity lost")
	}
}

func TestPriorD03JournalUpgradeHasNoNativeAuthority(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "corrupt"}[corrupt], func(t *testing.T) {
			root, body := t.TempDir(), request(t, false)
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := j.Snapshot()
			path := j.path
			_ = j.Close()
			old := priorState{Schema: 1, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance}
			canonical, _ := models.StorageCanonical(old)
			checksum := digest(canonical)
			if corrupt {
				checksum = "invalid"
			}
			data, _ := json.Marshal(struct {
				SHA256 string     `json:"sha256"`
				State  priorState `json:"state"`
			}{checksum, old})
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			j, err = Open(root, body)
			if corrupt {
				if err == nil {
					j.Close()
					t.Fatal("corrupt old journal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			reopened, _ := j.Snapshot()
			if reopened.Schema != 5 || reopened.Finalize != nil || reopened.Native != nil || reopened.Utility != nil || !reflect.DeepEqual(reopened.Request, s.Request) || !reflect.DeepEqual(reopened.Objects, s.Objects) {
				t.Fatal("upgrade invented authority")
			}
			if filepath.Base(j.path) != "transaction.json" {
				t.Fatal("parallel journal")
			}
		})
	}
}
