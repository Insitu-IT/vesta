package storageupload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func finalizeJournal(t *testing.T) (*Journal, string, []byte) {
	return finalizeJournalVersioned(t, false)
}

func finalizeJournalVersioned(t *testing.T, versioned bool) (*Journal, string, []byte) {
	t.Helper()
	j, root, body, x := exportJournal(t)
	if j.BindExport(x) != nil || j.BindExportMaps([]ExportMap{{VolumeID: x.Volumes[0].VolumeID, VirtualSize: 1, Ranges: []ExportRange{}}}) != nil {
		t.Fatal("export")
	}
	provider := store(t, body)
	provider.version = versioned
	reads := 0
	if err := j.UploadAll(context.Background(), provider, inputs(provider.r, 0, &reads), nil); err != nil {
		t.Fatal(err)
	}
	response := ack(t, j)
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	if _, err := j.Submit(context.Background(), "https://backend.test", client, func(context.Context) (string, error) { return "fixture", nil }); err != nil {
		t.Fatal(err)
	}
	return j, root, body
}
func TestFinalizeJournalFsyncBeforeNextEffect(t *testing.T) {
	for _, stage := range []string{"intent", "delete", "terminal", "proof"} {
		t.Run(stage, func(t *testing.T) {
			j, root, body := finalizeJournal(t)
			if stage != "intent" {
				if j.PrepareFinalize("unknown") != nil {
					t.Fatal("prepare")
				}
				j.state.Finalize.IntentID = "acknowledged-intent"
				if j.save() != nil {
					t.Fatal("ack")
				}
			}
			if stage == "terminal" || stage == "proof" {
				if j.RecordDeleteIntent("41") != nil {
					t.Fatal("delete intent")
				}
			}
			if stage == "proof" {
				if j.RecordTerminal("43") != nil {
					t.Fatal("terminal")
				}
			}
			before, err := os.ReadFile(j.path)
			if err != nil {
				t.Fatal(err)
			}
			j.syncFile = func(*os.File) error { return errors.New("injected fsync refusal") }
			switch stage {
			case "intent":
				err = j.PrepareFinalize("unknown")
			case "delete":
				err = j.RecordDeleteIntent("41")
			case "terminal":
				err = j.RecordTerminal("43")
			case "proof":
				err = j.RecordCheckpoint("51")
			}
			if err == nil {
				t.Fatal("fsync failed open")
			}
			if _, err = j.Snapshot(); err == nil {
				t.Fatal("poisoned journal used")
			}
			_ = j.Close()
			after, err := os.ReadFile(j.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("uncommitted evidence durable")
			}
			j, err = Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
		})
	}
}
func TestFinalizeRequiresAcceptedReceiptNotPrepared(t *testing.T) {
	for _, phase := range []string{"uploading", "prepared", "submitting", "held"} {
		t.Run(phase, func(t *testing.T) {
			j, _, _ := finalizeJournal(t)
			defer j.Close()
			j.state.Phase, j.state.Acceptance = phase, nil
			if j.PrepareFinalize("quiesced") == nil || j.RecordDeleteIntent("1") == nil || j.RecordTerminal("2") == nil || j.RecordCheckpoint("3") == nil {
				t.Fatal("premature finalize")
			}
		})
	}
}

func TestFinalizeCorruptNativeInventoryRefusesReopen(t *testing.T) {
	j, root, body := finalizeJournal(t)
	if j.PrepareFinalize("unknown") != nil {
		t.Fatal("prepare")
	}
	s, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := j.path
	j.Close()
	s.Native.Objects = nil
	canonical, err := models.StorageCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(diskJournal{State: s, SHA256: digest(canonical)})
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("corrupt fixture")
	}
	if reopened, err := Open(root, body); err == nil {
		reopened.Close()
		t.Fatal("corrupt native inventory admitted")
	}
}

func TestFinalizeJournalV4UpgradeDoesNotInventFinalizeAuthority(t *testing.T) {
	j, root, body := finalizeJournal(t)
	s, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := j.path
	j.Close()
	b, _ := json.Marshal(s)
	var old map[string]any
	if json.Unmarshal(b, &old) != nil {
		t.Fatal("fixture")
	}
	delete(old, "finalize")
	old["schema"] = 4
	c, _ := models.StorageCanonical(old)
	data, _ := json.Marshal(map[string]any{"state": old, "sha256": digest(c)})
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture")
	}
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.Snapshot()
	s.Schema = 5
	if err != nil || got.Finalize != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("upgrade changed accepted custody")
	}
}
