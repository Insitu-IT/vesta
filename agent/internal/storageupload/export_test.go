package storageupload

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func exportJournal(t *testing.T) (*Journal, string, []byte, ExportState) {
	t.Helper()
	j, root, body, u := utilityJournal(t)
	if j.BindUtility(u) != nil {
		t.Fatal("utility")
	}
	s, _ := j.Snapshot()
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	x := ExportState{Resources: []ExportResource{{Role: "export", Name: "export", UID: "export-uid", OwnerUID: s.Native.Objects[1].UID}, {Role: "service", Name: "service", UID: "service-uid", OwnerUID: "export-uid"}, {Role: "pod", Name: "pod", UID: "pod-uid", OwnerUID: "export-uid"}, {Role: "endpointslice", Name: "slice", UID: "slice-uid", OwnerUID: "service-uid"}}, CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), Checkpoint: "child", ClusterIP: "10.0.0.1", PodAddresses: []string{"10.0.0.2"}, Volumes: []ExportVolume{}}
	for _, v := range s.Request.Plan.Source.Volumes {
		x.Volumes = append(x.Volumes, ExportVolume{Name: v.Name, VolumeID: v.PVCUID, DiskTarget: "vda", DataURL: "https://export.example/exports/" + v.Name + "/data", MapURL: "https://export.example/exports/" + v.Name + "/map"})
	}
	x.Selector = map[string]string{"routing": "fixture"}
	return j, root, body, x
}
func TestExportJournalDurabilityAndConflictingBinding(t *testing.T) {
	j, root, body, x := exportJournal(t)
	if err := j.BindExport(x); err != nil {
		t.Fatal(err)
	}
	maps := []ExportMap{{VolumeID: x.Volumes[0].VolumeID, VirtualSize: 1, Ranges: []ExportRange{{Offset: 0, Length: 1}}}}
	if err := j.BindExportMaps(maps); err != nil {
		t.Fatal(err)
	}
	s, _ := j.Snapshot()
	// Caller mutations cannot change the committed authority.
	x.Resources[0].UID = "replacement"
	maps[0].Ranges[0].Length = 2
	if j.BindExport(x) == nil || j.BindExportMaps(maps) == nil {
		t.Fatal("replacement accepted")
	}
	j.Close()
	j, err := Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.Snapshot()
	if err != nil || !reflect.DeepEqual(s, got) {
		t.Fatal("restart facts drift")
	}
}
func TestExportJournalFailedFsyncCannotAuthorizeNextEffect(t *testing.T) {
	for _, phase := range []string{"export", "maps"} {
		t.Run(phase, func(t *testing.T) {
			j, root, body, x := exportJournal(t)
			if phase == "maps" && j.BindExport(x) != nil {
				t.Fatal("bind")
			}
			before, err := os.ReadFile(j.path)
			if err != nil {
				t.Fatal(err)
			}
			j.syncFile = func(*os.File) error { return errors.New("injected fsync failure") }
			if phase == "export" {
				err = j.BindExport(x)
			} else {
				err = j.BindExportMaps([]ExportMap{{VolumeID: x.Volumes[0].VolumeID, VirtualSize: 1, Ranges: []ExportRange{}}})
			}
			if err == nil {
				t.Fatal("failed durability acknowledged")
			}
			if _, err = j.Snapshot(); err == nil {
				t.Fatal("failed writer usable")
			}
			j.Close()
			j, err = Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s, _ := j.Snapshot()
			if phase == "export" && s.Export != nil || phase == "maps" && len(s.Maps) != 0 {
				t.Fatal("uncommitted attribution restored")
			}
			if len(before) == 0 {
				t.Fatal("missing predecessor")
			}
		})
	}
}
func TestExportJournalSchemaThreeUpgradeDoesNotInventExport(t *testing.T) {
	j, root, body, _ := exportJournal(t)
	s, _ := j.Snapshot()
	path := j.path
	j.Close()
	b, _ := json.Marshal(s)
	var old map[string]any
	_ = json.Unmarshal(b, &old)
	delete(old, "export")
	delete(old, "maps")
	delete(old, "finalize")
	old["schema"] = 3
	c, _ := models.StorageCanonical(old)
	data, _ := json.Marshal(map[string]any{"state": old, "sha256": digest(c)})
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture")
	}
	j, err := Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, _ := j.Snapshot()
	if got.Schema != 5 || got.Finalize != nil || got.Export != nil || len(got.Maps) != 0 || !reflect.DeepEqual(got.Utility, s.Utility) {
		t.Fatal("upgrade invented authority")
	}
}
func TestExportJournalExactMapAndURLBounds(t *testing.T) {
	for _, value := range []string{"http://export.example/a", "https://user:password@export.example/a", "https://export.example/a?token=value", "https://export.example/a#token", "https://export.example/%2fa", "https://export.example/a\\b"} {
		if ExportURL(value) {
			t.Fatal("unsafe export URL")
		}
	}
	for _, kind := range []string{"wrong-volume", "duplicate", "overlap", "capacity", "zero-length", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			j, _, _, x := exportJournal(t)
			defer j.Close()
			if j.BindExport(x) != nil {
				t.Fatal("bind")
			}
			m := []ExportMap{{VolumeID: x.Volumes[0].VolumeID, VirtualSize: 1, Ranges: []ExportRange{{Offset: 0, Length: 1}}}}
			switch kind {
			case "wrong-volume":
				m[0].VolumeID = "other"
			case "duplicate":
				m = append(m, m[0])
			case "overlap":
				m[0].Ranges = append(m[0].Ranges, m[0].Ranges[0])
			case "capacity":
				m[0].Ranges[0].Length = ^uint64(0)
			case "zero-length":
				m[0].Ranges[0].Length = 0
			case "oversized":
				m[0].Ranges = make([]ExportRange, MaxExportRanges+1)
			}
			if j.BindExportMaps(m) == nil {
				t.Fatal("invalid map authority")
			}
		})
	}
}

func TestExportMapVirtualSizeMayBeBelowFilesystemPVCCapacity(t *testing.T) {
	j, _, _, x := exportJournal(t)
	defer j.Close()
	if err := j.BindExport(x); err != nil {
		t.Fatal(err)
	}
	s, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	capacity := uint64(s.Request.Plan.Source.Volumes[0].CapacityBytes)
	if capacity < 2 {
		t.Fatal("fixture has no filesystem overhead headroom")
	}
	mapState := []ExportMap{{VolumeID: x.Volumes[0].VolumeID, VirtualSize: capacity - 1, Ranges: []ExportRange{{Offset: 0, Length: capacity - 1}}}}
	if err := j.BindExportMaps(mapState); err != nil {
		t.Fatal("guest-visible disk smaller than filesystem PVC was refused", err)
	}
	mapState[0].VirtualSize = capacity + 1
	if err := j.BindExportMaps(mapState); err == nil {
		t.Fatal("virtual disk larger than owned PVC was accepted")
	}
}
