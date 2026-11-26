//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func attachedFixture(t *testing.T, incremental bool) (*Executor, []byte, *dynamicfake.FakeDynamicClient, storageupload.State) {
	return attachedFixtureConfigured(t, incremental, nil)
}

func attachedFixtureConfigured(t *testing.T, incremental bool, configure func(*models.StorageTransactionRequest, []*unstructured.Unstructured) []*unstructured.Unstructured) (*Executor, []byte, *dynamicfake.FakeDynamicClient, storageupload.State) {
	t.Helper()
	e, body, _, dyn := nativeFixtureConfigured(t, incremental, configure)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	s, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	b, err := dyn.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b.SetCreationTimestamp(metav1.NewTime(time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC)))
	nativeType := "Full"
	if incremental {
		nativeType = "Incremental"
	}
	b.Object["status"] = map[string]interface{}{"type": nativeType, "conditions": []interface{}{
		map[string]interface{}{"type": "Progressing", "status": "True", "reason": "Backup export has been initiated, waiting for export links"},
		map[string]interface{}{"type": "Done", "status": "False"},
		map[string]interface{}{"type": "ExportInitiated", "status": "True"},
		map[string]interface{}{"type": "ExportReady", "status": "False"},
	}}
	if err := dyn.Tracker().Update(kvtypes.BackupResource, b, "ns"); err != nil {
		t.Fatal(err)
	}
	vmi, err := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), s.Request.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedSlice(vmi.Object, []interface{}{map[string]interface{}{"name": b.GetName() + "-backup-target-pvc", "claimName": "scratch", "type": "Backup"}}, "spec", "utilityVolumes")
	_ = unstructured.SetNestedMap(vmi.Object, map[string]interface{}{"backupName": b.GetName(), "startTimestamp": "2026-09-14T01:02:03Z"}, "status", "changedBlockTracking", "backupStatus")
	if err := dyn.Tracker().Update(kvtypes.VMIResource, vmi, "ns"); err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	return e, body, dyn, s
}

func TestBorrowedUtilityProductionPreparationDurableReopen(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			e, body, dyn, original := attachedFixture(t, incremental)
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			s, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if s.Utility == nil || s.Utility.VMIUID != *s.Request.Plan.Source.VMIUID || s.Utility.ScratchUID != "scratch-original" || s.Utility.BackupUID != s.Native.Objects[1].UID || s.Utility.TrackerUID != s.Native.Objects[0].UID || !reflect.DeepEqual(s.Native, original.Native) {
				t.Fatal("projection or native authority")
			}
			// Independently read the committed disk before the next boundary.
			data, err := os.ReadFile(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions", s.Request.ReservationID, "transaction.json"))
			if err != nil {
				t.Fatal(err)
			}
			var disk struct {
				SHA256 string              `json:"sha256"`
				State  storageupload.State `json:"state"`
			}
			if json.Unmarshal(data, &disk) != nil || !reflect.DeepEqual(disk.State.Utility, s.Utility) {
				t.Fatal("not durable")
			}
			canonical, _ := models.StorageCanonical(disk.State)
			if disk.SHA256 != nativeHash(canonical) {
				t.Fatal("checksum")
			}
			_ = j.Close()
			e = NewExecutor(e.cfg, nil, dyn, "ns")
			j, err = e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			reopened, _ := j.Snapshot()
			if !reflect.DeepEqual(s, reopened) || reopened.Receipt != nil || reopened.Acceptance != nil {
				t.Fatal("reopen invented progress")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("borrowed attachment conferred mutation authority")
				}
			}
		})
	}
}

// Pin the wire distinction independently of the fixture builder: v1.9.0's
// backup/v1alpha1.BackupType enum is Full/Incremental, whereas transaction/1
// uses full/incremental. Lowercasing native status would hide malformed input.
func TestBorrowedUtilityNativeBackupTypeWire(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, nativeType := range []string{"Full", "Incremental", "full", "incremental", "FULL", "INCREMENTAL", "", "Unknown"} {
			planType, allowed := "full", "Full"
			if incremental {
				planType, allowed = "incremental", "Incremental"
			}
			t.Run(planType+"/"+nativeType, func(t *testing.T) {
				e, body, dyn, state := attachedFixture(t, incremental)
				b, err := dyn.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), state.Native.Objects[1].Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				_ = unstructured.SetNestedField(b.Object, nativeType, "status", "type")
				if err := dyn.Tracker().Update(kvtypes.BackupResource, b, "ns"); err != nil {
					t.Fatal(err)
				}
				dyn.ClearActions()
				j, err := e.PrepareStorageTransaction(context.Background(), body)
				if nativeType == allowed {
					if err != nil {
						t.Fatal(err)
					}
					s, err := j.Snapshot()
					_ = j.Close()
					if err != nil || s.Utility == nil || s.Utility.BackupType != planType {
						t.Fatal("native wire type changed the committed plan projection")
					}
				} else {
					if j != nil {
						_ = j.Close()
					}
					if err == nil {
						t.Fatal("unsupported native type admitted")
					}
				}
				for _, action := range dyn.Actions() {
					if action.GetVerb() != "get" || (nativeType != allowed && action.GetResource().Resource == "secrets") {
						t.Fatal("native type refusal must precede mutation and token access")
					}
				}
			})
		}
	}
}

func TestBorrowedUtilityBoundaryRefusals(t *testing.T) {
	for _, mutation := range []string{"extra", "wrong-claim", "wrong-type", "unknown-field", "readonly", "malformed", "vmi-replacement", "scratch-replacement", "tracker-replacement", "vmb-replacement", "vmb-scratch", "vmb-owner", "aborting", "failed", "completed", "timestamp", "other-backup", "status-missing", "type-mismatch", "disk-drift", "removed-after-bind", "renamed-after-bind"} {
		t.Run(mutation, func(t *testing.T) {
			e, body, dyn, state := attachedFixture(t, true)
			if mutation == "removed-after-bind" || mutation == "renamed-after-bind" {
				j, err := e.PrepareStorageTransaction(context.Background(), body)
				if err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
			}
			resource, name := kvtypes.VMIResource, state.Request.Plan.VMName
			switch mutation {
			case "scratch-replacement":
				resource, name = pvcResource, "scratch"
			case "tracker-replacement":
				resource, name = kvtypes.BackupTrackerResource, state.Native.Objects[0].Name
			case "vmb-replacement", "vmb-scratch", "vmb-owner", "aborting", "failed", "type-mismatch":
				resource, name = kvtypes.BackupResource, state.Native.Objects[1].Name
			}
			obj, err := dyn.Resource(resource).Namespace("ns").Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "vmi-replacement", "scratch-replacement", "tracker-replacement", "vmb-replacement":
				obj.SetUID("replacement")
			case "vmb-owner":
				obj.SetOwnerReferences(nil)
			case "vmb-scratch":
				_ = unstructured.SetNestedField(obj.Object, "other", "spec", "pvcName")
			case "aborting":
				_ = unstructured.SetNestedSlice(obj.Object, []interface{}{map[string]interface{}{"type": "Aborting", "status": "True", "reason": "Aborting"}}, "status", "conditions")
			case "failed":
				_ = unstructured.SetNestedSlice(obj.Object, []interface{}{map[string]interface{}{"type": "Aborting", "status": "True", "reason": "Failed"}}, "status", "conditions")
			case "type-mismatch":
				_ = unstructured.SetNestedField(obj.Object, "Full", "status", "type")
			case "completed":
				_ = unstructured.SetNestedField(obj.Object, true, "status", "changedBlockTracking", "backupStatus", "completed")
			case "timestamp":
				_ = unstructured.SetNestedField(obj.Object, "2026-09-14T01:02:04Z", "status", "changedBlockTracking", "backupStatus", "startTimestamp")
			case "other-backup":
				_ = unstructured.SetNestedField(obj.Object, "other", "status", "changedBlockTracking", "backupStatus", "backupName")
			case "status-missing":
				unstructured.RemoveNestedField(obj.Object, "status", "changedBlockTracking")
			case "disk-drift":
				_ = unstructured.SetNestedSlice(obj.Object, []interface{}{}, "spec", "domain", "devices", "disks")
			case "removed-after-bind":
				unstructured.RemoveNestedField(obj.Object, "spec", "utilityVolumes")
			case "malformed":
				_ = unstructured.SetNestedField(obj.Object, "invalid", "spec", "utilityVolumes")
			default:
				items, _, _ := unstructured.NestedSlice(obj.Object, "spec", "utilityVolumes")
				u := items[0].(map[string]interface{})
				switch mutation {
				case "extra":
					items = append(items, u)
				case "wrong-claim":
					u["claimName"] = "other"
				case "wrong-type":
					u["type"] = "MemoryDump"
				case "unknown-field":
					u["dataVolume"] = "other"
				case "readonly":
					u["readOnly"] = true
				case "renamed-after-bind":
					u["name"] = "other"
				}
				_ = unstructured.SetNestedSlice(obj.Object, items, "spec", "utilityVolumes")
			}
			if err = dyn.Tracker().Update(resource, obj, "ns"); err != nil {
				t.Fatal(err)
			}
			dyn.ClearActions()
			if j, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				_ = j.Close()
				t.Fatal("unsafe projection admitted")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("effect after refusal")
				}
				if a.GetResource().Resource == "secrets" {
					t.Fatal("token read before attachment admission")
				}
			}
		})
	}
}

func TestBorrowedUtilitySupportedControllerProgression(t *testing.T) {
	for _, reason := range []string{"Backup initiated", "Export preparation", "Backup export has been initiated, waiting for export links", "Export links ready"} {
		t.Run(reason, func(t *testing.T) {
			e, body, dyn, s := attachedFixture(t, false)
			b, err := dyn.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_ = unstructured.SetNestedSlice(b.Object, []interface{}{
				map[string]interface{}{"type": "Progressing", "status": "True", "reason": reason},
				map[string]interface{}{"type": "Done", "status": "False"},
			}, "status", "conditions")
			if err = dyn.Tracker().Update(kvtypes.BackupResource, b, "ns"); err != nil {
				t.Fatal(err)
			}
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			_ = j.Close()
			// The defaulted boolean has identical canonical meaning, and may
			// appear after an API reserialization without changing authority.
			vmi, err := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), s.Request.Plan.VMName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			items, _, _ := unstructured.NestedSlice(vmi.Object, "spec", "utilityVolumes")
			items[0].(map[string]interface{})["readOnly"] = false
			_ = unstructured.SetNestedSlice(vmi.Object, items, "spec", "utilityVolumes")
			if err = dyn.Tracker().Update(kvtypes.VMIResource, vmi, "ns"); err != nil {
				t.Fatal(err)
			}
			j, err = e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
		})
	}
}
