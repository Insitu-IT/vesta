//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"vnbui/agent/internal/operationbudget"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

func nativeHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func nativeFixture(t *testing.T, incremental bool) (*Executor, []byte, *models.StorageTransactionRequest, *dynamicfake.FakeDynamicClient) {
	return nativeFixtureConfigured(t, incremental, nil)
}

func nativeFixtureConfigured(t *testing.T, incremental bool, configure func(*models.StorageTransactionRequest, []*unstructured.Unstructured) []*unstructured.Unstructured) (*Executor, []byte, *models.StorageTransactionRequest, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	previous := nativeNow
	nativeNow = func() time.Time { return time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC) }
	t.Cleanup(func() { nativeNow = previous })
	body, err := os.ReadFile("../../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := models.DecodeStorageTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	source, objects := sourceAdmissionFixture()
	r.Plan.Source.Namespace, r.Plan.Source.VMUID, r.Plan.Source.VMIUID = source.Plan.Source.Namespace, source.Plan.Source.VMUID, source.Plan.Source.VMIUID
	r.Plan.Source.Volumes, r.Plan.Exclusions, r.Plan.VMName = source.Plan.Source.Volumes, source.Plan.Exclusions, source.Plan.VMName
	if incremental {
		r.Plan.BackupType = "incremental"
		r.Plan.Parent = &models.StorageParent{BackupID: "77777777-7777-4777-8777-777777777777", RootBackupID: "77777777-7777-4777-8777-777777777777", GenerationID: "88888888-8888-4888-8888-888888888888", ReceiptSHA256: strings.Repeat("a", 64), TrackerUID: "original-tracker", Checkpoint: "accepted-parent"}
	} else {
		objects = objects[:4]
	}
	r.Plan.Artifacts = nil
	root := "vnbui-owned/v1/" + nativeHash([]byte(r.OrgID)) + "/" + nativeHash([]byte(r.BackupID)) + "/payload/" + r.Plan.AttemptID + "/"
	// Contract ordering is literal-key ordering, not input-volume order.
	for _, v := range r.Plan.Source.Volumes {
		for _, role := range []string{"volume_manifest", "volume_payload"} {
			maximum := v.CapacityBytes
			if role == "volume_manifest" {
				maximum = 16 * 1024 * 1024
			}
			r.Plan.Artifacts = append(r.Plan.Artifacts, models.StorageArtifact{VolumeID: v.PVCUID, Role: role, Key: root + nativeHash([]byte(v.PVCUID)) + "/" + role, PlaintextMax: maximum, CiphertextMax: maximum})
		}
	}
	sort.Slice(r.Plan.Artifacts, func(i, j int) bool { return r.Plan.Artifacts[i].Key < r.Plan.Artifacts[j].Key })
	if configure != nil {
		objects = configure(r, objects)
	}
	p, err := models.StorageCanonical(r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r.PlanSHA256 = nativeHash(p)
	body, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = models.DecodeStorageTransaction(body); err != nil {
		t.Fatal(err)
	}
	raw := []runtime.Object{}
	for _, o := range objects {
		raw = append(raw, o)
	}
	raw = append(raw, &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]interface{}{"name": "scratch", "namespace": "ns", "uid": "scratch-original"}, "spec": map[string]interface{}{"volumeMode": "Filesystem", "accessModes": []interface{}{"ReadWriteOnce"}}, "status": map[string]interface{}{"phase": "Bound"}}})
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{kvtypes.BackupResource: "VirtualMachineBackupList", kvtypes.ExportResource: "VirtualMachineExportList", exportPodResource: "PodList", exportSliceResource: "EndpointSliceList"}, raw...)
	e := NewExecutor(&config.Config{KubeNamespace: "ns", KeyFilePath: filepath.Join(t.TempDir(), "agent.key"), KubevirtBackupScratchPVC: "scratch", KubevirtNativeTTLSeconds: config.DefaultNativeBackupTTLSeconds}, nil, dyn, "ns")
	e.cfg.KubevirtRestoreImage = "registry.example/agent@sha256:" + strings.Repeat("a", 64)
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(operationbudget.ScratchSample{At: nativeNow().UTC(), AvailableBytes: 1 << 40, CapacityBytes: 1 << 40})
	}))
	t.Cleanup(probe.Close)
	e.core, _ = kubernetes.NewForConfig(&rest.Config{Host: probe.URL})
	dyn.PrependReactor("create", "*", func(action k8stest.Action) (bool, runtime.Object, error) {
		obj := action.(k8stest.CreateAction).GetObject().(*unstructured.Unstructured)
		obj.SetUID(types.UID("uid-" + obj.GetKind()))
		obj.SetCreationTimestamp(metav1.NewTime(nativeNow()))
		obj.SetResourceVersion("1")
		if obj.GetKind() == "Lease" {
			return false, nil, nil
		}
		if obj.GetKind() == "Pod" {
			_ = unstructured.SetNestedField(obj.Object, "Running", "status", "phase")
			_ = unstructured.SetNestedField(obj.Object, "fixture-node", "spec", "nodeName")
			return false, nil, nil
		}
		// Real disk image, not a Snapshot call on the writer. Intent and full
		// request must already be fsynced before each native Create is observed.
		path := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions", r.ReservationID, "transaction.json")
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var disk struct {
			SHA256 string              `json:"sha256"`
			State  storageupload.State `json:"state"`
		}
		if json.Unmarshal(data, &disk) != nil {
			t.Fatal("journal")
		}
		canonical, _ := models.StorageCanonical(disk.State)
		if disk.SHA256 != nativeHash(canonical) || !reflect.DeepEqual(disk.State.Request, *r) {
			t.Fatal("missing durable accepted request")
		}
		found := false
		for _, o := range disk.State.Native.Objects {
			if o.Name == obj.GetName() && o.Phase == "create_intent" && o.OwnerUID != "" {
				found = true
			}
		}
		if !found {
			t.Fatal("create precedes intent")
		}
		if strings.Contains(string(data), "stringData") {
			t.Fatal("native token journaled")
		}
		return false, nil, nil
	})
	return e, body, r, dyn
}

func TestNativePreparationDurableTwoVolumeReopen(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, incremental)
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				for _, a := range dyn.Actions() {
					t.Log(a.GetVerb(), a.GetResource().Resource)
				}
				t.Fatal(err)
			}
			state, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Request.Plan.Source.Volumes) != 2 || len(state.Objects) != 4 || len(state.Native.Objects) != 3 || state.Acceptance != nil {
				t.Fatal("incomplete or premature evidence")
			}
			for _, o := range state.Native.Objects {
				if o.Phase != "observed" || o.UID == "" {
					t.Fatal("missing native UID")
				}
			}
			if _, err = e.PrepareStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("concurrent owner")
			}
			_ = j.Close()
			dyn.ClearActions()
			// Fresh executor and reopened journal, with no in-memory progress state.
			e = NewExecutor(e.cfg, nil, dyn, "ns")
			j, err = e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			reopened, _ := j.Snapshot()
			if !reflect.DeepEqual(state, reopened) || reopened.Request.ReservationID != r.ReservationID {
				t.Fatal("reopen drift")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("reopen native mutation")
				}
			}
		})
	}
}

func TestNativePreparationLostCreateNeverAdoptsOrRetries(t *testing.T) {
	for _, resource := range []string{"virtualmachinebackuptrackers", "virtualmachinebackups", "secrets"} {
		t.Run(resource, func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, false)
			dyn.PrependReactor("create", resource, func(a k8stest.Action) (bool, runtime.Object, error) {
				obj := a.(k8stest.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
				obj.SetUID("lost-response-uid")
				if err := dyn.Tracker().Create(a.GetResource(), obj, a.GetNamespace()); err != nil {
					t.Fatal(err)
				}
				return true, nil, errors.New("lost create response")
			})
			if _, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("accepted lost create")
			}
			dyn.ClearActions()
			if _, err := NewExecutor(e.cfg, nil, dyn, "ns").PrepareStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("adopted lost create")
			}
			if len(dyn.Actions()) != 0 {
				t.Fatal("uncertain reopen performed native I/O")
			}
			j, err := storageupload.Open(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s, _ := j.Snapshot()
			if s.Phase != "held" || s.Request.ReservationID != r.ReservationID {
				t.Fatal("uncertainty lost")
			}
		})
	}
}

func TestNativePreparationReplacedObjectsHeld(t *testing.T) {
	for _, role := range []string{"tracker", "backup", "export_token", "scratch"} {
		t.Run(role, func(t *testing.T) {
			e, body, _, dyn := nativeFixture(t, false)
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := j.Snapshot()
			_ = j.Close()
			resource, name := pvcResource, "scratch"
			for _, o := range s.Native.Objects {
				if o.Role == role {
					resource, name = nativeResource(role), o.Name
				}
			}
			obj, err := dyn.Resource(resource).Namespace("ns").Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			obj.SetUID("replacement")
			if _, err = dyn.Resource(resource).Namespace("ns").Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			dyn.ClearActions()
			if _, err = e.PrepareStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("replacement accepted")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("replacement mutated")
				}
			}
			if hash, err := storageupload.HeldJournalSHA256(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), body); err != nil || len(hash) != 64 {
				t.Fatal("confirmed native replacement did not become a reviewable held journal", err)
			}
		})
	}
}

func TestNativePreparationMissingObservedBackupIsReviewable(t *testing.T) {
	e, body, _, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	backup := state.Native.Objects[1]
	if err = dyn.Resource(kvtypes.BackupResource).Namespace("ns").Delete(context.Background(), backup.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	if _, err = NewExecutor(e.cfg, nil, dyn, "ns").PrepareStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("missing observed backup was accepted")
	}
	for _, action := range dyn.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("missing observed backup caused a new provider mutation")
		}
	}
	if hash, err := storageupload.HeldJournalSHA256(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), body); err != nil || len(hash) != 64 {
		t.Fatal("missing observed backup did not become a reviewable held journal", err)
	}
}

func TestNativePreparationTransientReadDoesNotHold(t *testing.T) {
	e, body, _, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	dyn.PrependReactor("get", "virtualmachinebackups", func(k8stest.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("transient API read failure")
	})
	if _, err = e.PrepareStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("transient failed read was accepted")
	}
	j, err = storageupload.Open(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Snapshot()
	if err != nil || state.Phase != "uploading" {
		t.Fatal("transient read prematurely held the journal", err)
	}
}

func TestNativePreparationRefusesBeforeCreate(t *testing.T) {
	for _, failure := range []string{"source-replacement", "second-pvc", "scratch-missing", "journal-corrupt", "journal-missing", "backup-name-collision"} {
		t.Run(failure, func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, false)
			switch failure {
			case "source-replacement", "second-pvc":
				resource, name := pvcResource, r.Plan.Source.Volumes[1].PVCName
				if failure == "source-replacement" {
					resource = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
					name = r.Plan.VMName
				}
				obj, err := dyn.Resource(resource).Namespace("ns").Get(context.Background(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				obj.SetUID("replacement")
				if _, err = dyn.Resource(resource).Namespace("ns").Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "scratch-missing":
				e.cfg.KubevirtBackupScratchPVC = "missing"
			case "journal-corrupt", "journal-missing":
				root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				j, err := storageupload.Create(root, body)
				if err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
				path := filepath.Join(root, r.ReservationID, "transaction.json")
				if failure == "journal-corrupt" {
					err = os.WriteFile(path, []byte("broken"), 0600)
				} else {
					err = os.Remove(path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "backup-name-collision":
				obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackup", "metadata": map[string]interface{}{"name": "vnbui-" + r.BackupID, "namespace": "ns", "uid": "foreign"}}}
				if err := dyn.Tracker().Create(nativeResource("backup"), obj, "ns"); err != nil {
					t.Fatal(err)
				}
			}
			dyn.ClearActions()
			if _, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("unsafe admission")
			}
			for _, a := range dyn.Actions() {
				// The conflicting VMB is encountered after a journaled tracker
				// creation; it must never be adopted, overwritten or deleted.
				if a.GetVerb() != "get" && a.GetVerb() != "list" && !(failure == "backup-name-collision" && a.GetVerb() == "create" && (a.GetResource() == nativeResource("tracker") || a.GetResource() == scratchLeases || a.GetResource() == exportPodResource)) {
					t.Fatal("unsafe native mutation")
				}
			}
		})
	}
}

func TestNativePreparationRevalidatesBetweenCreates(t *testing.T) {
	e, body, r, dyn := nativeFixture(t, false)
	dyn.PrependReactor("create", "virtualmachinebackups", func(a k8stest.Action) (bool, runtime.Object, error) {
		// Simulate source replacement while the VMB create is in flight.
		vmResource := schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
		value, err := dyn.Tracker().Get(vmResource, "ns", r.Plan.VMName)
		if err != nil {
			t.Fatal(err)
		}
		vm := value.(*unstructured.Unstructured).DeepCopy()
		vm.SetUID("replacement")
		if err = dyn.Tracker().Update(vmResource, vm, "ns"); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
	if _, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("continued after replacement")
	}
	for _, a := range dyn.Actions() {
		if a.GetVerb() == "create" && a.GetResource() == coreV1Secret {
			t.Fatal("created token after source replacement")
		}
		if a.GetVerb() == "delete" || a.GetVerb() == "patch" {
			t.Fatal("compensated outside authority")
		}
	}
}

func TestNativePreparationUnattributedUtilityRefusesBeforeMutation(t *testing.T) {
	for _, variant := range []string{"backup-scratch", "foreign-claim", "malformed"} {
		t.Run(variant, func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, false)
			resource := schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
			vmi, err := dyn.Resource(resource).Namespace("ns").Get(context.Background(), r.Plan.VMName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			// v1.9.0 utility entries have no independent UID or VMB owner.
			// Even the configured scratch claim is not attribution authority.
			claim := e.cfg.KubevirtBackupScratchPVC
			if variant == "foreign-claim" {
				claim = "foreign"
			}
			var value interface{} = []interface{}{map[string]interface{}{"name": "adjacent-backup-target-pvc", "type": "Backup", "claimName": claim}}
			if variant == "malformed" {
				value = "not-an-array"
			}
			if err = unstructured.SetNestedField(vmi.Object, value, "spec", "utilityVolumes"); err != nil {
				t.Fatal(err)
			}
			if _, err = dyn.Resource(resource).Namespace("ns").Update(context.Background(), vmi, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			dyn.ClearActions()
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err == nil {
				j.Close()
				t.Fatal("unattributed utility admitted")
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("native mutation before utility attribution")
				}
			}
		})
	}
}
