//go:build kubevirt

package kubevirt

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func sourceAdmissionFixture() (*models.StorageTransactionRequest, []*unstructured.Unstructured) {
	vmiID := "original-vmi"
	r := &models.StorageTransactionRequest{Plan: models.StorageTransactionPlan{
		Provider: "kubevirt", VMName: "same-name", Exclusions: []string{"seed"},
		Source: models.StorageSource{Namespace: "ns", VMUID: "original-vm", VMIUID: &vmiID},
		Parent: &models.StorageParent{TrackerUID: "original-tracker", Checkpoint: "accepted-parent"},
	}}
	volumes, disks := []interface{}{}, []interface{}{}
	objects := []*unstructured.Unstructured{}
	for _, name := range []string{"data", "data-two"} {
		r.Plan.Source.Volumes = append(r.Plan.Source.Volumes, models.StorageVolume{Name: name, PVCName: name, PVCUID: name + "-uid", PVCResourceVersion: "42", CapacityBytes: 1048576, Mapping: models.StorageDiskMapping{DiskName: name, Device: "disk", Bus: "virtio"}})
		volumes = append(volumes, map[string]interface{}{"name": name, "persistentVolumeClaim": map[string]interface{}{"claimName": name}})
		disks = append(disks, map[string]interface{}{"name": name, "disk": map[string]interface{}{"bus": "virtio"}})
		objects = append(objects, &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]interface{}{"namespace": "ns", "name": name, "uid": name + "-uid", "resourceVersion": "42"}, "status": map[string]interface{}{"phase": "Bound", "capacity": map[string]interface{}{"storage": "1Mi"}}}})
	}
	volumes = append(volumes, map[string]interface{}{"name": "seed", "cloudInitNoCloud": map[string]interface{}{"userData": "fixture"}})
	disks = append(disks, map[string]interface{}{"name": "seed", "disk": map[string]interface{}{"bus": "virtio"}})
	spec := map[string]interface{}{"volumes": volumes, "domain": map[string]interface{}{"devices": map[string]interface{}{"disks": disks}}}
	vm := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"namespace": "ns", "name": "same-name", "uid": "original-vm"}, "spec": map[string]interface{}{"template": map[string]interface{}{"spec": spec}}}}
	vm.SetResourceVersion("17")
	_ = unstructured.SetNestedField(vm.Object, "Enabled", "status", "changedBlockTracking", "state")
	vmi := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance", "metadata": map[string]interface{}{"namespace": "ns", "name": "same-name", "uid": "original-vmi"}, "spec": runtime.DeepCopyJSON(spec)}}
	_ = unstructured.SetNestedField(vmi.Object, "Enabled", "status", "changedBlockTracking", "state")
	_ = unstructured.SetNestedField(vmi.Object, "Running", "status", "phase")
	_ = unstructured.SetNestedField(vmi.Object, "fixture-node", "status", "nodeName")
	_ = unstructured.SetNestedSlice(vmi.Object, []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}}, "status", "conditions")
	controller := true
	vmi.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachine", Name: "same-name", UID: "original-vm", Controller: &controller}})
	tracker := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackupTracker", "metadata": map[string]interface{}{"namespace": "ns", "name": kubevirtTrackerName("ns/original-vm"), "uid": "original-tracker", "annotations": map[string]interface{}{"vnbui.insitu/vm-uid": "original-vm"}}, "spec": map[string]interface{}{"source": map[string]interface{}{"name": "same-name"}}, "status": map[string]interface{}{"latestCheckpoint": map[string]interface{}{"name": "accepted-parent"}}}}
	return r, append(objects, vm, vmi, tracker)
}

func TestTransactionSourceFencesTwoVolumes(t *testing.T) {
	cases := map[string]func(*models.StorageTransactionRequest, []*unstructured.Unstructured){
		"accepted":        func(*models.StorageTransactionRequest, []*unstructured.Unstructured) {},
		"replacement-vm":  func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) { o[2].SetUID("replacement") },
		"replacement-vmi": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) { o[3].SetUID("replacement") },
		"foreign-vmi-owner": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			o[3].SetOwnerReferences(nil)
		},
		"vmi-cbt-initializing": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o[3].Object, "Initializing", "status", "changedBlockTracking", "state")
		},
		"vmi-cbt-missing": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			unstructured.RemoveNestedField(o[3].Object, "status", "changedBlockTracking")
		},
		"vmi-cbt-malformed": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o[3].Object, int64(42), "status", "changedBlockTracking", "state")
		},
		"replacement-second-pvc": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) { o[1].SetUID("replacement") },
		"pvc-version": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			o[0].SetResourceVersion("43")
		},
		"pvc-capacity": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o[1].Object, "2Mi", "status", "capacity", "storage")
		},
		"pvc-unbound": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o[1].Object, "Pending", "status", "phase")
		},
		"two-disk-omission": func(r *models.StorageTransactionRequest, _ []*unstructured.Unstructured) {
			r.Plan.Source.Volumes = r.Plan.Source.Volumes[:1]
		},
		"unknown-exclusion": func(r *models.StorageTransactionRequest, _ []*unstructured.Unstructured) {
			r.Plan.Exclusions[0] = "unknown"
		},
		"mapping-bus": func(r *models.StorageTransactionRequest, _ []*unstructured.Unstructured) {
			r.Plan.Source.Volumes[1].Mapping.Bus = "scsi"
		},
		"mapping-serial": func(r *models.StorageTransactionRequest, _ []*unstructured.Unstructured) {
			serial := "changed"
			r.Plan.Source.Volumes[0].Mapping.Serial = &serial
		},
		"tracker-replacement": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			o[4].SetUID(types.UID("replacement"))
		},
		"incidental-checkpoint-advance": func(_ *models.StorageTransactionRequest, o []*unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o[4].Object, "aborted-child", "status", "latestCheckpoint", "name")
		},
		"instance-started-after-selection": func(r *models.StorageTransactionRequest, _ []*unstructured.Unstructured) { r.Plan.Source.VMIUID = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, objects := sourceAdmissionFixture()
			mutate(r, objects)
			raw := []runtime.Object{}
			for _, o := range objects {
				raw = append(raw, o)
			}
			dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), raw...)
			e := &Executor{dynamic: dyn, namespace: "ns"}
			err := e.verifyTransactionSource(context.Background(), r)
			if (err == nil) != (name == "accepted") {
				t.Fatalf("admission result: %v", err)
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() != "get" {
					t.Fatalf("admission mutated native state: %v", action)
				}
			}
			if name == "accepted" {
				// A subsequent boundary must re-read, not trust prior admission.
				tracker, _ := dyn.Resource(kvtypes.BackupTrackerResource).Namespace("ns").Get(context.Background(), objects[4].GetName(), metav1.GetOptions{})
				tracker.SetUID("replacement")
				_, _ = dyn.Resource(kvtypes.BackupTrackerResource).Namespace("ns").Update(context.Background(), tracker, metav1.UpdateOptions{})
				if e.verifyTransactionSource(context.Background(), r) == nil {
					t.Fatal("cached admission survived replacement")
				}
			}
		})
	}
}

func TestSourceSpecRejectsAmbiguousAndUnsupportedMembership(t *testing.T) {
	for _, variant := range []string{"duplicate-disk", "duplicate-volume", "wrong-datavolume", "extra-source", "extra-disk", "wrong-claim", "vmi-only-drift"} {
		t.Run(variant, func(t *testing.T) {
			r, objects := sourceAdmissionFixture()
			spec, _, _ := unstructured.NestedMap(objects[3].Object, "spec")
			volumes := spec["volumes"].([]interface{})
			devices := spec["domain"].(map[string]interface{})["devices"].(map[string]interface{})
			disks := devices["disks"].([]interface{})
			switch variant {
			case "duplicate-disk":
				devices["disks"] = append(disks, disks[0])
			case "duplicate-volume":
				spec["volumes"] = append(volumes, volumes[0])
			case "wrong-datavolume":
				delete(volumes[0].(map[string]interface{}), "persistentVolumeClaim")
				volumes[0].(map[string]interface{})["dataVolume"] = map[string]interface{}{"name": "other"}
			case "extra-source":
				volumes[0].(map[string]interface{})["dataVolume"] = map[string]interface{}{"name": "data"}
			case "extra-disk":
				devices["disks"] = append(disks, map[string]interface{}{"name": "unplanned"})
			case "wrong-claim":
				volumes[0].(map[string]interface{})["persistentVolumeClaim"].(map[string]interface{})["claimName"] = "replacement"
			case "vmi-only-drift":
				disks[1].(map[string]interface{})["disk"].(map[string]interface{})["bus"] = "scsi"
			}
			if matchesSourceSpec(spec, r) {
				t.Fatal("ambiguous/unsupported selection accepted")
			}
		})
	}
}

func TestTransactionSourceAcceptsDataVolumeAndHoldsOneSidedChange(t *testing.T) {
	for _, variant := range []string{"both", "template-only", "instance-only"} {
		t.Run(variant, func(t *testing.T) {
			r, objects := sourceAdmissionFixture()
			for _, index := range []int{2, 3} {
				if (variant == "template-only" && index == 3) || (variant == "instance-only" && index == 2) {
					continue
				}
				path := []string{"spec"}
				if index == 2 {
					path = []string{"spec", "template", "spec"}
				}
				spec, _, _ := unstructured.NestedMap(objects[index].Object, path...)
				volume := spec["volumes"].([]interface{})[0].(map[string]interface{})
				delete(volume, "persistentVolumeClaim")
				volume["dataVolume"] = map[string]interface{}{"name": "data"}
				if err := unstructured.SetNestedMap(objects[index].Object, spec, path...); err != nil {
					t.Fatal(err)
				}
			}
			raw := []runtime.Object{}
			for _, o := range objects {
				raw = append(raw, o)
			}
			e := &Executor{dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), raw...), namespace: "ns"}
			err := e.verifyTransactionSource(context.Background(), r)
			if (err == nil) != (variant == "both") {
				t.Fatalf("DataVolume source admission %s: %v", variant, err)
			}
		})
	}
}

func TestSourceSpecUtilityFieldIsNotAnImplicitExclusion(t *testing.T) {
	for _, value := range []interface{}{nil, "malformed", map[string]interface{}{}, []interface{}{map[string]interface{}{"name": "seed", "claimName": "scratch", "type": "Backup"}}} {
		r, objects := sourceAdmissionFixture()
		spec, _, _ := unstructured.NestedMap(objects[3].Object, "spec")
		spec["utilityVolumes"] = value
		if matchesSourceSpec(spec, r) {
			t.Fatal("unattributed utility accepted as exclusion")
		}
	}
	r, objects := sourceAdmissionFixture()
	spec, _, _ := unstructured.NestedMap(objects[3].Object, "spec")
	spec["utilityVolumes"] = []interface{}{}
	if !matchesSourceSpec(spec, r) {
		t.Fatal("explicit empty utility inventory refused")
	}
}

func TestTransactionSourceRechecksCBTAfterAdmission(t *testing.T) {
	r, objects := sourceAdmissionFixture()
	raw := []runtime.Object{}
	for _, o := range objects {
		raw = append(raw, o)
	}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), raw...)
	e := &Executor{dynamic: dyn, namespace: "ns"}
	if err := e.verifyTransactionSource(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	vmi := objects[3].DeepCopy()
	_ = unstructured.SetNestedField(vmi.Object, "Disabled", "status", "changedBlockTracking", "state")
	if _, err := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Update(context.Background(), vmi, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if e.verifyTransactionSource(context.Background(), r) == nil {
		t.Fatal("cached admission survived CBT disablement")
	}
}

func TestStoppedTransactionSourceRequiresVMChangedBlockTracking(t *testing.T) {
	for _, state := range []string{"", "Initializing", "Enabled"} {
		t.Run(state, func(t *testing.T) {
			r, objects := sourceAdmissionFixture()
			r.Plan.Source.VMIUID = nil
			_ = unstructured.SetNestedField(objects[2].Object, state, "status", "changedBlockTracking", "state")
			raw := []runtime.Object{}
			for i, o := range objects {
				if i != 3 { // No running instance: the VM is the CBT authority.
					raw = append(raw, o)
				}
			}
			e := &Executor{dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), raw...), namespace: "ns"}
			if err := e.verifyTransactionSource(context.Background(), r); (err == nil) != (state == "Enabled") {
				t.Fatalf("stopped CBT %q: %v", state, err)
			}
		})
	}
}
