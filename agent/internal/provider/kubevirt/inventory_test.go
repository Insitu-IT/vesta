//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"testing"
)

func TestPersistentSourcesUseExactNamespaceUIDAndCapacity(t *testing.T) {
	vm := inventoryVM("one", "stable")
	if err := unstructured.SetNestedField(vm.Object, "Enabled", "status", "changedBlockTracking", "state"); err != nil {
		t.Fatal(err)
	}
	spec := map[string]interface{}{
		"domain": map[string]interface{}{"devices": map[string]interface{}{"disks": []interface{}{
			map[string]interface{}{"name": "data", "disk": map[string]interface{}{}},
			map[string]interface{}{"name": "boot", "disk": map[string]interface{}{}},
		}}},
		"volumes": []interface{}{
			map[string]interface{}{"name": "data", "persistentVolumeClaim": map[string]interface{}{"claimName": "same"}},
			map[string]interface{}{"name": "boot", "containerDisk": map[string]interface{}{"image": "boot"}},
		},
	}
	if err := unstructured.SetNestedMap(vm.Object, spec, "spec", "template", "spec"); err != nil {
		t.Fatal(err)
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "one", UID: "pvc-original", ResourceVersion: "17"},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Mi")}}}
	other := pvc.DeepCopy()
	other.Namespace = "two"
	other.UID = "wrong-namespace"
	p := &Provider{k8s: kubernetesfake.NewSimpleClientset(pvc, other)}
	info, err := vmToInfo(vm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.attachPersistentSources(context.Background(), vm, nil, info); err != nil {
		t.Fatal(err)
	}
	if info.Disks[0]["pvc_uid"] != "pvc-original" || info.Disks[0]["capacity_bytes"] != int64(104857600) || info.Disks[0]["backup_eligible"] != true {
		t.Fatalf("source: %+v", info.Disks)
	}
	if info.Disks[1]["backup_eligible"] != false {
		t.Fatal("container disk eligible")
	}
	// A running instance's actual volume selection wins over a pending template edit.
	instance := &unstructured.Unstructured{Object: map[string]interface{}{"spec": spec,
		"status": map[string]interface{}{"changedBlockTracking": map[string]interface{}{"state": "Enabled"}}}}
	instanceSpec := runtime.DeepCopyJSON(spec)
	instanceSpec["volumes"].([]interface{})[0].(map[string]interface{})["persistentVolumeClaim"] = map[string]interface{}{"claimName": "running"}
	instance.Object["spec"] = instanceSpec
	runningPVC := pvc.DeepCopy()
	runningPVC.Name, runningPVC.UID = "running", "running-pvc"
	p.k8s = kubernetesfake.NewSimpleClientset(pvc, runningPVC)
	info, err = vmToInfo(vm, instance)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.attachPersistentSources(context.Background(), vm, instance, info); err != nil {
		t.Fatal(err)
	}
	if info.Disks[0]["pvc_uid"] != "running-pvc" {
		t.Fatalf("template replaced running source: %+v", info.Disks)
	}
	// Replacement changes inventory evidence; it never preserves an old UID by name.
	p.k8s = kubernetesfake.NewSimpleClientset(other)
	if err = p.attachPersistentSources(context.Background(), vm, nil, info); err == nil {
		t.Fatal("missing namespace source accepted")
	}
	pvc.UID = "replacement"
	pvc.Status.Phase = corev1.ClaimPending
	p.k8s = kubernetesfake.NewSimpleClientset(pvc)
	info, _ = vmToInfo(vm, nil)
	if err = p.attachPersistentSources(context.Background(), vm, nil, info); err != nil {
		t.Fatal(err)
	}
	if info.Disks[0]["pvc_uid"] != "replacement" || info.Disks[0]["backup_eligible"] != false {
		t.Fatalf("pending: %+v", info.Disks)
	}
}

func TestPersistentSourcesRequireEnabledChangedBlockTracking(t *testing.T) {
	vm := inventoryVM("one", "stable")
	spec := map[string]interface{}{
		"domain": map[string]interface{}{"devices": map[string]interface{}{"disks": []interface{}{
			map[string]interface{}{"name": "data", "disk": map[string]interface{}{}},
		}}},
		"volumes": []interface{}{
			map[string]interface{}{"name": "data", "persistentVolumeClaim": map[string]interface{}{"claimName": "data"}},
		},
	}
	if err := unstructured.SetNestedMap(vm.Object, spec, "spec", "template", "spec"); err != nil {
		t.Fatal(err)
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "one", UID: "pvc-stable", ResourceVersion: "17"},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Mi")}}}
	p := &Provider{k8s: kubernetesfake.NewSimpleClientset(pvc)}
	for _, state := range []string{"", "PendingRestart", "Initializing", "Disabled", "FutureState", "Enabled"} {
		if state == "" {
			unstructured.RemoveNestedField(vm.Object, "status", "changedBlockTracking")
		} else if err := unstructured.SetNestedField(vm.Object, state, "status", "changedBlockTracking", "state"); err != nil {
			t.Fatal(err)
		}
		info, err := vmToInfo(vm, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.attachPersistentSources(context.Background(), vm, nil, info); err != nil {
			t.Fatal(err)
		}
		observation := info.Metadata["changed_block_tracking"].(map[string]interface{})
		var wantState interface{}
		if state != "" {
			wantState = state
		}
		if observation["state"] != wantState || observation["source"] != "vm" {
			t.Fatalf("CBT observation: %+v", observation)
		}
		eligible := info.Disks[0]["backup_eligible"]
		if eligible != (state == "Enabled") {
			t.Fatalf("CBT state %q eligibility: %v", state, eligible)
		}
		if state != "Enabled" && info.Disks[0]["source_error"] != "KubeVirt ChangedBlockTracking is not Enabled" {
			t.Fatalf("CBT state %q reason: %v", state, info.Disks[0]["source_error"])
		}
	}
	// The VM still advertises Enabled while its replacement VMI initializes.
	// Missing/disabled VMI status must not inherit the old VM's eligibility.
	for _, state := range []string{"", "Initializing", "Disabled", "FutureState", "Enabled"} {
		instance := &unstructured.Unstructured{Object: map[string]interface{}{"spec": runtime.DeepCopyJSON(spec)}}
		if state != "" {
			if err := unstructured.SetNestedField(instance.Object, state, "status", "changedBlockTracking", "state"); err != nil {
				t.Fatal(err)
			}
		}
		info, err := vmToInfo(vm, instance)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.attachPersistentSources(context.Background(), vm, instance, info); err != nil {
			t.Fatal(err)
		}
		observation := info.Metadata["changed_block_tracking"].(map[string]interface{})
		var wantState interface{}
		if state != "" {
			wantState = state
		}
		if observation["state"] != wantState || observation["source"] != "vmi" {
			t.Fatalf("replacement VMI CBT: %+v", observation)
		}
		if info.Disks[0]["backup_eligible"] != (state == "Enabled") {
			t.Fatalf("replacement VMI CBT %q inherited VM status: %+v", state, info.Disks)
		}
	}
	if err := unstructured.SetNestedField(vm.Object, int64(42), "status", "changedBlockTracking", "state"); err != nil {
		t.Fatal(err)
	}
	info, err := vmToInfo(vm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.attachPersistentSources(context.Background(), vm, nil, info); err == nil {
		t.Fatal("malformed VM CBT status accepted")
	}
}

func TestDataVolumeSourceResolvesItsBoundBackingPVC(t *testing.T) {
	vm := inventoryVM("one", "stable")
	if err := unstructured.SetNestedField(vm.Object, "Enabled", "status", "changedBlockTracking", "state"); err != nil {
		t.Fatal(err)
	}
	spec := map[string]interface{}{
		"domain": map[string]interface{}{"devices": map[string]interface{}{"disks": []interface{}{
			map[string]interface{}{"name": "data", "disk": map[string]interface{}{"bus": "virtio"}},
		}}},
		"volumes": []interface{}{
			map[string]interface{}{"name": "data", "dataVolume": map[string]interface{}{"name": "populated"}},
		},
	}
	if err := unstructured.SetNestedMap(vm.Object, spec, "spec", "template", "spec"); err != nil {
		t.Fatal(err)
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "populated", Namespace: "one", UID: "backing-pvc", ResourceVersion: "19"},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Mi")}}}
	p := &Provider{k8s: kubernetesfake.NewSimpleClientset(pvc)}
	info, err := vmToInfo(vm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.attachPersistentSources(context.Background(), vm, nil, info); err != nil {
		t.Fatal(err)
	}
	disk := info.Disks[0]
	if disk["source_type"] != "dataVolume" || disk["pvc_name"] != "populated" || disk["pvc_uid"] != "backing-pvc" || disk["backup_eligible"] != true {
		t.Fatalf("DataVolume backing PVC not captured: %+v", disk)
	}
	instance := &unstructured.Unstructured{Object: map[string]interface{}{"spec": runtime.DeepCopyJSON(spec),
		"status": map[string]interface{}{"changedBlockTracking": map[string]interface{}{"state": "Enabled"}}}}
	info, err = vmToInfo(vm, instance)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.attachPersistentSources(context.Background(), vm, instance, info); err != nil {
		t.Fatal(err)
	}
	if info.Disks[0]["source_type"] != "dataVolume" || info.Disks[0]["pvc_uid"] != "backing-pvc" || info.Disks[0]["backup_eligible"] != true {
		t.Fatalf("running DataVolume source not captured: %+v", info.Disks[0])
	}
	volume := spec["volumes"].([]interface{})[0].(map[string]interface{})
	volume["persistentVolumeClaim"] = map[string]interface{}{"claimName": "populated"}
	if err := unstructured.SetNestedMap(vm.Object, spec, "spec", "template", "spec"); err != nil {
		t.Fatal(err)
	}
	info, err = vmToInfo(vm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.attachPersistentSources(context.Background(), vm, nil, info); err == nil {
		t.Fatal("ambiguous PVC/DataVolume source accepted")
	}
}

func TestDiskMappingPreservesObservedBusAndSerial(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"domain": map[string]interface{}{
			"devices": map[string]interface{}{"disks": []interface{}{
				map[string]interface{}{"name": "data", "serial": "stable", "disk": map[string]interface{}{"bus": "scsi"}},
				map[string]interface{}{"name": "unknown", "disk": map[string]interface{}{}},
			}},
		}},
	}}
	disks := extractDisks(obj)
	mapping := disks[0]["mapping"].(map[string]interface{})
	if mapping["disk_name"] != "data" || mapping["device"] != "disk" || mapping["bus"] != "scsi" || mapping["serial"] != "stable" {
		t.Fatalf("mapping changed: %v", mapping)
	}
	missing := disks[1]["mapping"].(map[string]interface{})
	if missing["bus"] != "" || missing["serial"] != nil {
		t.Fatal("invented absent mapping")
	}
}

func inventoryVM(ns, uid string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
		"metadata": map[string]interface{}{"name": "same", "namespace": ns, "uid": uid},
		"spec":     map[string]interface{}{"template": map[string]interface{}{"spec": map[string]interface{}{"domain": map[string]interface{}{}}}},
	}}
}

func TestInventoryRejectsPartialListAndDoesNotAdoptReplacedInstance(t *testing.T) {
	vm := inventoryVM("one", "new-vm")
	vmi := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": map[string]interface{}{"name": "same", "namespace": "one", "uid": "old-vmi"},
		"status":   map[string]interface{}{"phase": "Running"},
	}}
	vmi.SetOwnerReferences([]metav1.OwnerReference{{Kind: "VirtualMachine", UID: "old-vm"}})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{VMResource: "VirtualMachineList", VMIResource: "VirtualMachineInstanceList"}, vm, vmi)
	p := &Provider{connected: true, dynamic: client}
	p.SetNamespaceScope(func() []string { return []string{"one", "two"} }, []string{"one", "two"})
	vms, err := p.ListVMs()
	if err != nil || len(vms) != 1 || vms[0].VMIUID != "" || vms[0].State != "unknown" {
		t.Fatalf("replacement inherited instance: %+v %v", vms, err)
	}
	calls := 0
	client.PrependReactor("list", "virtualmachines", func(a ktesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			page := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*vm}}
			page.SetContinue("next")
			return true, page, nil
		}
		return true, nil, fmt.Errorf("second page unavailable")
	})
	if partial, err := p.ListVMs(); err == nil || partial != nil || calls != 2 {
		t.Fatalf("partial inventory accepted: %+v %v calls=%d", partial, err, calls)
	}
}

func TestInventoryUsesVMObjectsAndOwnerUID(t *testing.T) {
	vm := inventoryVM("one", "stable")
	other := inventoryVM("two", "other")
	vmi := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": map[string]interface{}{"name": "same", "namespace": "one", "uid": "instance"},
		"status":   map[string]interface{}{"phase": "Running"}}}
	controller := true
	vmi.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachine", Name: "same", UID: types.UID("stable"), Controller: &controller}})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{VMResource: "VirtualMachineList", VMIResource: "VirtualMachineInstanceList"}, vm, other, vmi)
	p := &Provider{connected: true, dynamic: client}
	p.SetNamespaceScope(func() []string { return []string{"one", "two"} }, []string{"one", "two"})
	vms, err := p.ListVMs()
	if err != nil || len(vms) != 2 {
		t.Fatalf("inventory: %v %v", vms, err)
	}
	for _, got := range vms {
		if got.Namespace == "one" && (got.VMUID != "stable" || got.VMIUID != "instance" || got.State != "running") {
			t.Fatalf("running: %+v", got)
		}
		if got.Namespace == "two" && (got.State != "stopped" || got.VMIUID != "") {
			t.Fatalf("stopped: %+v", got)
		}
	}
	if _, err := p.GetVM("same"); err == nil {
		t.Fatal("ambiguous name accepted")
	}
}

func TestEmptyInventoryIsAnArray(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{VMResource: "VirtualMachineList", VMIResource: "VirtualMachineInstanceList"})
	p := &Provider{connected: true, dynamic: client}
	p.SetNamespaceScope(func() []string { return []string{"one", "two"} }, []string{"one", "two"})
	vms, err := p.ListVMs()
	if err != nil || vms == nil || len(vms) != 0 {
		t.Fatalf("empty: %#v %v", vms, err)
	}
}

func TestMemoryObservationPrecedenceAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		current, guest, request string
		active, instanceType    bool
		want                    int64
		source                  interface{}
	}{
		{"guest only", "", "1Gi", "", true, false, 1048576, "vmi.spec.domain.memory.guest"},
		{"guest beats request", "", "1Gi", "2Gi", true, false, 1048576, "vmi.spec.domain.memory.guest"},
		{"current beats requested guest", "1Gi", "2Gi", "3Gi", true, false, 1048576, "vmi.status.memory.guestCurrent"},
		{"request fallback", "", "", "512Mi", true, false, 524288, "vmi.spec.domain.resources.requests.memory"},
		{"stopped guest", "", "2Gi", "3Gi", false, false, 2097152, "vm.spec.template.spec.domain.memory.guest"},
		{"stopped request fallback", "", "", "512Mi", false, false, 524288, "vm.spec.template.spec.domain.resources.requests.memory"},
		{"missing", "", "", "", false, false, 0, nil},
		{"unresolved instance type", "", "", "1Gi", false, true, 0, nil},
		{"unresolved active instance type", "", "", "1Gi", true, true, 0, nil},
		{"resolved active instance type", "", "2Gi", "1Gi", true, true, 2097152, "vmi.spec.domain.memory.guest"},
		{"invalid current stays unknown", "broken", "1Gi", "2Gi", true, false, 0, "vmi.status.memory.guestCurrent"},
		{"invalid guest stays unknown", "", "broken", "2Gi", false, false, 0, "vm.spec.template.spec.domain.memory.guest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := inventoryVM("ns", "stable")
			spec := map[string]interface{}{}
			if tc.guest != "" {
				unstructured.SetNestedField(spec, tc.guest, "domain", "memory", "guest")
			}
			if tc.request != "" {
				unstructured.SetNestedField(spec, tc.request, "domain", "resources", "requests", "memory")
			}
			unstructured.SetNestedMap(vm.Object, spec, "spec", "template", "spec")
			if tc.instanceType {
				unstructured.SetNestedMap(vm.Object, map[string]interface{}{"name": "unresolved"}, "spec", "instancetype")
			}
			var instance *unstructured.Unstructured
			if tc.active {
				instance = &unstructured.Unstructured{Object: map[string]interface{}{"spec": spec}}
				if tc.current != "" {
					unstructured.SetNestedField(instance.Object, tc.current, "status", "memory", "guestCurrent")
				}
			}
			info, err := vmToInfo(vm, instance)
			if err != nil {
				t.Fatal(err)
			}
			memory := info.Metadata["memory"].(map[string]interface{})
			if info.MemoryKB != tc.want || memory["source"] != tc.source || memory["known"] != (tc.want > 0) {
				t.Fatalf("memory=%d provenance=%+v", info.MemoryKB, memory)
			}
		})
	}
}
