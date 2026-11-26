//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/models"
)

func TestBackupDiscoveryUsesOnlyAPIResourcesAndDistinguishesDenied(t *testing.T) {
	count := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count[r.URL.Path]++
		if r.Method != "GET" {
			t.Errorf("unexpected method %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		var response string
		switch r.URL.Path {
		case "/apis/backup.kubevirt.io/v1alpha1":
			response = `{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"backup.kubevirt.io/v1alpha1","resources":[{"name":"virtualmachinebackups"}]}`
		case "/apis/export.kubevirt.io/v1beta1":
			w.WriteHeader(http.StatusForbidden)
			response = `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}`
		case "/apis/groupsnapshot.storage.k8s.io":
			response = `{"apiVersion":"v1","kind":"APIGroup","name":"groupsnapshot.storage.k8s.io","versions":[{"version":"v1","groupVersion":"groupsnapshot.storage.k8s.io/v1"}]}`
		case "/apis/groupsnapshot.storage.k8s.io/v1":
			response = `{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"groupsnapshot.storage.k8s.io/v1","resources":[{"name":"volumegroupsnapshots"},{"name":"volumegroupsnapshotclasses"}]}`
		default:
			t.Errorf("unexpected discovery path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	disk := map[string]interface{}{"source_type": "persistentVolumeClaim"}
	vms := []models.VMInfo{
		{Metadata: map[string]interface{}{}, Disks: []map[string]interface{}{disk}},
		{Metadata: map[string]interface{}{}, Disks: []map[string]interface{}{disk, disk}},
		{Metadata: map[string]interface{}{}, Disks: []map[string]interface{}{disk, disk}},
	}
	(&Provider{k8s: client}).describeBackupAPIs(context.Background(), vms)
	for i, vm := range vms {
		apis := vm.Metadata["backup_apis"].(map[string]string)
		if apis["virtualmachinebackups"] != "served" || apis["virtualmachinebackuptrackers"] != "not_served" || apis["virtualmachineexports"] != "unknown" {
			t.Fatalf("unexpected API evidence: %v", apis)
		}
		if (apis["group_snapshot"] == "served") != (i > 0) {
			t.Fatalf("incorrect multidisk evidence: %v", apis)
		}
	}
	for path, n := range count {
		if n != 1 {
			t.Fatalf("read %s %d times per inventory", path, n)
		}
	}
}

func TestVolumeSnapshotObservationBindsOnlyTheSameTemplateVolume(t *testing.T) {
	var object map[string]interface{}
	err := json.Unmarshal([]byte(`{
		"spec":{"template":{"spec":{"volumes":[
			{"name":"data","dataVolume":{"name":"data"}},
			{"name":"moved","persistentVolumeClaim":{"claimName":"old"}},
			{"name":"ambiguous","dataVolume":{"name":"ambiguous"}},
			{"name":"off","dataVolume":{"name":"off"}}]}}},
		"status":{"volumeSnapshotStatuses":[
			{"name":"data","enabled":true,"reason":"controller private diagnostic"},
			{"name":"moved","enabled":true},{"name":"ambiguous","enabled":false},
			{"name":"ambiguous","enabled":true},{"name":"off","enabled":false}]}}`), &object)
	if err != nil {
		t.Fatal(err)
	}
	vm := &unstructured.Unstructured{Object: object}
	volumes, _, _ := unstructured.NestedSlice(vm.Object, "spec", "template", "spec", "volumes")
	current := map[string]map[string]interface{}{}
	for _, item := range volumes {
		v := item.(map[string]interface{})
		current[v["name"].(string)] = v
	}
	current["moved"]["persistentVolumeClaim"] = map[string]interface{}{"claimName": "new"}
	got := volumeSnapshotStatuses(vm, current)
	if !reflect.DeepEqual(got, map[string]bool{"data": true, "off": false}) {
		t.Fatalf("wrong snapshot evidence: %v", got)
	}
}

func TestExactTrackerObservationAndFailureStates(t *testing.T) {
	vm := models.VMInfo{Name: "source", VMUID: "vm-uid", Namespace: "test"}
	name := TrackerName("vesta", "test/vm-uid")
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackupTracker",
		"metadata": map[string]interface{}{"name": name, "namespace": vm.Namespace, "uid": "tracker-id",
			"annotations": map[string]interface{}{"vnbui.insitu/vm-uid": vm.VMUID, "private": "filtered"}},
		"spec":   map[string]interface{}{"source": map[string]interface{}{"apiGroup": "kubevirt.io", "kind": "VirtualMachine", "name": vm.Name}},
		"status": map[string]interface{}{"latestCheckpoint": map[string]interface{}{"name": "checkpoint"}},
	}}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
	got := observedTracker(context.Background(), client, "vesta", vm)
	if got["state"] != "observed" || len(got) != 3 || len(got["uid_sha256"]) != 64 || len(got["checkpoint_sha256"]) != 64 {
		t.Fatal("unexpected tracker evidence", got)
	}
	action := client.Actions()[0].(ktesting.GetAction)
	if action.GetName() != name || action.GetNamespace() != vm.Namespace || action.GetVerb() != "get" {
		t.Fatal("tracker lookup exceeded VM scope")
	}
	if got := observedTracker(context.Background(), client, "vnbui", vm); got["state"] != "absent" {
		t.Fatal("adopted a different installation's tracker", got)
	}
	obj.SetAnnotations(map[string]string{"vnbui.insitu/vm-uid": "replaced"})
	client = fake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
	if got := observedTracker(context.Background(), client, "vesta", vm); got["state"] != "source_mismatch" {
		t.Fatal("adopted a different VM's tracker", got)
	}
	client.PrependReactor("get", "virtualmachinebackuptrackers", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("denied") })
	if got := observedTracker(context.Background(), client, "vesta", vm); got["state"] != "unknown" {
		t.Fatal("failed read classified as absence", got)
	}
}

func TestInventoryInstanceNeedsExactControllerAndUniqueBinding(t *testing.T) {
	vm := inventoryVM("test", "vm-id")
	raw := vm.DeepCopy()
	raw.SetKind("VirtualMachineInstance")
	raw.SetUID("vmi-id")
	yes := true
	owner := metav1.OwnerReference{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachine", Name: vm.GetName(), UID: vm.GetUID(), Controller: &yes}
	raw.SetOwnerReferences([]metav1.OwnerReference{owner})
	if got, ambiguous := inventoryInstance(vm, []unstructured.Unstructured{*raw}); got == nil || ambiguous {
		t.Fatal("lost a verified current VMI")
	}
	if got, ambiguous := inventoryInstance(vm, nil); got != nil || ambiguous {
		t.Fatal("absent instance is indeterminate")
	}
	for _, change := range []func(*unstructured.Unstructured){
		func(v *unstructured.Unstructured) { v.SetName("different") },
		func(v *unstructured.Unstructured) {
			bad := owner
			bad.Controller = nil
			v.SetOwnerReferences([]metav1.OwnerReference{bad})
		},
		func(v *unstructured.Unstructured) {
			bad := owner
			bad.Name = "old"
			v.SetOwnerReferences([]metav1.OwnerReference{bad})
		},
		func(v *unstructured.Unstructured) {
			bad := owner
			bad.APIVersion = "other/v1"
			v.SetOwnerReferences([]metav1.OwnerReference{bad})
		},
	} {
		copy := raw.DeepCopy()
		change(copy)
		if got, ambiguous := inventoryInstance(vm, []unstructured.Unstructured{*copy}); got != nil || !ambiguous {
			t.Fatal("adopted a mismatched instance")
		}
	}
	if got, ambiguous := inventoryInstance(vm, []unstructured.Unstructured{*raw, *raw}); got != nil || !ambiguous {
		t.Fatal("adopted ambiguous instances")
	}
}

func TestOptionalGroupTimeoutPreservesBackupAndExportDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/backup.kubevirt.io/v1alpha1":
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"backup.kubevirt.io/v1alpha1","resources":[{"name":"virtualmachinebackups"},{"name":"virtualmachinebackuptrackers"}]}`))
		case "/apis/export.kubevirt.io/v1beta1":
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"APIResourceList","groupVersion":"export.kubevirt.io/v1beta1","resources":[{"name":"virtualmachineexports"}]}`))
		case "/apis/groupsnapshot.storage.k8s.io":
			cancel()
			<-r.Context().Done()
		default:
			t.Errorf("unexpected discovery path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	disk := map[string]interface{}{"source_type": "dataVolume"}
	vms := []models.VMInfo{{Metadata: map[string]interface{}{}, Disks: []map[string]interface{}{disk, disk}}}
	(&Provider{k8s: client}).describeBackupAPIs(ctx, vms)
	got := vms[0].Metadata["backup_apis"].(map[string]string)
	if got["virtualmachinebackups"] != "served" || got["virtualmachineexports"] != "served" || got["group_snapshot"] != "unknown" {
		t.Fatal("optional read discarded required evidence", got)
	}
}
