//go:build kubevirt

package kubevirt

import (
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
	"testing"
)

func TestMultiNamespaceSnapshotIsCompleteOrError(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{VMResource: "VirtualMachineList", VMIResource: "VirtualMachineInstanceList"}, inventoryVM("one", "one-uid"), inventoryVM("two", "two-uid"))
	p := &Provider{connected: true, dynamic: client}
	selected := []string{"one", "two"}
	p.SetNamespaceScope(func() []string { return selected }, selected)
	vms, namespaces, err := p.ListVMsWithNamespaces()
	if err != nil || len(vms) != 2 || len(namespaces) != 2 || vms[0].VMUID == vms[1].VMUID {
		t.Fatalf("namespace/UID identity lost: %+v %v", vms, err)
	}
	if _, err := p.GetVM("same"); err == nil {
		t.Fatal("duplicate name was not ambiguous")
	}
	client.PrependReactor("list", "virtualmachines", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "two" {
			return true, nil, fmt.Errorf("permission denied")
		}
		return false, nil, nil
	})
	vms, namespaces, err = p.ListVMsWithNamespaces()
	if err == nil || vms != nil || namespaces != nil {
		t.Fatal("failed namespace produced complete inventory")
	}
	selected = []string{}
	vms, namespaces, err = p.ListVMsWithNamespaces()
	if err != nil || len(vms) != 0 || len(namespaces) != 0 {
		t.Fatal("empty scope expanded to all namespaces")
	}
}

func TestUnconfiguredInventoryNeverListsOrWatchesCluster(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{VMResource: "VirtualMachineList", VMIResource: "VirtualMachineInstanceList"}, inventoryVM("one", "one-uid"))
	p := &Provider{connected: true, dynamic: client}
	vms, namespaces, err := p.ListVMsWithNamespaces()
	if err == nil || vms != nil || namespaces != nil {
		t.Fatal("unconfigured inventory returned a complete snapshot")
	}
	if err := p.SubscribeEvents(nil); err == nil {
		t.Fatal("unconfigured inventory opened watches")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("unconfigured inventory accessed cluster resources")
	}
	p.namespace = "one"
	vms, namespaces, err = p.ListVMsWithNamespaces()
	if err != nil || len(vms) != 1 || len(namespaces) != 1 || namespaces[0] != "one" {
		t.Fatal("explicit singleton unavailable", err)
	}
	for _, a := range client.Actions() {
		if a.GetNamespace() != "one" {
			t.Fatal("singleton inventory escaped namespace")
		}
	}
}
