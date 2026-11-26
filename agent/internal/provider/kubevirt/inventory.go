//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"vnbui/agent/internal/models"
)

// Only a complete list may be advertised as an authoritative inventory snapshot.
func listInventory(ctx context.Context, resource dynamic.ResourceInterface) (*unstructured.UnstructuredList, error) {
	result := &unstructured.UnstructuredList{}
	options := metav1.ListOptions{Limit: 500}
	for {
		page, err := resource.List(ctx, options)
		if err != nil {
			return nil, err
		}
		result.Items = append(result.Items, page.Items...)
		if page.GetContinue() == "" {
			return result, nil
		}
		if options.Continue == page.GetContinue() {
			return nil, fmt.Errorf("inventory pagination did not advance")
		}
		options.Continue = page.GetContinue()
	}
}

// Resolve persistent storage from the observed VM/VMI specification, not names
// reconstructed by the backend. A failed PVC read invalidates the whole snapshot.
func (p *Provider) attachPersistentSources(ctx context.Context, vm, instance *unstructured.Unstructured, info *models.VMInfo) error {
	source := vm
	path := []string{"spec", "template", "spec", "volumes"}
	if instance != nil {
		source = instance
		path = []string{"spec", "volumes"}
	}
	// A VM's status can describe the previous instance during restart. When
	// a VMI exists, only that instance's CBT status describes the live disks.
	cbtState, cbtFound, err := unstructured.NestedString(source.Object, "status", "changedBlockTracking", "state")
	if err != nil {
		return fmt.Errorf("invalid VM/VMI ChangedBlockTracking status: %w", err)
	}
	var rawState interface{}
	if cbtFound {
		rawState = cbtState
	}
	cbtSource := "vm"
	if instance != nil {
		cbtSource = "vmi"
	}
	info.Metadata["changed_block_tracking"] = map[string]interface{}{"state": rawState, "source": cbtSource}
	volumes, _, err := unstructured.NestedSlice(source.Object, path...)
	if err != nil {
		return fmt.Errorf("invalid VM volumes: %w", err)
	}
	byName := map[string]map[string]interface{}{}
	for _, raw := range volumes {
		volume, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid VM volume")
		}
		name, _, err := unstructured.NestedString(volume, "name")
		if err != nil || name == "" {
			return fmt.Errorf("invalid VM volume name")
		}
		if _, exists := byName[name]; exists {
			return fmt.Errorf("duplicate VM volume %s", name)
		}
		byName[name] = volume
	}
	// This optional VM-controller report describes individual template volumes.
	// Keep it out of the disk identity used for scheduler grants and backup plans.
	info.Metadata["volume_snapshot_statuses"] = volumeSnapshotStatuses(vm, byName)
	for _, disk := range info.Disks {
		name, _ := disk["target"].(string)
		volume, exists := byName[name]
		if !exists {
			return fmt.Errorf("disk %s has no volume", name)
		}
		disk["backup_eligible"] = false
		claim, pvcFound, err := unstructured.NestedString(volume, "persistentVolumeClaim", "claimName")
		if err != nil {
			return fmt.Errorf("invalid PVC source for %s: %w", name, err)
		}
		dataVolume, dvFound, err := unstructured.NestedString(volume, "dataVolume", "name")
		if err != nil || (pvcFound && dvFound) {
			return fmt.Errorf("invalid or ambiguous persistent source for %s", name)
		}
		if dvFound {
			claim = dataVolume // CDI creates the backing PVC under the DataVolume name.
		}
		if !pvcFound && !dvFound {
			// Other sources are visible but cannot supply PVC ownership evidence.
			disk["source_type"] = "unsupported"
			continue
		}
		if claim == "" || p.k8s == nil {
			return fmt.Errorf("PVC source for %s cannot be resolved", name)
		}
		pvc, err := p.k8s.CoreV1().PersistentVolumeClaims(vm.GetNamespace()).Get(ctx, claim, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read PVC %s/%s: %w", vm.GetNamespace(), claim, err)
		}
		if pvc.UID == "" || pvc.DeletionTimestamp != nil {
			return fmt.Errorf("PVC %s has no usable identity", claim)
		}
		if dvFound {
			disk["source_type"] = "dataVolume"
		} else {
			disk["source_type"] = "persistentVolumeClaim"
		}
		disk["pvc_name"] = claim
		disk["pvc_namespace"], disk["pvc_uid"] = vm.GetNamespace(), string(pvc.UID)
		disk["pvc_resource_version"] = pvc.ResourceVersion
		capacity := pvc.Status.Capacity[corev1.ResourceStorage]
		bytes, exact := capacity.AsInt64()
		if pvc.Status.Phase != corev1.ClaimBound || !exact || bytes <= 0 {
			disk["source_error"] = "PVC is not bound with a positive measured capacity"
			continue
		}
		disk["capacity_bytes"] = bytes
		disk["capacity_source"] = "pvc.status.capacity.storage"
		if cbtState != "Enabled" {
			disk["source_error"] = "KubeVirt ChangedBlockTracking is not Enabled"
			continue
		}
		disk["backup_eligible"] = disk["device"] == "disk"
	}
	return nil
}

func volumeSnapshotStatuses(vm *unstructured.Unstructured, observed map[string]map[string]interface{}) map[string]bool {
	result := map[string]bool{}
	statuses, _, err := unstructured.NestedSlice(vm.Object, "status", "volumeSnapshotStatuses")
	if err != nil || len(statuses) > 256 {
		return result
	}
	template, _, _ := unstructured.NestedSlice(vm.Object, "spec", "template", "spec", "volumes")
	matching := map[string]bool{}
	for _, raw := range template {
		volume, _ := raw.(map[string]interface{})
		name, _ := volume["name"].(string)
		if _, duplicate := matching[name]; duplicate {
			matching[name] = false
		} else {
			matching[name] = name != "" && reflect.DeepEqual(volume, observed[name])
		}
	}
	seen := map[string]bool{}
	for _, raw := range statuses {
		status, _ := raw.(map[string]interface{})
		name, _ := status["name"].(string)
		enabled, valid := status["enabled"].(bool)
		if seen[name] {
			delete(result, name)
		} else if valid && matching[name] {
			result[name] = enabled
		}
		seen[name] = true
	}
	return result
}

// Stable identity comes only from the VirtualMachine, never from its instance.
func inventoryInstance(vm *unstructured.Unstructured, instances []unstructured.Unstructured) (*unstructured.Unstructured, bool) {
	var match *unstructured.Unstructured
	for i := range instances {
		vmi := &instances[i]
		if vmi.GetNamespace() != vm.GetNamespace() {
			continue
		}
		controllers, refers, owned := 0, false, false
		for _, owner := range vmi.GetOwnerReferences() {
			refers = refers || (owner.Kind == "VirtualMachine" && owner.UID == vm.GetUID())
			if owner.Controller != nil && *owner.Controller {
				controllers++
				owned = owner.APIVersion == "kubevirt.io/v1" && owner.Kind == "VirtualMachine" &&
					owner.Name == vm.GetName() && owner.UID == vm.GetUID()
			}
		}
		if vmi.GetName() != vm.GetName() && !refers {
			continue
		}
		if match != nil || !owned || controllers != 1 || vmi.GetKind() != "VirtualMachineInstance" ||
			vmi.GetAPIVersion() != "kubevirt.io/v1" || vmi.GetName() != vm.GetName() || vmi.GetUID() == "" || vmi.GetDeletionTimestamp() != nil {
			return nil, true
		}
		match = vmi
	}
	return match, false
}

func vmToInfo(vm, instance *unstructured.Unstructured) (*models.VMInfo, error) {
	if vm.GetUID() == "" || vm.GetNamespace() == "" || vm.GetName() == "" {
		return nil, fmt.Errorf("VM inventory has incomplete identity")
	}
	template, found, err := unstructured.NestedMap(vm.Object, "spec", "template", "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("VM %s/%s has no valid template", vm.GetNamespace(), vm.GetName())
	}
	source := &unstructured.Unstructured{Object: map[string]interface{}{"spec": template}}
	if instance != nil {
		source = instance
	}
	info, err := unstructuredToVMInfo(source)
	if err != nil {
		return nil, err
	}
	info.Name, info.UUID, info.VMUID = vm.GetName(), string(vm.GetUID()), string(vm.GetUID())
	info.Provider, info.Namespace = "kubevirt", vm.GetNamespace()
	info.Metadata["namespace"] = vm.GetNamespace()
	memorySource := "vmi"
	_, unresolvedType, _ := unstructured.NestedMap(vm.Object, "spec", "instancetype")
	if instance == nil {
		memorySource = "vm.spec.template"
	}
	memoryKB, sourcePath := observedMemory(source, memorySource, unresolvedType)
	info.MemoryKB = memoryKB
	info.Metadata["memory"] = map[string]interface{}{"source": sourcePath, "known": info.MemoryKB > 0}
	if instance == nil {
		info.State = "stopped"
	} else {
		info.VMIUID = string(instance.GetUID())
		info.Metadata["backup_instance_readiness"] = instanceReadiness(instance)
	}
	return info, nil
}

// Project the readiness facts used by scratch admission without interpreting
// other conditions or returning controller diagnostics to inventory readers.
func instanceReadiness(vmi *unstructured.Unstructured) string {
	conditions, found, err := unstructured.NestedSlice(vmi.Object, "status", "conditions")
	if err != nil || !found || len(conditions) > 256 {
		return "unknown"
	}
	ready := "unknown"
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			return "unknown"
		}
		if c["type"] == "Paused" && c["status"] == "True" {
			if c["reason"] == "PausedIOError" {
				return "io_paused"
			}
			return "paused"
		}
		if c["type"] == "Ready" {
			if c["status"] == "False" {
				ready = "not_ready"
			} else if c["status"] == "True" {
				ready = "ready"
			}
		}
	}
	node, _, _ := unstructured.NestedString(vmi.Object, "status", "nodeName")
	if ready == "ready" && (node == "" || vmi.GetDeletionTimestamp() != nil) {
		return "not_ready"
	}
	return ready
}

// A selected but malformed guest value is unknown, never a scheduling request.
// Instance-type specifications need expansion by KubeVirt before a guest value
// can be observed; their request does not establish guest RAM.
func observedMemory(obj *unstructured.Unstructured, source string, unresolvedType bool) (int64, interface{}) {
	paths := [][]string{{"status", "memory", "guestCurrent"}, {"spec", "domain", "memory", "guest"}, {"spec", "domain", "resources", "requests", "memory"}}
	if source != "vmi" {
		paths = paths[1:]
	}
	for i, path := range paths {
		if unresolvedType && i == len(paths)-1 {
			return 0, nil
		}
		value, found, err := unstructured.NestedString(obj.Object, path...)
		if err != nil {
			return 0, source + "." + strings.Join(path, ".")
		}
		if found {
			return parseMemoryToKB(value), source + "." + strings.Join(path, ".")
		}
	}
	return 0, nil
}
