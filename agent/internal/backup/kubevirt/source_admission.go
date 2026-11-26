//go:build kubevirt

package kubevirt

import (
	"context"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

var pvcResource = schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}

// verifyTransactionSource is read-only. Call at each native/export/finalize
// boundary, never as a substitute for UID preconditions on native mutations.
// Admission deliberately requires both the VM template and running instance to
// retain the committed mapping; a same-name replacement cannot supply evidence.
func (e *Executor) verifyTransactionSource(ctx context.Context, r *models.StorageTransactionRequest) error {
	return e.verifyTransactionSourceBound(ctx, r, nil)
}

func (e *Executor) verifyTransactionSourceBound(ctx context.Context, r *models.StorageTransactionRequest, utility *storageupload.BorrowedUtility) error {
	return e.verifyTransactionSourceInstance(ctx, r, utility, nil)
}

func (e *Executor) verifyTransactionSourceInstance(ctx context.Context, r *models.StorageTransactionRequest, utility *storageupload.BorrowedUtility, instance *unstructured.Unstructured) error {
	checkpoint := ""
	if r.Plan.Parent != nil {
		checkpoint = r.Plan.Parent.Checkpoint
	}
	return e.verifyTransactionSourceObservation(ctx, r, utility, checkpoint, instance)
}

// Only the finalize observer supplies the expected new checkpoint, after its
// original tracker/accepted-receipt/intent checks. The committed plan is intact.
func (e *Executor) verifyTransactionSourceCheckpoint(ctx context.Context, r *models.StorageTransactionRequest, utility *storageupload.BorrowedUtility, expectedCheckpoint string) error {
	return e.verifyTransactionSourceObservation(ctx, r, utility, expectedCheckpoint, nil)
}

// A supplied instance is the fresh VMI observation from this admission boundary.
// Comparing its utility projection with a second VMI read can misclassify the
// controller's ordinary attachment transition as permanent source drift. Never
// reuse this observation across boundaries or as native mutation authority.
func (e *Executor) verifyTransactionSourceObservation(ctx context.Context, r *models.StorageTransactionRequest, utility *storageupload.BorrowedUtility, expectedCheckpoint string, instance *unstructured.Unstructured) error {
	s := r.Plan.Source
	if r.Plan.Provider != "kubevirt" || ((e.cfg == nil || e.cfg.NamespaceScope == nil) && e.namespace != "" && e.namespace != s.Namespace) {
		return fault("admission", "source_scope_refused", "refused")
	}
	vm, err := e.dynamic.Resource(kvtypes.VMResource).Namespace(s.Namespace).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		return observationFault("source_vm", err)
	}
	if string(vm.GetUID()) != s.VMUID || vm.GetDeletionTimestamp() != nil {
		return fault("admission", "source_vm_identity_changed", "refused")
	}
	spec, found, err := unstructured.NestedMap(vm.Object, "spec", "template", "spec")
	if err != nil || !found || !matchesSourceSpec(spec, r) {
		return fault("admission", "source_template_mapping_changed", "refused")
	}
	templateSpec := spec
	vmi := instance
	if vmi == nil {
		vmi, err = e.dynamic.Resource(kvtypes.VMIResource).Namespace(s.Namespace).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	}
	cbtSource := vm
	if s.VMIUID == nil {
		if !apierrors.IsNotFound(err) {
			if err != nil {
				return observationFault("source_vmi", err)
			}
			return fault("admission", "source_vmi_identity_changed", "refused")
		}
	} else {
		if err != nil {
			return observationFault("source_vmi", err)
		}
		if vmi.GetNamespace() != s.Namespace || vmi.GetName() != r.Plan.VMName || string(vmi.GetUID()) != *s.VMIUID || vmi.GetDeletionTimestamp() != nil {
			return fault("admission", "source_vmi_identity_changed", "refused")
		}
		cbtSource = vmi
		owned := false
		for _, owner := range vmi.GetOwnerReferences() {
			if owner.Controller != nil && *owner.Controller && owner.Kind == "VirtualMachine" && string(owner.UID) == s.VMUID && owner.Name == r.Plan.VMName {
				owned = true
			}
		}
		spec, found, err = unstructured.NestedMap(vmi.Object, "spec")
		if utility != nil {
			projection, valid := utilityProjection(vmi, utility.TrackerUID, utility.BackupUID, utility.ScratchUID)
			projection.BackupType = r.Plan.BackupType
			if !valid || projection != *utility {
				return fault("admission", "source_utility_mapping_changed", "refused")
			}
			// Only this exact, independently admitted borrowed projection is
			// removed from the ordinary source comparison. All other utilities
			// (including duplicates) still fail closed.
			delete(spec, "utilityVolumes")
		}
		if !owned || err != nil || !found || !matchesSourceSpec(spec, r) || !sameProtectedSourceKinds(templateSpec, spec, r) {
			return fault("admission", "source_instance_mapping_changed", "refused")
		}
	}
	// Inventory is only an observation, not an execution-time permission.
	// Recheck the exact current source at every transaction boundary so stale
	// Enabled status cannot authorize an initializing/reconfigured instance.
	cbtState, _, err := unstructured.NestedString(cbtSource.Object, "status", "changedBlockTracking", "state")
	if err != nil || cbtState != "Enabled" {
		return fault("admission", "source_cbt_not_enabled", "refused")
	}
	for _, volume := range s.NativeDisks() {
		pvc, err := e.dynamic.Resource(pvcResource).Namespace(s.Namespace).Get(ctx, volume.PVCName, metav1.GetOptions{})
		if err != nil {
			return observationFault("source_volume", err)
		}
		if string(pvc.GetUID()) != volume.PVCUID || pvc.GetResourceVersion() != volume.PVCResourceVersion || pvc.GetDeletionTimestamp() != nil {
			return fault("admission", "source_volume_identity_changed", "refused")
		}
		phase, _, _ := unstructured.NestedString(pvc.Object, "status", "phase")
		capacity, _, _ := unstructured.NestedString(pvc.Object, "status", "capacity", "storage")
		quantity, err := resource.ParseQuantity(capacity)
		if err != nil || phase != "Bound" {
			return fault("admission", "source_volume_not_bound", "refused")
		}
		count, exact := quantity.AsInt64()
		if !exact || count != volume.CapacityBytes {
			return fault("admission", "source_volume_capacity_changed", "refused")
		}
	}
	if parent := r.Plan.Parent; parent != nil {
		tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(s.Namespace).Get(ctx, e.trackerName(s.Namespace+"/"+s.VMUID), metav1.GetOptions{})
		if err != nil {
			return observationFault("parent_tracker", err)
		}
		if string(tracker.GetUID()) != parent.TrackerUID || tracker.GetDeletionTimestamp() != nil || tracker.GetAnnotations()["vnbui.insitu/vm-uid"] != s.VMUID {
			return fault("admission", "parent_tracker_identity_changed", "refused")
		}
		source, _, _ := unstructured.NestedString(tracker.Object, "spec", "source", "name")
		checkpoint, _, _ := unstructured.NestedString(tracker.Object, "status", "latestCheckpoint", "name")
		if source != r.Plan.VMName || checkpoint != expectedCheckpoint {
			return fault("admission", "parent_checkpoint_changed", "refused")
		}
	}
	return nil
}

func namedSourceEntries(spec map[string]interface{}, path ...string) (map[string]map[string]interface{}, bool) {
	entries, found, err := unstructured.NestedSlice(spec, path...)
	if err != nil || !found || len(entries) > 512 {
		return nil, false
	}
	result := map[string]map[string]interface{}{}
	for _, entry := range entries {
		item, ok := entry.(map[string]interface{})
		if !ok {
			return nil, false
		}
		name, _, err := unstructured.NestedString(item, "name")
		if err != nil || name == "" || result[name] != nil {
			return nil, false
		}
		result[name] = item
	}
	return result, true
}

func sameProtectedSourceKinds(template, instance map[string]interface{}, r *models.StorageTransactionRequest) bool {
	templateVolumes, ok := namedSourceEntries(template, "volumes")
	if !ok {
		return false
	}
	instanceVolumes, ok := namedSourceEntries(instance, "volumes")
	if !ok {
		return false
	}
	for _, volume := range r.Plan.Source.NativeDisks() {
		if (templateVolumes[volume.Name]["dataVolume"] != nil) != (instanceVolumes[volume.Name]["dataVolume"] != nil) {
			return false
		}
	}
	return true
}

func matchesSourceSpec(spec map[string]interface{}, r *models.StorageTransactionRequest) bool {
	// Utility attachments are a separate VMI field, not ordinary source disks.
	// Until an explicit read-only borrowed-attachment binding is admitted and
	// journaled, neither a matching scratch name nor Type=Backup proves custody.
	// Unknown/malformed utility data must not silently bypass source admission.
	if raw, present := spec["utilityVolumes"]; present {
		utilities, ok := raw.([]interface{})
		if !ok || len(utilities) != 0 {
			return false
		}
	}
	volumes, ok := namedSourceEntries(spec, "volumes")
	if !ok {
		return false
	}
	disks, ok := namedSourceEntries(spec, "domain", "devices", "disks")
	if !ok || len(disks) != len(r.Plan.Source.Volumes)+len(r.Plan.Exclusions) || len(volumes) != len(disks) {
		return false
	}
	native := map[string]bool{}
	for _, v := range r.Plan.Source.NativeDisks() {
		native[v.Name] = true
	}
	for _, name := range r.Plan.Exclusions {
		if volumes[name] == nil || disks[name] == nil {
			return false
		}
		// Legacy snapshots omit persistent exclusions, so they cannot safely
		// admit native controller participation or scratch effects.
		persistent := volumes[name]["persistentVolumeClaim"] != nil || volumes[name]["dataVolume"] != nil
		if persistent != native[name] {
			return false
		}
	}
	for _, v := range r.Plan.Source.NativeDisks() {
		disk, volume := disks[v.Name], volumes[v.Name]
		if disk == nil || volume == nil {
			return false
		}
		// Require exactly one pinned PVC or DataVolume source, without extras.
		if len(volume) != 2 || volume["name"] != v.Name {
			return false
		}
		pvc, pvcSource := volume["persistentVolumeClaim"].(map[string]interface{})
		dv, dvSource := volume["dataVolume"].(map[string]interface{})
		if pvcSource == dvSource || (pvcSource && pvc["claimName"] != v.PVCName) || (dvSource && dv["name"] != v.PVCName) {
			return false
		}
		for _, unsupported := range []string{"lun", "cdrom"} {
			if _, exists := disk[unsupported]; exists {
				return false
			}
		}
		device, ok := disk["disk"].(map[string]interface{})
		if !ok || device["bus"] != v.Mapping.Bus || v.Mapping.Device != "disk" || v.Mapping.DiskName != v.Name {
			return false
		}
		var serial interface{}
		if v.Mapping.Serial != nil {
			serial = *v.Mapping.Serial
		}
		if !reflect.DeepEqual(disk["serial"], serial) {
			return false
		}
	}
	return true
}
