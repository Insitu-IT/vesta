//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"os"
	"path/filepath"
	"time"
	"vnbui/agent/internal/config"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

// PrepareStorageTransaction is the transaction/1 native preparation entry, not
// the legacy StartBackup/upload/compensation path. HTTP admission remains 423
// until the entire handshake is accepted. The returned journal owns the
// exclusive attempt lock; the caller must retain it through upload/finalize.
// This entry never reports completion or deletes controller-owned resources.
func (e *Executor) PrepareStorageTransaction(ctx context.Context, body []byte) (_ *storageupload.Journal, err error) {
	r, err := models.DecodeStorageTransaction(body)
	if err != nil || r.Plan.Provider != "kubevirt" || e.cfg.KubevirtPrefix() == "" || e.cfg.ValidateNativeLifetime() != nil {
		return nil, storageupload.ErrHeld
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, storageupload.ErrHeld
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	err = parent.Sync()
	_ = parent.Close()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	var j *storageupload.Journal
	_, statErr := os.Lstat(filepath.Join(root, r.ReservationID))
	if os.IsNotExist(statErr) {
		j, err = storageupload.CreateWithKubevirtPrefix(root, body, e.cfg.KubevirtPrefix())
	} else if statErr == nil {
		j, err = storageupload.Open(root, body)
	} else {
		return nil, storageupload.ErrHeld
	}
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	defer func() {
		if err != nil {
			_ = j.Close()
		}
	}()
	state, err := j.Snapshot()
	if err != nil || (state.Phase != "uploading" && state.Phase != "prepared" && state.Phase != "submitting" && state.Phase != "accepted") {
		return nil, storageupload.ErrHeld
	}
	g := safetyFrom(ctx)
	if g == nil {
		g, err = openSafety(root, r)
		if errors.Is(err, os.ErrNotExist) && state.Native == nil {
			g, err = e.createSafety(root, r)
		}
		if err != nil {
			return nil, fault("admission", "safety_record_missing_or_invalid", "refused")
		}
		ctx = context.WithValue(ctx, safetyContextKey{}, g)
	}
	if err = checkSafety(ctx); err != nil {
		return nil, err
	}
	if err = safetyProgress(ctx, "preparing", 0); err != nil {
		return nil, err
	}
	// A naming mismatch is an installation fence, not evidence of native loss.
	// Refuse before drift probes so no other-profile object is read or adopted.
	if !e.namingMatches(&state) {
		return nil, storageupload.ErrHeld
	}
	if state.Native == nil && !e.cfg.SourceNamespaceAllowed(r.Plan.Source.Namespace) {
		return nil, storageupload.ErrHeld
	}
	if err = e.admitNativeBoundary(ctx, j); err != nil {
		if state.Native == nil && e.confirmedParentDrift(ctx, r) {
			_ = j.HoldPreNativeSourceDrift()
		} else if e.confirmedNativeDrift(ctx, &state) {
			_ = j.HoldNativeDrift()
		}
		return nil, err
	}
	if state.Phase != "uploading" {
		// Receipt recovery performs no native preparation, token access or
		// upload. The transaction entry separately revalidates export facts.
		return j, nil
	}
	scratch := e.cfg.ScratchPVC(r.Plan.Source.Namespace)
	if scratch == "" {
		return nil, storageupload.ErrHeld
	}
	pvc, err := e.dynamic.Resource(pvcResource).Namespace(r.Plan.Source.Namespace).Get(ctx, scratch, metav1.GetOptions{})
	if err != nil || pvc.GetUID() == "" || pvc.GetDeletionTimestamp() != nil {
		return nil, storageupload.ErrHeld
	}
	phase, _, _ := unstructured.NestedString(pvc.Object, "status", "phase")
	if phase != "Bound" {
		return nil, storageupload.ErrHeld
	}
	for _, volume := range r.Plan.Source.NativeDisks() {
		if volume.PVCName == scratch || volume.PVCUID == string(pvc.GetUID()) {
			return nil, storageupload.ErrHeld
		}
	}
	if state.Native == nil {
		if err = e.reserveScratch(ctx, r, pvc, g); err != nil {
			return nil, err
		}
		vm, getErr := e.dynamic.Resource(kvtypes.VMResource).Namespace(r.Plan.Source.Namespace).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
		if getErr != nil || string(vm.GetUID()) != r.Plan.Source.VMUID || vm.GetResourceVersion() == "" || vm.GetDeletionTimestamp() != nil {
			return nil, storageupload.ErrHeld
		}
		spec, found, getErr := unstructured.NestedMap(vm.Object, "spec", "template", "spec")
		if getErr != nil || !found || !matchesSourceSpec(spec, r) {
			return nil, storageupload.ErrHeld
		}
		definition, marshalErr := json.Marshal(map[string]any{
			"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
			"metadata": map[string]any{"namespace": vm.GetNamespace(), "name": vm.GetName(), "uid": string(vm.GetUID()), "resourceVersion": vm.GetResourceVersion()},
			"spec":     vm.Object["spec"],
		})
		if marshalErr != nil || len(definition) > storageupload.MaxVMDefinitionBytes {
			return nil, storageupload.ErrHeld
		}
		name := e.cfg.KubevirtPrefix() + "-" + r.BackupID
		budget := g.snapshot().Progress.Budget
		ttl := max(config.MinNativeBackupTTLSeconds, int(budget.RunSeconds+budget.ClosureSeconds))
		if ttl > e.cfg.KubevirtNativeTTLSeconds {
			return nil, fault("admission", "estimated_window_exceeds_native_limit", "refused")
		}
		err = j.PrepareNative(storageupload.NativeState{ScratchName: scratch, ScratchUID: string(pvc.GetUID()), VMDefinition: string(definition),
			Lifetime: &storageupload.NativeLifetime{TTLSeconds: ttl, PreparedAt: nativeNow().UTC().Format(time.RFC3339Nano), TransactionTimeoutSeconds: min(e.cfg.KubevirtTransactionTimeoutSeconds, ttl)},
			Objects: []storageupload.NativeObject{
				{Role: "tracker", Name: e.trackerName(r.Plan.Source.Namespace + "/" + r.Plan.Source.VMUID), Phase: "planned"},
				{Role: "backup", Name: name, Phase: "planned"},
				{Role: "export_token", Name: name + "-token", Phase: "planned"},
			}})
		if err != nil {
			return nil, storageupload.ErrHeld
		}
	} else if state.Native.ScratchName != scratch || state.Native.ScratchUID != string(pvc.GetUID()) || state.Native.VMDefinition == "" {
		return nil, storageupload.ErrHeld
	}
	state, err = j.Snapshot()
	if err != nil || g.bindNative(state.Native) != nil {
		return nil, storageupload.ErrHeld
	}
	for i := 0; i < 3; i++ {
		if err = checkSafety(ctx); err != nil {
			return nil, err
		}
		if _, err = e.sourceAvailability(ctx, r); err != nil {
			return nil, err
		}
		state, err = j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
		if err = e.admitNativeBoundary(ctx, j); err != nil {
			if e.confirmedNativeDrift(ctx, &state) {
				_ = j.HoldNativeDrift()
			}
			return nil, err
		}
		// The scratch PVC is borrowed, not transaction-owned. Revalidate its UID
		// before each native mutation; no cleanup authority is conferred by use.
		current, getErr := e.dynamic.Resource(pvcResource).Namespace(r.Plan.Source.Namespace).Get(ctx, scratch, metav1.GetOptions{})
		if getErr != nil || string(current.GetUID()) != state.Native.ScratchUID || current.GetDeletionTimestamp() != nil {
			return nil, storageupload.ErrHeld
		}
		if i == 1 && state.Native.Objects[i].Phase == "planned" {
			// Scheduling and tracker preparation may have consumed the first
			// sample's lifetime. Recheck immediately before starting CBW.
			if err = e.reserveScratch(ctx, r, current, g); err != nil {
				return nil, err
			}
			if err = inspectServiceHealth(ctx, g); err != nil {
				return nil, err
			}
		}
		if err = e.prepareNativeObject(ctx, j, &state, i); err != nil {
			return nil, err
		}
		state, err = j.Snapshot()
		if err != nil || g.bindNative(state.Native) != nil {
			return nil, storageupload.ErrHeld
		}
	}
	if err = e.admitNativeBoundary(ctx, j); err != nil {
		return nil, err
	}
	return j, nil
}

func nativeResource(role string) schema.GroupVersionResource {
	switch role {
	case "tracker":
		return kvtypes.BackupTrackerResource
	case "backup":
		return kvtypes.BackupResource
	default:
		return coreV1Secret
	}
}

// A transient API error is not evidence of loss. Only an authoritative
// NotFound, replacement UID, deletion or changed observed object converts an
// unaccepted journal into a durable hold that an operator can review.
// A parent belongs to the accepted ancestor, not the current attempt's native
// object list. Recognize authoritative drift before any new resource is bound;
// an unavailable API is not evidence of drift and must remain retryable.
func (e *Executor) confirmedParentDrift(ctx context.Context, r *models.StorageTransactionRequest) bool {
	parent := r.Plan.Parent
	if parent == nil {
		return false
	}
	s := r.Plan.Source
	tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(s.Namespace).Get(ctx, e.trackerName(s.Namespace+"/"+s.VMUID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil {
		return false
	}
	source, _, _ := unstructured.NestedString(tracker.Object, "spec", "source", "name")
	checkpoint, _, _ := unstructured.NestedString(tracker.Object, "status", "latestCheckpoint", "name")
	return string(tracker.GetUID()) != parent.TrackerUID || tracker.GetDeletionTimestamp() != nil ||
		tracker.GetAnnotations()["vnbui.insitu/vm-uid"] != s.VMUID || source != r.Plan.VMName || checkpoint != parent.Checkpoint
}

func (e *Executor) confirmedNativeDrift(ctx context.Context, state *storageupload.State) bool {
	n := state.Native
	if n == nil {
		return false
	}
	r := &state.Request
	ns := r.Plan.Source.Namespace
	for i, observed := range n.Objects {
		if observed.Phase != "observed" || observed.Role == "export_token" {
			continue // Token data must not be read before source admission.
		}
		current, err := e.dynamic.Resource(nativeResource(observed.Role)).Namespace(ns).Get(ctx, observed.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}
		if err == nil && (string(current.GetUID()) != observed.UID || current.GetDeletionTimestamp() != nil || !validNativeObject(current, r, n, i, observed.Created)) {
			return true
		}
	}
	if n.Objects[0].Phase != "observed" {
		return false
	}
	pvc, err := e.dynamic.Resource(pvcResource).Namespace(ns).Get(ctx, n.ScratchName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) || (err == nil && (string(pvc.GetUID()) != n.ScratchUID || pvc.GetDeletionTimestamp() != nil)) {
		return true
	}
	if r.Plan.Source.VMIUID != nil {
		vmi, getErr := e.dynamic.Resource(kvtypes.VMIResource).Namespace(ns).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) || (getErr == nil && (string(vmi.GetUID()) != *r.Plan.Source.VMIUID || vmi.GetDeletionTimestamp() != nil)) {
			return true
		}
	}
	return false
}

func nativeOwner(r *models.StorageTransactionRequest, n *storageupload.NativeState, index int) metav1.OwnerReference {
	controller := true
	owner := metav1.OwnerReference{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachine", Name: r.Plan.VMName, UID: types.UID(r.Plan.Source.VMUID), Controller: &controller}
	if index > 0 {
		owner.APIVersion = "backup.kubevirt.io/v1alpha1"
		owner.Kind = []string{"VirtualMachineBackupTracker", "VirtualMachineBackup"}[index-1]
		owner.Name, owner.UID = n.Objects[index-1].Name, types.UID(n.Objects[index-1].UID)
	}
	return owner
}

func (e *Executor) prepareNativeObject(ctx context.Context, j *storageupload.Journal, state *storageupload.State, index int) error {
	r, n := &state.Request, state.Native
	for prior := 0; prior < index; prior++ {
		bound := n.Objects[prior]
		current, err := e.dynamic.Resource(nativeResource(bound.Role)).Namespace(r.Plan.Source.Namespace).Get(ctx, bound.Name, metav1.GetOptions{})
		if err != nil || bound.Phase != "observed" || string(current.GetUID()) != bound.UID || !validNativeObject(current, r, n, prior, bound.Created) {
			if apierrors.IsNotFound(err) || (err == nil && bound.Phase == "observed") {
				_ = j.HoldNativeDrift()
			}
			return storageupload.ErrHeld
		}
	}
	o := n.Objects[index]
	resource := e.dynamic.Resource(nativeResource(o.Role)).Namespace(r.Plan.Source.Namespace)
	existing, err := resource.Get(ctx, o.Name, metav1.GetOptions{})
	owner := nativeOwner(r, n, index)
	if o.Phase == "observed" {
		if err != nil || string(existing.GetUID()) != o.UID || existing.GetDeletionTimestamp() != nil {
			if apierrors.IsNotFound(err) || err == nil {
				_ = j.HoldNativeDrift()
			}
			return storageupload.ErrHeld
		}
		if !validNativeObject(existing, r, n, index, o.Created) {
			_ = j.HoldNativeDrift()
			return storageupload.ErrHeld
		}
		return nil
	}
	if o.Phase != "planned" {
		return storageupload.ErrHeld
	}
	if err == nil {
		// Only a source tracker can predate this attempt. Its exact UID is then
		// journaled. Neither VMB nor export-token names are adoption authority.
		if index != 0 || !validNativeObject(existing, r, n, index, false) {
			return storageupload.ErrHeld
		}
		return j.ObserveNative(o.Role, string(existing.GetUID()), string(owner.UID), false)
	}
	if !apierrors.IsNotFound(err) || (index == 0 && r.Plan.Parent != nil) {
		return storageupload.ErrHeld
	}
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(owner.APIVersion)
	obj.SetKind("VirtualMachineBackupTracker")
	obj.SetName(o.Name)
	obj.SetNamespace(r.Plan.Source.Namespace)
	obj.SetOwnerReferences([]metav1.OwnerReference{owner})
	obj.SetAnnotations(map[string]string{"vnbui.insitu/vm-uid": r.Plan.Source.VMUID, "vnbui.insitu/attempt-id": r.Plan.AttemptID, "vnbui.insitu/reservation-id": r.ReservationID, "vnbui.insitu/plan-sha256": r.PlanSHA256})
	obj.SetLabels(map[string]string{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix()})
	switch index {
	case 0:
		obj.SetAPIVersion("backup.kubevirt.io/v1alpha1")
		obj.Object["spec"] = map[string]interface{}{"source": map[string]interface{}{"apiGroup": "kubevirt.io", "kind": "VirtualMachine", "name": r.Plan.VMName}}
	case 1:
		obj.SetKind("VirtualMachineBackup")
		obj.Object["spec"] = map[string]interface{}{"source": map[string]interface{}{"apiGroup": "backup.kubevirt.io", "kind": "VirtualMachineBackupTracker", "name": n.Objects[0].Name}, "mode": "Pull", "pvcName": n.ScratchName, "tokenSecretRef": n.Objects[2].Name, "ttlDuration": n.BackupTTL().String(), "forceFullBackup": r.Plan.BackupType == "full"}
	case 2:
		obj.SetAPIVersion("v1")
		obj.SetKind("Secret")
		token := make([]byte, 32)
		if _, err = rand.Read(token); err != nil {
			return storageupload.ErrHeld
		}
		// This is only the native export token. It is never written to the
		// journal and is unrelated to backend/provider credentials or the DEK.
		obj.Object["stringData"] = map[string]interface{}{"token": base64.URLEncoding.EncodeToString(token)}
	}
	if err = j.BeginNativeCreate(o.Role, string(owner.UID)); err != nil {
		return err
	}
	if g := safetyFrom(ctx); g != nil {
		pending, err := j.Snapshot()
		if err != nil || g.bindNative(pending.Native) != nil {
			return storageupload.ErrHeld
		}
		if err := checkSafety(ctx); err != nil {
			return err
		}
	}
	created, err := resource.Create(ctx, obj, metav1.CreateOptions{})
	if err != nil || !validNativeObject(created, r, n, index, true) {
		return storageupload.ErrHeld
	}
	if index == 1 && n.Lifetime != nil {
		return j.ObserveNativeBackup(string(created.GetUID()), string(owner.UID), created.GetCreationTimestamp().Time)
	}
	return j.ObserveNative(o.Role, string(created.GetUID()), string(owner.UID), true)
}

func validNativeObject(obj *unstructured.Unstructured, r *models.StorageTransactionRequest, n *storageupload.NativeState, index int, created bool) bool {
	if obj == nil || obj.GetUID() == "" || obj.GetDeletionTimestamp() != nil || obj.GetName() != n.Objects[index].Name || obj.GetNamespace() != r.Plan.Source.Namespace {
		return false
	}
	annotations := obj.GetAnnotations()
	if annotations["vnbui.insitu/vm-uid"] != r.Plan.Source.VMUID {
		return false
	}
	if created {
		if annotations["vnbui.insitu/attempt-id"] != r.Plan.AttemptID || annotations["vnbui.insitu/reservation-id"] != r.ReservationID || annotations["vnbui.insitu/plan-sha256"] != r.PlanSHA256 {
			return false
		}
		owner := nativeOwner(r, n, index)
		refs := obj.GetOwnerReferences()
		if len(refs) != 1 || refs[0].UID != owner.UID || refs[0].Name != owner.Name || refs[0].Kind != owner.Kind || refs[0].APIVersion != owner.APIVersion || refs[0].Controller == nil || !*refs[0].Controller {
			return false
		}
	}
	if index == 0 {
		source, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "name")
		if source != r.Plan.VMName {
			return false
		}
		if p := r.Plan.Parent; p != nil {
			checkpoint, _, _ := unstructured.NestedString(obj.Object, "status", "latestCheckpoint", "name")
			if string(obj.GetUID()) != p.TrackerUID || checkpoint != p.Checkpoint {
				return false
			}
		}
	}
	if index == 1 {
		duration, err := time.ParseDuration(textAt(obj, "spec", "ttlDuration"))
		if err != nil || duration != n.BackupTTL() {
			return false
		}
		if n.Lifetime != nil && n.Lifetime.CreatedAt != "" && obj.GetCreationTimestamp().UTC().Format(time.RFC3339Nano) != n.Lifetime.CreatedAt {
			return false
		}
		source, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "name")
		scratch, _, _ := unstructured.NestedString(obj.Object, "spec", "pvcName")
		token, _, _ := unstructured.NestedString(obj.Object, "spec", "tokenSecretRef")
		mode, _, _ := unstructured.NestedString(obj.Object, "spec", "mode")
		full, found, _ := unstructured.NestedBool(obj.Object, "spec", "forceFullBackup")
		if source != n.Objects[0].Name || scratch != n.ScratchName || token != n.Objects[2].Name || mode != "Pull" || !found || full != (r.Plan.BackupType == "full") {
			return false
		}
	}
	return true
}
