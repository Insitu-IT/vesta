//go:build kubevirt

package kubevirt

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

// utilityProjection accepts the pinned controller's one embedded Backup PVC
// attachment, not an independently owned resource. Missing readOnly and false
// have the same API meaning. Unknown fields and additional utilities refuse.
func utilityProjection(vmi *unstructured.Unstructured, trackerUID, backupUID, scratchUID string) (storageupload.BorrowedUtility, bool) {
	var u storageupload.BorrowedUtility
	items, found, err := unstructured.NestedSlice(vmi.Object, "spec", "utilityVolumes")
	if err != nil || !found || len(items) != 1 {
		return u, false
	}
	m, ok := items[0].(map[string]interface{})
	if !ok || len(m) < 3 || len(m) > 4 {
		return u, false
	}
	for k := range m {
		if k != "name" && k != "claimName" && k != "type" && k != "readOnly" {
			return u, false
		}
	}
	name, n := m["name"].(string)
	claim, c := m["claimName"].(string)
	kind, k := m["type"].(string)
	if !n || !c || !k || name == "" || claim == "" || kind != "Backup" {
		return u, false
	}
	if ro, present := m["readOnly"]; present {
		b, ok := ro.(bool)
		if !ok || b {
			return u, false
		}
	}
	u = storageupload.BorrowedUtility{VMIUID: string(vmi.GetUID()), TrackerUID: trackerUID, BackupUID: backupUID, ScratchUID: scratchUID, Name: name, ClaimName: claim, Type: kind}
	start, _, _ := unstructured.NestedString(vmi.Object, "status", "changedBlockTracking", "backupStatus", "startTimestamp")
	stamp, err := time.Parse(time.RFC3339Nano, start)
	if err != nil || stamp.IsZero() {
		return u, false
	}
	u.StartedAt = stamp.UTC().Format(time.RFC3339Nano)
	return u, true
}

// admitNativeBoundary is read-only toward Kubernetes. The sole local mutation
// is fsync of a first observed borrowed projection, before another native call.
// Callers must retain the journal's exclusive custody for the entire boundary.
func (e *Executor) admitNativeBoundary(ctx context.Context, j *storageupload.Journal) error {
	s, err := j.Snapshot()
	if err != nil {
		return storageupload.ErrHeld
	}
	return e.admitNativeSnapshot(ctx, &s, j.BindUtility)
}

// UploadAll owns the journal mutex. Stream admission therefore uses an
// immutable, already-bound snapshot, never re-enters Snapshot/BindUtility.
func (e *Executor) admitNativeSnapshot(ctx context.Context, s *storageupload.State, bind func(storageupload.BorrowedUtility) error) error {
	if !e.namingMatches(s) {
		return storageupload.ErrHeld
	}
	r, n := &s.Request, s.Native
	if n == nil {
		return e.verifyTransactionSource(ctx, r)
	}
	if n.Lifetime != nil && !beforePinnedNativeDeadline(n) {
		return storageupload.ErrHeld
	}
	ns := r.Plan.Source.Namespace
	var backup *unstructured.Unstructured
	for i, o := range n.Objects {
		// A Secret GET also reads token data. Do not access it before source
		// and borrowed-attachment admission. Preparation checks its exact UID
		// separately after this boundary; the future export reader must too.
		if o.Role == "export_token" {
			continue
		}
		if o.Phase == "planned" {
			continue
		}
		if o.Phase != "observed" {
			return storageupload.ErrHeld
		}
		obj, err := e.dynamic.Resource(nativeResource(o.Role)).Namespace(ns).Get(ctx, o.Name, metav1.GetOptions{})
		if err != nil {
			return observationFault("native_"+o.Role, err)
		}
		if string(obj.GetUID()) != o.UID || !validNativeObject(obj, r, n, i, o.Created) {
			return storageupload.ErrHeld
		}
		if i == 1 {
			if !beforeNativeTTL(obj, n) {
				return storageupload.ErrHeld
			}
			backup = obj
		}
	}
	pvc, err := e.dynamic.Resource(pvcResource).Namespace(ns).Get(ctx, n.ScratchName, metav1.GetOptions{})
	if err != nil {
		return observationFault("native_scratch", err)
	}
	if string(pvc.GetUID()) != n.ScratchUID || pvc.GetDeletionTimestamp() != nil {
		return storageupload.ErrHeld
	}
	phase, _, _ := unstructured.NestedString(pvc.Object, "status", "phase")
	if phase != "Bound" {
		return storageupload.ErrHeld
	}
	if r.Plan.Source.VMIUID == nil {
		return e.verifyTransactionSource(ctx, r)
	}
	vmi, err := e.dynamic.Resource(kvtypes.VMIResource).Namespace(ns).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		return observationFault("native_vmi", err)
	}
	if string(vmi.GetUID()) != *r.Plan.Source.VMIUID || vmi.GetDeletionTimestamp() != nil {
		return storageupload.ErrHeld
	}
	items, _, err := unstructured.NestedSlice(vmi.Object, "spec", "utilityVolumes")
	if err != nil {
		return storageupload.ErrHeld
	}
	if len(items) == 0 {
		if s.Utility != nil {
			return storageupload.ErrHeld
		}
		return e.verifyTransactionSourceInstance(ctx, r, nil, vmi)
	}
	if backup == nil || !admittedUtilityStatus(vmi, backup, r.Plan.BackupType) {
		return storageupload.ErrHeld
	}
	u, ok := utilityProjection(vmi, n.Objects[0].UID, n.Objects[1].UID, n.ScratchUID)
	u.BackupType = r.Plan.BackupType
	// Transaction VMB names are bounded UUID names, so the pinned controller's
	// backup-target-pvc suffix fits its DNS label limit without truncation.
	// This name is only a consistency check; UID/status/source bindings above
	// are mandatory and cannot be replaced by this spelling.
	if !ok || u.ClaimName != n.ScratchName || u.Name != n.Objects[1].Name+"-backup-target-pvc" {
		return storageupload.ErrHeld
	}
	if s.Utility != nil && *s.Utility != u {
		return storageupload.ErrHeld
	}
	if err := e.verifyTransactionSourceInstance(ctx, r, &u, vmi); err != nil {
		return err
	}
	if s.Utility == nil {
		if bind == nil {
			return storageupload.ErrHeld
		}
		return bind(u)
	}
	return nil
}

func admittedUtilityStatus(vmi, backup *unstructured.Unstructured, backupType string) bool {
	name, _, _ := unstructured.NestedString(vmi.Object, "status", "changedBlockTracking", "backupStatus", "backupName")
	start, _, _ := unstructured.NestedString(vmi.Object, "status", "changedBlockTracking", "backupStatus", "startTimestamp")
	stamp, err := time.Parse(time.RFC3339Nano, start)
	created := backup.GetCreationTimestamp()
	if name != backup.GetName() || err != nil || created.IsZero() || !stamp.Equal(created.Time) {
		return false
	}
	for _, flag := range []string{"completed", "failed", "aborted"} {
		b, _, err := unstructured.NestedBool(vmi.Object, "status", "changedBlockTracking", "backupStatus", flag)
		if err != nil || b {
			return false
		}
	}
	typ, _, _ := unstructured.NestedString(backup.Object, "status", "type")
	// The transaction wire uses lowercase types; the native BackupType enum
	// is exactly Full/Incremental. Do not accept arbitrary
	// casing or normalize a malformed controller value into authority.
	expected := map[string]string{"full": "Full", "incremental": "Incremental"}[backupType]
	if expected == "" || typ != expected {
		return false
	}
	conditions, found, err := unstructured.NestedSlice(backup.Object, "status", "conditions")
	if err != nil || !found || len(conditions) > 16 {
		return false
	}
	seen, progressing := map[string]bool{}, false
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		t, ok := c["type"].(string)
		if !ok || seen[t] {
			return false
		}
		seen[t] = true
		s, ok := c["status"].(string)
		if !ok {
			return false
		}
		switch t {
		case "Progressing":
			progressing = s == "True"
		case "Done", "Aborting", "Deleting":
			if s != "False" {
				return false
			}
		case "Initializing", "ExportInitiated", "ExportReady":
			// KubeVirt 1.8 reports phases as condition types, with
			// descriptive (not enum) reasons.
		default:
			return false
		}
	}
	return progressing
}
