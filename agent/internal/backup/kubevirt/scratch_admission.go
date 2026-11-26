//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

var scratchLeases = schema.GroupVersionResource{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}

// Availability is separate from ownership. An IOError-paused guest must not
// prevent the independent closer from addressing its original native backup.
func (e *Executor) sourceAvailability(ctx context.Context, r *models.StorageTransactionRequest) (string, error) {
	if r.Plan.Source.VMIUID == nil {
		return "", fault("admission", "source_not_running", "refused")
	}
	vmi, err := e.dynamic.Resource(kvtypes.VMIResource).Namespace(r.Plan.Source.Namespace).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		return "", safetyReadFault(err, "admission", "source_status_unavailable")
	}
	if string(vmi.GetUID()) != *r.Plan.Source.VMIUID || vmi.GetDeletionTimestamp() != nil {
		return "", fault("admission", "source_identity_changed", "refused")
	}
	conditions, _, _ := unstructured.NestedSlice(vmi.Object, "status", "conditions")
	ready := false
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			return "", storageupload.ErrHeld
		}
		if c["type"] == "Paused" && c["status"] == "True" {
			reason := "source_paused"
			if c["reason"] == "PausedIOError" {
				reason = "source_io_error_pause"
			}
			return "", fault("source_health", reason, "refused")
		}
		if c["type"] == "Ready" && c["status"] == "True" {
			ready = true
		}
	}
	node := textAt(vmi, "status", "nodeName")
	if textAt(vmi, "status", "phase") != "Running" || !ready || node == "" {
		return "", fault("source_health", "source_not_ready", "refused")
	}
	return node, nil
}

func scratchIdentity(obj *unstructured.Unstructured, r *models.StorageTransactionRequest) bool {
	a := obj.GetAnnotations()
	return obj.GetNamespace() == r.Plan.Source.Namespace && obj.GetUID() != "" && obj.GetDeletionTimestamp() == nil &&
		a["vnbui.insitu/reservation-id"] == r.ReservationID && a["vnbui.insitu/plan-sha256"] == r.PlanSHA256
}

func scratchAnnotations(r *models.StorageTransactionRequest) map[string]string {
	return map[string]string{"vnbui.insitu/reservation-id": r.ReservationID, "vnbui.insitu/plan-sha256": r.PlanSHA256}
}

// A claim is exclusively reserved rather than optimistically dividing a free
// sample between jobs. Lease time does not expire authority: an uncertain holder
// is never replaced merely because its agent went away.
func (e *Executor) reserveScratch(ctx context.Context, r *models.StorageTransactionRequest, pvc *unstructured.Unstructured, g *operationSafety) error {
	node, err := e.sourceAvailability(ctx, r)
	if err != nil {
		return err
	}
	if textAt(pvc, "spec", "volumeMode") != "" && textAt(pvc, "spec", "volumeMode") != "Filesystem" {
		return fault("scratch", "scratch_requires_filesystem", "refused")
	}
	modes, _, _ := unstructured.NestedStringSlice(pvc.Object, "spec", "accessModes")
	compatible := false
	for _, m := range modes {
		if m == "ReadWriteOnce" || m == "ReadWriteMany" {
			compatible = true
		}
	}
	if !compatible {
		return fault("scratch", "scratch_access_mode_incompatible", "refused")
	}
	s := g.snapshot()
	if s.Scratch == nil {
		size, err := nativeBytes(r)
		if err != nil {
			return err
		}
		required, err := s.Policy.ScratchBytes(size)
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(pvc.GetUID()))
		if err = g.update(func(s *safetyState) error {
			s.Scratch = &scratchReservation{Name: pvc.GetName(), UID: string(pvc.GetUID()), Node: node, RequiredBytes: required,
				LeaseName: e.cfg.KubevirtPrefix() + "-scratch-" + hex.EncodeToString(hash[:12]), ProbeName: e.cfg.KubevirtPrefix() + "-probe-" + r.BackupID, ProbeImage: e.cfg.KubevirtRestoreImage, Intent: "planned"}
			return nil
		}); err != nil {
			return err
		}
		s = g.snapshot()
	}
	a := s.Scratch
	if a.Name != pvc.GetName() || a.UID != string(pvc.GetUID()) || a.Node != node {
		return fault("scratch", "scratch_identity_or_node_changed", "refused")
	}
	leases := e.dynamic.Resource(scratchLeases).Namespace(r.Plan.Source.Namespace)
	lease, err := leases.Get(ctx, a.LeaseName, metav1.GetOptions{})
	if a.LeaseUID == "" {
		if !apierrors.IsNotFound(err) || a.Intent != "planned" {
			return fault("scratch", "scratch_already_reserved_or_uncertain", "refused")
		}
		if g.update(func(s *safetyState) error { s.Scratch.Intent = "lease_create_intent"; return nil }) != nil {
			return storageupload.ErrHeld
		}
		obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "coordination.k8s.io/v1", "kind": "Lease", "spec": map[string]interface{}{"holderIdentity": r.ReservationID}}}
		obj.SetName(a.LeaseName)
		obj.SetNamespace(r.Plan.Source.Namespace)
		obj.SetAnnotations(scratchAnnotations(r))
		obj.SetLabels(map[string]string{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix()})
		lease, err = leases.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil || !scratchIdentity(lease, r) {
			return fault("scratch", "scratch_reservation_uncertain", "uncertain")
		}
		if g.update(func(s *safetyState) error {
			s.Scratch.LeaseUID = string(lease.GetUID())
			s.Scratch.Intent = "lease_observed"
			return nil
		}) != nil {
			return storageupload.ErrHeld
		}
		a = g.snapshot().Scratch
	} else if err != nil || string(lease.GetUID()) != a.LeaseUID || !scratchIdentity(lease, r) || textAt(lease, "spec", "holderIdentity") != r.ReservationID {
		return fault("scratch", "scratch_reservation_changed", "refused")
	}
	// Any unowned mounted/pending user is a conflict, including another agent's
	// native utility pod. Never detach it or infer that old age means it is safe.
	pods, err := e.exportCandidates(ctx, exportPodResource, r.Plan.Source.Namespace)
	if err != nil {
		return fault("scratch", "scratch_users_unavailable", "transient")
	}
	for _, pod := range pods {
		if pod.GetName() == a.ProbeName && string(pod.GetUID()) == a.ProbeUID && scratchIdentity(&pod, r) {
			continue
		}
		volumes, _, _ := unstructured.NestedSlice(pod.Object, "spec", "volumes")
		for _, raw := range volumes {
			v, ok := raw.(map[string]interface{})
			if !ok {
				return storageupload.ErrHeld
			}
			claim, _, _ := unstructured.NestedString(v, "persistentVolumeClaim", "claimName")
			if claim == a.Name {
				return fault("scratch", "scratch_in_use", "refused")
			}
		}
	}
	backups, err := e.exportCandidates(ctx, kvtypes.BackupResource, r.Plan.Source.Namespace)
	if err != nil {
		return fault("scratch", "scratch_users_unavailable", "transient")
	}
	for _, job := range backups {
		if textAt(&job, "spec", "pvcName") == a.Name {
			return fault("scratch", "scratch_in_use", "refused")
		}
	}
	if err := e.ensureScratchProbe(ctx, r, g); err != nil {
		return err
	}
	sample, err := e.readScratchSample(ctx, r, g.snapshot().Scratch)
	if err != nil {
		return err
	}
	if sample.AvailableBytes < a.RequiredBytes {
		return fault("scratch", "scratch_reserve_insufficient", "refused")
	}
	return g.update(func(s *safetyState) error { s.Scratch.Initial = &sample; s.Scratch.Latest = &sample; return nil })
}

func (e *Executor) ensureScratchProbe(ctx context.Context, r *models.StorageTransactionRequest, g *operationSafety) error {
	a := g.snapshot().Scratch
	pods := e.dynamic.Resource(exportPodResource).Namespace(r.Plan.Source.Namespace)
	pod, err := pods.Get(ctx, a.ProbeName, metav1.GetOptions{})
	if a.ProbeUID != "" {
		if err != nil || string(pod.GetUID()) != a.ProbeUID || !validScratchProbe(pod, r, a) {
			return fault("scratch", "scratch_probe_identity_changed", "refused")
		}
		return nil
	}
	if !apierrors.IsNotFound(err) || a.Intent != "lease_observed" {
		return fault("scratch", "scratch_probe_creation_uncertain", "uncertain")
	}
	if e.core == nil || !strings.Contains(a.ProbeImage, "@sha256:") {
		return fault("scratch", "scratch_probe_configuration_missing", "refused")
	}
	if g.update(func(s *safetyState) error { s.Scratch.Intent = "probe_create_intent"; return nil }) != nil {
		return storageupload.ErrHeld
	}
	pod = &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Pod", "spec": map[string]interface{}{
		"automountServiceAccountToken": false, "restartPolicy": "Never", "enableServiceLinks": false,
		"affinity":              map[string]interface{}{"nodeAffinity": map[string]interface{}{"requiredDuringSchedulingIgnoredDuringExecution": map[string]interface{}{"nodeSelectorTerms": []interface{}{map[string]interface{}{"matchFields": []interface{}{map[string]interface{}{"key": "metadata.name", "operator": "In", "values": []interface{}{a.Node}}}}}}}},
		"activeDeadlineSeconds": g.snapshot().Progress.Budget.RunSeconds + g.snapshot().Progress.Budget.ClosureSeconds,
		"securityContext":       map[string]interface{}{"runAsNonRoot": true, "seccompProfile": map[string]interface{}{"type": "RuntimeDefault"}},
		"containers": []interface{}{map[string]interface{}{"name": "probe", "image": a.ProbeImage, "command": []interface{}{"/vnbui-agent", "-scratch-probe"},
			"securityContext": map[string]interface{}{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]interface{}{"drop": []interface{}{"ALL"}}},
			"resources":       map[string]interface{}{"requests": map[string]interface{}{"cpu": "5m", "memory": "16Mi"}, "limits": map[string]interface{}{"cpu": "100m", "memory": "64Mi"}},
			"volumeMounts":    []interface{}{map[string]interface{}{"name": "scratch", "mountPath": "/scratch", "readOnly": true}}}},
		"volumes": []interface{}{map[string]interface{}{"name": "scratch", "persistentVolumeClaim": map[string]interface{}{"claimName": a.Name, "readOnly": true}}},
	}}}
	pod.SetName(a.ProbeName)
	pod.SetNamespace(r.Plan.Source.Namespace)
	pod.SetAnnotations(scratchAnnotations(r))
	pod.SetLabels(map[string]string{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix(), "vesta.insitu/role": "scratch-probe"})
	created, err := pods.Create(ctx, pod, metav1.CreateOptions{})
	if err != nil || !validScratchProbe(created, r, a) {
		return fault("scratch", "scratch_probe_creation_uncertain", "uncertain")
	}
	return g.update(func(s *safetyState) error {
		s.Scratch.ProbeUID = string(created.GetUID())
		s.Scratch.Intent = "probe_observed"
		return nil
	})
}

func (e *Executor) readScratchSample(ctx context.Context, r *models.StorageTransactionRequest, a *scratchReservation) (operationbudget.ScratchSample, error) {
	var out operationbudget.ScratchSample
	failed := func(reason, disposition string) (operationbudget.ScratchSample, error) {
		return out, fault("scratch", reason, disposition)
	}
	if e.core == nil || a == nil || a.ProbeUID == "" {
		return failed("scratch_measurement_unavailable", "refused")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pods := e.dynamic.Resource(exportPodResource).Namespace(r.Plan.Source.Namespace)
	pod, err := pods.Get(ctx, a.ProbeName, metav1.GetOptions{})
	if err != nil {
		return out, safetyReadFault(err, "scratch", "scratch_probe_observation_unavailable")
	}
	if string(pod.GetUID()) != a.ProbeUID || !validScratchProbe(pod, r, a) {
		return failed("scratch_probe_identity_changed", "refused")
	}
	if textAt(pod, "status", "phase") != "Running" {
		return failed("scratch_probe_not_running", "transient")
	}
	if textAt(pod, "spec", "nodeName") != a.Node {
		return failed("scratch_probe_node_mismatch", "refused")
	}
	limit, tail := int64(2048), int64(1)
	body, err := e.core.CoreV1().Pods(r.Plan.Source.Namespace).GetLogs(a.ProbeName, &corev1.PodLogOptions{Container: "probe", TailLines: &tail, LimitBytes: &limit}).Stream(ctx)
	if err != nil {
		return failed("scratch_measurement_unavailable", "transient")
	}
	data, readErr := io.ReadAll(io.LimitReader(body, limit+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil {
		return failed("scratch_measurement_unavailable", "transient")
	}
	if int64(len(data)) > limit || decodeSafety(data, &out, int(limit)) != nil {
		return failed("scratch_measurement_invalid", "refused")
	}
	pod, err = pods.Get(ctx, a.ProbeName, metav1.GetOptions{})
	if err != nil {
		return out, safetyReadFault(err, "scratch", "scratch_probe_observation_unavailable")
	}
	if string(pod.GetUID()) != a.ProbeUID || !validScratchProbe(pod, r, a) {
		return failed("scratch_probe_identity_changed", "refused")
	}
	if out.CapacityBytes <= 0 || out.AvailableBytes < 0 || out.AvailableBytes > out.CapacityBytes || out.At.IsZero() || out.At.After(nativeNow().Add(time.Second)) || nativeNow().Sub(out.At) > 20*time.Second {
		return failed("scratch_measurement_stale_or_invalid", "refused")
	}
	return out, nil
}

func updateScratchGrowth(s *safetyState, next operationbudget.ScratchSample) error {
	a := s.Scratch
	if a == nil || a.Initial == nil {
		return storageupload.ErrHeld
	}
	if before := a.Latest; before != nil {
		older, newer := *before, next
		if next.At.Before(before.At) {
			older, newer = next, *before
		}
		seconds := newer.At.Sub(older.At).Seconds()
		if seconds > 0 && newer.AvailableBytes < older.AvailableBytes {
			rate := math.Ceil(float64(older.AvailableBytes-newer.AvailableBytes) / seconds)
			if rate >= float64(math.MaxInt64) {
				return storageupload.ErrHeld
			}
			a.PeakGrowthBytesPerSecond = max(a.PeakGrowthBytesPerSecond, int64(rate))
		}
		// Overlapping inspections may finish out of acquisition order. Retain
		// the newest sample and any conservative growth revealed by the older
		// one. Equal timestamps cannot improve the available-space evidence.
		if !next.At.After(before.At) {
			if next.At.Equal(before.At) && next.AvailableBytes < before.AvailableBytes {
				a.Latest = &next
			}
			return nil
		}
	}
	a.Latest = &next
	return nil
}

func validScratchProbe(pod *unstructured.Unstructured, r *models.StorageTransactionRequest, a *scratchReservation) bool {
	if !scratchIdentity(pod, r) || a.ProbeImage == "" {
		return false
	}
	token, found, err := unstructured.NestedBool(pod.Object, "spec", "automountServiceAccountToken")
	if err != nil || !found || token {
		return false
	}
	for _, field := range []string{"initContainers", "ephemeralContainers"} {
		if values, _, err := unstructured.NestedSlice(pod.Object, "spec", field); err != nil || len(values) != 0 {
			return false
		}
	}
	containers, found, err := unstructured.NestedSlice(pod.Object, "spec", "containers")
	if err != nil || !found || len(containers) != 1 {
		return false
	}
	c, ok := containers[0].(map[string]interface{})
	if !ok || c["name"] != "probe" || c["image"] != a.ProbeImage || !reflect.DeepEqual(c["command"], []interface{}{"/vnbui-agent", "-scratch-probe"}) || c["args"] != nil || c["env"] != nil || c["envFrom"] != nil || c["volumeDevices"] != nil {
		return false
	}
	mounts, found, err := unstructured.NestedSlice(c, "volumeMounts")
	if err != nil || !found || len(mounts) != 1 {
		return false
	}
	mount, ok := mounts[0].(map[string]interface{})
	if !ok || mount["name"] != "scratch" || mount["mountPath"] != "/scratch" || mount["readOnly"] != true || mount["subPath"] != nil || mount["subPathExpr"] != nil {
		return false
	}
	volumes, found, err := unstructured.NestedSlice(pod.Object, "spec", "volumes")
	if err != nil || !found || len(volumes) != 1 {
		return false
	}
	volume, ok := volumes[0].(map[string]interface{})
	if !ok || len(volume) != 2 || volume["name"] != "scratch" {
		return false
	}
	claim, ok := volume["persistentVolumeClaim"].(map[string]interface{})
	return ok && claim["claimName"] == a.Name && claim["readOnly"] == true
}
