//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

var pvcGVR = schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}
var secretGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
var configMapGVR = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
var jobGVR = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
var vmGVR = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
var nadGVR = schema.GroupVersionResource{Group: "k8s.cni.cncf.io", Version: "v1", Resource: "network-attachment-definitions"}
var podGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

func restorePrefix(s *restoreState) string {
	prefix, _ := config.NormalizeKubevirtResourcePrefix(s.ResourcePrefix)
	return prefix
}
func resourceName(s *restoreState) string { return restorePrefix(s) + "-restore-" + s.PlanSHA[:24] }
func metadata(s *restoreState, name string) map[string]interface{} {
	return map[string]interface{}{"name": name, "namespace": s.Request.Target.Namespace,
		"labels":      map[string]interface{}{"app.kubernetes.io/managed-by": restorePrefix(s), "vnbui.io/restore-id": s.Request.RestoreID},
		"annotations": map[string]interface{}{"vnbui.io/restore-token": s.Token, "vnbui.io/restore-plan": s.PlanSHA, "vnbui.io/restore-org": s.Request.OrgID}}
}

func (e *Executor) reconcile(ctx context.Context, s *restoreState) error {
	if restorePrefix(s) == "" || restorePrefix(s) != e.cfg.KubevirtPrefix() || !e.namespaceAllowed(s.Request.Target.Namespace) {
		return errHeld
	}
	if s.Phase == "credential_cleanup" {
		return e.finishCredentialCleanup(ctx, s)
	}
	if s.Phase == "prepared" {
		if err := e.capturedVM(ctx, s); err != nil {
			return err
		}
	}
	if s.Phase != "provisioning" && s.Phase != "populating" && s.Phase != "defining" {
		return errHeld
	}
	if s.VM == nil {
		return errHeld
	}
	// Reopened provisioning must obey the same explicit attachment policy as
	// a fresh render. Do not rewrite a retained definition or allocate resources
	// for a plan that would let KubeVirt supply an implicit interface.
	autoAttach, found, err := unstructured.NestedBool(s.VM, "spec", "template", "spec", "domain", "devices", "autoattachPodInterface")
	if err != nil || !found || autoAttach {
		return fmt.Errorf("%w: retained VM definition permits implicit network attachment", errHeld)
	}
	// Resolve dependencies in this explicitly authorized namespace, not using
	// names copied from the source or cluster-wide wildcard lookups.
	for key, name := range s.Request.Target.Dependencies {
		gvr := configMapGVR
		if len(key) > 7 && key[:7] == "secret/" {
			gvr = secretGVR
		}
		obj, err := e.dynamic.Resource(gvr).Namespace(s.Request.Target.Namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: mapped dependency is missing", errHeld)
		}
		if err != nil {
			return err
		}
		if obj.GetDeletionTimestamp() != nil {
			return errHeld
		}
	}
	for _, network := range s.Request.Target.Networks {
		if network.Type == "multus" {
			_, err := e.dynamic.Resource(nadGVR).Namespace(s.Request.Target.Namespace).Get(ctx, network.NetworkName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("%w: mapped Multus network is missing", errHeld)
			}
			if err != nil {
				return err
			}
		}
	}
	// A pre-existing target VM is refused even before allocating the first PVC.
	if s.VMUID == "" && s.Inflight != "virtualmachines/"+s.Request.Target.VMName {
		_, err := e.dynamic.Resource(vmGVR).Namespace(s.Request.Target.Namespace).Get(ctx, s.Request.Target.VMName, metav1.GetOptions{})
		if err == nil {
			return fmt.Errorf("%w: target VM already exists", errHeld)
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
	}
	data, _ := json.Marshal(s.Request)
	secret := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Secret", "metadata": metadata(s, resourceName(s)), "immutable": true, "type": "Opaque",
		"data": map[string]interface{}{"request.json": base64.StdEncoding.EncodeToString(data)}}}
	if s.CAPEM != "" {
		secret.Object["data"].(map[string]interface{})["ca.pem"] = base64.StdEncoding.EncodeToString([]byte(s.CAPEM))
	}
	uid, err := e.ensure(ctx, s, secretGVR, secret, s.SecretUID)
	if err != nil {
		return err
	}
	if uid != s.SecretUID {
		s.SecretUID = uid
		if err = e.save(s); err != nil {
			return err
		}
	}
	for _, disk := range s.Request.Target.Disks {
		pvc := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": metadata(s, disk.PVCName), "spec": map[string]interface{}{
			"storageClassName": disk.StorageClass, "volumeMode": disk.VolumeMode, "accessModes": []interface{}{disk.AccessMode},
			"resources": map[string]interface{}{"requests": map[string]interface{}{"storage": strconv.FormatInt(disk.CapacityBytes, 10)}}}}}
		uid, err = e.ensure(ctx, s, pvcGVR, pvc, s.PVCUIDs[disk.PVCName])
		if err != nil {
			return err
		}
		if uid != s.PVCUIDs[disk.PVCName] {
			s.PVCUIDs[disk.PVCName] = uid
			if err = e.save(s); err != nil {
				return err
			}
		}
	}
	job := workerJob(s)
	uid, err = e.ensure(ctx, s, jobGVR, job, s.JobUID)
	if err != nil {
		return err
	}
	if uid != s.JobUID {
		s.JobUID = uid
		if err = e.save(s); err != nil {
			return err
		}
	}
	s.Phase = "populating"
	s.Progress.ProgressPercent = 25
	op := "populating and verifying fresh PVCs"
	s.Progress.CurrentOperation = &op
	observed, err := e.dynamic.Resource(jobGVR).Namespace(s.Request.Target.Namespace).Get(ctx, job.GetName(), metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(observed.GetUID()) != s.JobUID || observed.GetDeletionTimestamp() != nil {
		return errHeld
	}
	conditions, _, _ := unstructured.NestedSlice(observed.Object, "status", "conditions")
	complete := false
	for _, entry := range conditions {
		condition, _ := entry.(map[string]interface{})
		if condition["status"] == "True" {
			if condition["type"] == "Failed" {
				return fmt.Errorf("%w: restore worker failed; partial PVCs retained", errHeld)
			}
			if condition["type"] == "Complete" {
				complete = true
			}
		}
	}
	if !complete {
		return e.save(s)
	}
	pods, err := e.dynamic.Resource(podGVR).Namespace(s.Request.Target.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "batch.kubernetes.io/controller-uid=" + s.JobUID})
	if err != nil {
		return err
	}
	if len(pods.Items) != 1 {
		return fmt.Errorf("%w: exact single worker Pod evidence is unavailable", errHeld)
	}
	pod := pods.Items[0]
	owners := pod.GetOwnerReferences()
	phase, _, _ := unstructured.NestedString(pod.Object, "status", "phase")
	if len(owners) != 1 || string(owners[0].UID) != s.JobUID || owners[0].Kind != "Job" || phase != "Succeeded" || pod.GetDeletionTimestamp() != nil {
		return errHeld
	}
	// All disks were reconstructed and checksum-read before worker exit zero.
	// Recheck exact PVC UIDs after completion; no replacement can be attached.
	for _, disk := range s.Request.Target.Disks {
		pvc, err := e.dynamic.Resource(pvcGVR).Namespace(s.Request.Target.Namespace).Get(ctx, disk.PVCName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		phase, _, _ := unstructured.NestedString(pvc.Object, "status", "phase")
		if string(pvc.GetUID()) != s.PVCUIDs[disk.PVCName] || pvc.GetDeletionTimestamp() != nil {
			return errHeld
		}
		if phase != "Bound" {
			return errors.New("waiting for bound restored PVC")
		}
	}
	s.Phase = "defining"
	s.Progress.ProgressPercent = 90
	op = "creating fresh Halted VM"
	s.Progress.CurrentOperation = &op
	if err = e.save(s); err != nil {
		return err
	}
	vm := &unstructured.Unstructured{Object: s.VM}
	vm.Object["metadata"] = metadata(s, s.Request.Target.VMName)
	uid, err = e.ensure(ctx, s, vmGVR, vm, s.VMUID)
	if err != nil {
		return err
	}
	s.VMUID = uid
	// Journal this boundary before deleting the credential Secret. Recovery
	// retries only cleanup, never the worker or destination creation.
	s.Phase = "credential_cleanup"
	s.Progress.ProgressPercent = 99
	op = "fresh VM created Halted; removing temporary restore credentials"
	s.Progress.CurrentOperation = &op
	pvcs := map[string]interface{}{}
	for name, uid := range s.PVCUIDs {
		pvcs[name] = uid
	}
	s.Progress.Result = map[string]interface{}{"namespace": s.Request.Target.Namespace, "vm_name": s.Request.Target.VMName, "vm_uid": s.VMUID, "pvc_uids": pvcs, "job_name": resourceName(s), "job_uid": s.JobUID, "plan_sha256": s.PlanSHA, "run_strategy": "Halted"}
	if err = e.save(s); err != nil {
		return err
	}
	return e.finishCredentialCleanup(ctx, s)
}

func (e *Executor) finishCredentialCleanup(ctx context.Context, s *restoreState) error {
	if s.VMUID == "" || s.JobUID == "" || s.SecretUID == "" {
		return errHeld
	}
	client := e.dynamic.Resource(secretGVR).Namespace(s.Request.Target.Namespace)
	secret, err := client.Get(ctx, resourceName(s), metav1.GetOptions{})
	if err == nil {
		if string(secret.GetUID()) != s.SecretUID {
			return fmt.Errorf("%w: temporary credential Secret was replaced", errHeld)
		}
		secretUID := types.UID(s.SecretUID)
		err = client.Delete(ctx, resourceName(s), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &secretUID}})
		if apierrors.IsConflict(err) {
			return fmt.Errorf("%w: credential cleanup UID conflict", errHeld)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		// Accepted deletion may still be pending finalizers. A lost response
		// retries this observation; absence is completion only for cleanup,
		// never evidence that the restore worker or disk writes succeeded.
		_, err = client.Get(ctx, resourceName(s), metav1.GetOptions{})
		if err == nil {
			return errors.New("waiting for temporary restore credential deletion")
		}
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	s.Phase = "completed"
	s.Progress.Status = models.TaskStatusCompleted
	s.Progress.ProgressPercent = 100
	op := "fresh VM created Halted; validate guest before starting"
	s.Progress.CurrentOperation = &op
	s.Request.Keys = nil
	s.Request.S3.AccessKey = ""
	s.Request.S3.SecretKey = ""
	s.Request.S3.SessionToken = ""
	return e.save(s)
}

// ensure persists creation intent before API writes. Lost replies may recover
// only the exact nonce/plan/spec; recorded UIDs cannot be replaced or recreated.
// If an interrupted create is absent, custody stays held rather than guessing.
func (e *Executor) ensure(ctx context.Context, s *restoreState, gvr schema.GroupVersionResource, desired *unstructured.Unstructured, known string) (string, error) {
	if !e.namespaceAllowed(s.Request.Target.Namespace) || desired.GetNamespace() != s.Request.Target.Namespace {
		return "", errHeld
	}
	name := desired.GetName()
	key := gvr.Resource + "/" + name
	client := e.dynamic.Resource(gvr).Namespace(s.Request.Target.Namespace)
	current, err := client.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		if current.GetUID() == "" || current.GetDeletionTimestamp() != nil || (known != "" && string(current.GetUID()) != known) || !ownedMatches(current, desired, gvr) {
			return "", fmt.Errorf("%w: resource collision or mutation", errHeld)
		}
		if s.Inflight == key {
			s.Inflight = ""
		}
		return string(current.GetUID()), nil
	}
	if !apierrors.IsNotFound(err) {
		return "", err
	}
	if known != "" || s.Inflight == key {
		return "", fmt.Errorf("%w: recorded or uncertain resource is absent", errHeld)
	}
	if s.Inflight != "" {
		return "", errHeld
	}
	s.Inflight = key
	if err = e.save(s); err != nil {
		return "", err
	}
	created, err := client.Create(ctx, desired, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if created.GetUID() == "" || !ownedMatches(created, desired, gvr) {
		return "", errHeld
	}
	// UID and cleared intent are persisted by the caller in one next save.
	s.Inflight = ""
	return string(created.GetUID()), nil
}

func ownedMatches(actual, wanted *unstructured.Unstructured, gvr schema.GroupVersionResource) bool {
	if actual.GetName() != wanted.GetName() || actual.GetNamespace() != wanted.GetNamespace() || len(actual.GetOwnerReferences()) != 0 {
		return false
	}
	for key, value := range wanted.GetAnnotations() {
		if actual.GetAnnotations()[key] != value {
			return false
		}
	}
	comparison := wanted.DeepCopy()
	if gvr == pvcGVR {
		actualSize, _, _ := unstructured.NestedString(actual.Object, "spec", "resources", "requests", "storage")
		wantedSize, _, _ := unstructured.NestedString(wanted.Object, "spec", "resources", "requests", "storage")
		a, errA := resource.ParseQuantity(actualSize)
		b, errB := resource.ParseQuantity(wantedSize)
		if errA != nil || errB != nil || a.Cmp(b) != 0 {
			return false
		}
		_ = unstructured.SetNestedField(comparison.Object, actualSize, "spec", "resources", "requests", "storage")
	}
	if !contains(actual.Object["spec"], comparison.Object["spec"]) {
		return false
	}
	if gvr == secretGVR {
		return actual.Object["immutable"] == true && actual.Object["type"] == "Opaque" && reflect.DeepEqual(actual.Object["data"], wanted.Object["data"])
	}
	if gvr == pvcGVR {
		spec, _ := actual.Object["spec"].(map[string]interface{})
		if spec["dataSource"] != nil || spec["dataSourceRef"] != nil || spec["selector"] != nil {
			return false
		}
	}
	return true
}

// Server-defaulted map fields are allowed; every planned field and array entry
// must still be present exactly. Controller metadata/status never grants ownership.
func contains(actual, wanted interface{}) bool {
	if wanted == nil {
		return true
	}
	switch value := wanted.(type) {
	case map[string]interface{}:
		got, ok := actual.(map[string]interface{})
		if !ok {
			return false
		}
		for k, v := range value {
			if !contains(got[k], v) {
				return false
			}
		}
		return true
	case []interface{}:
		got, ok := actual.([]interface{})
		if !ok || len(got) != len(value) {
			return false
		}
		for i, v := range value {
			if !contains(got[i], v) {
				return false
			}
		}
		return true
	default:
		return fmt.Sprint(actual) == fmt.Sprint(wanted)
	}
}

func workerJob(s *restoreState) *unstructured.Unstructured {
	mounts := []interface{}{map[string]interface{}{"name": "input", "mountPath": "/run/restore", "readOnly": true}}
	devices := []interface{}{}
	volumes := []interface{}{map[string]interface{}{"name": "input", "secret": map[string]interface{}{"secretName": resourceName(s), "defaultMode": int64(0440)}}}
	for i, disk := range s.Request.Target.Disks {
		name := fmt.Sprintf("disk-%03d", i)
		volumes = append(volumes, map[string]interface{}{"name": name, "persistentVolumeClaim": map[string]interface{}{"claimName": disk.PVCName}})
		if disk.VolumeMode == "Block" {
			devices = append(devices, map[string]interface{}{"name": name, "devicePath": fmt.Sprintf("/dev/restore/disk-%03d", i)})
		} else {
			mounts = append(mounts, map[string]interface{}{"name": name, "mountPath": fmt.Sprintf("/restore/disk-%03d", i)})
		}
	}
	seconds := int64(86400) // existing journals retain their original worker contract
	if s.Budget != nil {
		seconds = s.Budget.Budget.RunSeconds
	}
	container := map[string]interface{}{"name": "restore", "image": s.Image, "imagePullPolicy": "IfNotPresent", "command": []interface{}{"/vnbui-restore"}, "args": []interface{}{"-worker", "/run/restore/request.json", "-timeout", (time.Duration(seconds) * time.Second).String()},
		"volumeMounts": mounts, "volumeDevices": devices, "resources": map[string]interface{}{"requests": map[string]interface{}{"cpu": "100m", "memory": "128Mi"}, "limits": map[string]interface{}{"memory": "1Gi"}},
		"securityContext": map[string]interface{}{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]interface{}{"drop": []interface{}{"ALL"}}}}
	if s.Budget != nil {
		container["args"] = append(container["args"].([]interface{}), "-deadline", s.Budget.Deadline().UTC().Format(time.RFC3339Nano))
	}
	if len(devices) == 0 {
		delete(container, "volumeDevices")
	}
	if s.CAPEM != "" {
		container["args"] = append(container["args"].([]interface{}), "-worker-ca", "/run/restore/ca.pem")
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "batch/v1", "kind": "Job", "metadata": metadata(s, resourceName(s)), "spec": map[string]interface{}{
		"backoffLimit": int64(0), "parallelism": int64(1), "completions": int64(1), "activeDeadlineSeconds": seconds, "suspend": false, "podReplacementPolicy": "Failed",
		"template": map[string]interface{}{"metadata": map[string]interface{}{"labels": map[string]interface{}{"app.kubernetes.io/managed-by": restorePrefix(s), "vnbui.io/restore-id": s.Request.RestoreID}}, "spec": map[string]interface{}{
			"serviceAccountName": restorePrefix(s) + "-restore-worker", "automountServiceAccountToken": false, "restartPolicy": "Never", "securityContext": map[string]interface{}{"runAsNonRoot": true, "runAsUser": int64(107), "runAsGroup": int64(107), "fsGroup": int64(107), "seccompProfile": map[string]interface{}{"type": "RuntimeDefault"}},
			"containers": []interface{}{container}, "volumes": volumes}}}}}
}
