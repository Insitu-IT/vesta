//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"vnbui/agent/internal/models"
)

var apiVersionName = regexp.MustCompile(`^v[0-9]+((alpha|beta)[0-9]+)?$`)

func observedTracker(ctx context.Context, client dynamic.Interface, prefix string, vm models.VMInfo) map[string]string {
	evidence := map[string]string{"state": "unknown"}
	if client == nil || (prefix != "vesta" && prefix != "vnbui") {
		return evidence
	}
	name := TrackerName(prefix, vm.Namespace+"/"+vm.VMUID)
	obj, err := client.Resource(BackupTrackerResource).Namespace(vm.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		evidence["state"] = "absent"
		return evidence
	}
	if err != nil || obj == nil {
		return evidence
	}
	source, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "name")
	group, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "apiGroup")
	kind, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "kind")
	if obj.GetName() != name || obj.GetNamespace() != vm.Namespace || obj.GetDeletionTimestamp() != nil ||
		obj.GetUID() == "" || group != "kubevirt.io" || kind != "VirtualMachine" ||
		source != vm.Name || obj.GetAnnotations()["vnbui.insitu/vm-uid"] != vm.VMUID {
		evidence["state"] = "source_mismatch"
		return evidence
	}
	checkpoint, _, err := unstructured.NestedString(obj.Object, "status", "latestCheckpoint", "name")
	if err != nil {
		return evidence
	}
	evidence["state"] = "observed"
	// Only equality with the accepted catalog is needed. Never send arbitrary
	// controller strings, annotations, descriptions or object bodies.
	uidHash := sha256.Sum256([]byte(obj.GetUID()))
	checkpointHash := sha256.Sum256([]byte(checkpoint))
	evidence["uid_sha256"] = hex.EncodeToString(uidHash[:])
	evidence["checkpoint_sha256"] = hex.EncodeToString(checkpointHash[:])
	return evidence
}

// Resource discovery uses public API descriptions, without listing classes,
// storage drivers or objects outside the selected source namespaces.
func resourceAvailability(ctx context.Context, client rest.Interface, groupVersion string, names ...string) map[string]string {
	var list metav1.APIResourceList
	err := client.Get().AbsPath("/apis/" + groupVersion).Do(ctx).Into(&list)
	result := map[string]string{}
	for _, name := range names {
		result[name] = "unknown"
		if apierrors.IsNotFound(err) {
			result[name] = "not_served"
		}
		if err != nil || list.GroupVersion != groupVersion {
			continue
		}
		result[name] = "not_served"
		for _, resource := range list.APIResources {
			if resource.Name == name {
				result[name] = "served"
				break
			}
		}
	}
	return result
}

func groupSnapshotAvailability(ctx context.Context, client rest.Interface) string {
	const name = "groupsnapshot.storage.k8s.io"
	var group metav1.APIGroup
	err := client.Get().AbsPath("/apis/" + name).Do(ctx).Into(&group)
	if apierrors.IsNotFound(err) {
		return "not_served"
	}
	if err != nil || group.Name != name || len(group.Versions) == 0 || len(group.Versions) > 8 {
		return "unknown"
	}
	result := "not_served"
	for _, version := range group.Versions {
		if !apiVersionName.MatchString(version.Version) || version.GroupVersion != name+"/"+version.Version {
			result = "unknown"
			continue
		}
		entries := resourceAvailability(ctx, client, version.GroupVersion, "volumegroupsnapshots", "volumegroupsnapshotclasses")
		if entries["volumegroupsnapshots"] == "served" && entries["volumegroupsnapshotclasses"] == "served" {
			return "served"
		}
		if entries["volumegroupsnapshots"] == "unknown" || entries["volumegroupsnapshotclasses"] == "unknown" {
			result = "unknown"
		}
	}
	return result
}

func (p *Provider) describeBackupAPIs(ctx context.Context, vms []models.VMInfo) {
	if len(vms) == 0 || p.k8s == nil {
		return
	}
	client := p.k8s.Discovery().RESTClient()
	if client == nil {
		return
	}
	// Honor the inventory's existing request deadline. A slow optional group
	// lookup cannot change the evidence already read for backup and export.
	backup := resourceAvailability(ctx, client, BackupResource.GroupVersion().String(), BackupResource.Resource, BackupTrackerResource.Resource)
	export := resourceAvailability(ctx, client, ExportResource.GroupVersion().String(), ExportResource.Resource)
	for i := range vms {
		evidence := map[string]string{
			BackupResource.Resource:        backup[BackupResource.Resource],
			BackupTrackerResource.Resource: backup[BackupTrackerResource.Resource],
			ExportResource.Resource:        export[ExportResource.Resource],
		}
		vms[i].Metadata["backup_apis"] = evidence
		if backup[BackupTrackerResource.Resource] == "served" && vms[i].VMIUID != "" {
			vms[i].Metadata["backup_tracker"] = observedTracker(ctx, p.dynamic, p.trackerPrefix, vms[i])
		}
	}
	group := ""
	for i := range vms {
		persistent := 0
		for _, disk := range vms[i].Disks {
			if disk["source_type"] == "persistentVolumeClaim" || disk["source_type"] == "dataVolume" {
				persistent++
			}
		}
		if persistent > 1 {
			if group == "" {
				group = groupSnapshotAvailability(ctx, client)
			}
			vms[i].Metadata["backup_apis"].(map[string]string)["group_snapshot"] = group
		}
	}
}
