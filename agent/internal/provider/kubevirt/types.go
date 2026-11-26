//go:build kubevirt

package kubevirt

import (
	"crypto/sha256"
	"encoding/hex"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TrackerName is shared by native execution and read-only source discovery.
func TrackerName(prefix, identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

// KubeVirt GroupVersionResources for dynamic client.
// Shared across provider, backup executor, and reconciler.
var (
	VMIResource = schema.GroupVersionResource{
		Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances",
	}
	VMResource = schema.GroupVersionResource{
		Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines",
	}
	SnapshotResource = schema.GroupVersionResource{
		Group: "snapshot.kubevirt.io", Version: "v1beta1", Resource: "virtualmachinesnapshots",
	}
	ExportResource = schema.GroupVersionResource{
		Group: "export.kubevirt.io", Version: "v1beta1", Resource: "virtualmachineexports",
	}
	BackupResource = schema.GroupVersionResource{
		Group: "backup.kubevirt.io", Version: "v1alpha1", Resource: "virtualmachinebackups",
	}
	BackupTrackerResource = schema.GroupVersionResource{
		Group: "backup.kubevirt.io", Version: "v1alpha1", Resource: "virtualmachinebackuptrackers",
	}
)
