package models

import "encoding/json"

const KubeVirtRestoreSchema = "vnbui-kubevirt-vm-restore/1"

// KubeVirtSelectedDiskRestore binds the complete native participant set before
// excluding unprotected disks from a fresh stopped VM definition.
const KubeVirtSelectedDiskRestore = "kubevirt-selected-disks/1"

// KubeVirtRestoreRequest carries one authorized immutable chain and a fresh
// destination. Credentials travel only over authenticated TLS and private
// journal/Secret custody, never in API progress or the public restore bundle.
type KubeVirtRestoreRequest struct {
	Schema         string                `json:"schema"`
	OrgID          string                `json:"org_id"`
	AgentID        string                `json:"agent_id"`
	RecoveryOrigin *RestoreOrigin        `json:"recovery_origin,omitempty"`
	RestoreID      string                `json:"restore_id"`
	Target         KubeVirtRestoreTarget `json:"target"`
	Bundle         json.RawMessage       `json:"bundle"`
	S3             KubeVirtRestoreS3     `json:"s3"`
	Keys           map[string]string     `json:"keys"`
}

type KubeVirtRestoreS3 struct {
	Endpoint     string `json:"endpoint"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token,omitempty"`
}

type KubeVirtRestoreTarget struct {
	Namespace string                   `json:"namespace"`
	VMName    string                   `json:"vm_name"`
	Disks     []KubeVirtRestoreDisk    `json:"disks"`
	Networks  []KubeVirtRestoreNetwork `json:"networks"`
	// Explicit dependency mappings: "secret/<source>" or "configMap/<source>".
	Dependencies map[string]string `json:"dependencies"`
}

type KubeVirtRestoreDisk struct {
	VolumeName    string `json:"volume_name"`
	PVCName       string `json:"pvc_name"`
	StorageClass  string `json:"storage_class"`
	AccessMode    string `json:"access_mode"`
	VolumeMode    string `json:"volume_mode"`
	CapacityBytes int64  `json:"capacity_bytes"`
}

type KubeVirtRestoreNetwork struct {
	Name        string `json:"name"`
	Type        string `json:"type"`         // pod or multus
	NetworkName string `json:"network_name"` // empty for pod; target-namespace NAD for multus
}
