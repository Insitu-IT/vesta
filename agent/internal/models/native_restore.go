package models

import "encoding/json"

const NativeRestoreSchema = "vnbui-native-vm-restore/1"

// NativeRestoreTarget has no arbitrary destination filesystem paths. Restored
// target.raw files live below the installation-owned root/<restore UUID>/disks.
type NativeRestoreTarget struct {
	VMName            string                 `json:"vm_name"`
	VMUUID            string                 `json:"vm_uuid"`
	Disks             []string               `json:"disks"`
	DropExcludedDisks []string               `json:"drop_excluded_disks"`
	Networks          []NativeRestoreNetwork `json:"networks"`
}

type NativeRestoreNetwork struct {
	SourceMAC string `json:"source_mac"`
	Network   string `json:"network"`
}

type NativeRestoreRequest struct {
	Schema         string              `json:"schema"`
	OrgID          string              `json:"org_id"`
	AgentID        string              `json:"agent_id"`
	RecoveryOrigin *RestoreOrigin      `json:"recovery_origin,omitempty"`
	RestoreID      string              `json:"restore_id"`
	Target         NativeRestoreTarget `json:"target"`
	Bundle         json.RawMessage     `json:"bundle"`
	S3             KubeVirtRestoreS3   `json:"s3"`
	Keys           map[string]string   `json:"keys"`
}
