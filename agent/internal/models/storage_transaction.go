package models

// StorageProtocol is negotiated independently of the component major version.
const StorageProtocol = "vnbui-storage-transaction/1"

// Absence of a transfer profile preserves the original 8 MiB sizing contract.
const KubevirtTransfer32 = "kubevirt-32m/1"

const KubevirtNativeDisks = "kubevirt-native-disks/1"

func StorageProfiles() []string {
	return []string{"checksum-enforced/1", "consumer-verified/1", "db-rooted-consumer-verified/1"}
}

// StorageTransactionRequest is deliberately separate from the legacy request.
// No uploader may interpret an unknown protocol as a legacy backup request.
type StorageTransactionRequest struct {
	Protocol      string                 `json:"protocol"`
	OrgID         string                 `json:"org_id"`
	AgentID       string                 `json:"agent_id"`
	BackupID      string                 `json:"backup_id"`
	ReservationID string                 `json:"reservation_id"`
	PlanSHA256    string                 `json:"plan_sha256"`
	Plan          StorageTransactionPlan `json:"plan"`
}

type StorageTransactionPlan struct {
	TransferProfile   string            `json:"transfer_profile,omitempty"`
	AttemptID         string            `json:"attempt_id"`
	CapabilityProfile string            `json:"capability_profile"`
	Source            StorageSource     `json:"source"`
	Provider          string            `json:"provider"`
	VMName            string            `json:"vm_name"`
	BackupType        string            `json:"backup_type"`
	Exclusions        []string          `json:"exclusions"`
	Parent            *StorageParent    `json:"parent"`
	Target            StorageTarget     `json:"target"`
	CredentialRef     string            `json:"credential_ref"`
	Encryption        StorageEncryption `json:"encryption"`
	Artifacts         []StorageArtifact `json:"artifacts"`
	ChecksumPolicy    string            `json:"checksum_policy"`
}

type StorageSource struct {
	Schema        int             `json:"schema"`
	AgentID       string          `json:"agent_id"`
	VMID          string          `json:"vm_id"`
	VMUID         string          `json:"vm_uid"`
	VMIUID        *string         `json:"vmi_uid"`
	Namespace     string          `json:"namespace"`
	Volumes       []StorageVolume `json:"volumes"`
	NativeVolumes []StorageVolume `json:"native_volumes,omitempty"`
}

type StorageVolume struct {
	Name               string             `json:"name"`
	PVCName            string             `json:"pvc_name"`
	PVCUID             string             `json:"pvc_uid"`
	PVCResourceVersion string             `json:"pvc_resource_version"`
	CapacityBytes      int64              `json:"capacity_bytes"`
	Mapping            StorageDiskMapping `json:"mapping"`
}

type StorageDiskMapping struct {
	DiskName string  `json:"disk_name"`
	Device   string  `json:"device"`
	Bus      string  `json:"bus"`
	Serial   *string `json:"serial"`
}

type StorageParent struct {
	BackupID      string `json:"backup_id"`
	RootBackupID  string `json:"root_backup_id"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	GenerationID  string `json:"generation_id"`
	TrackerUID    string `json:"tracker_uid"`
	Checkpoint    string `json:"checkpoint"`
}

type StorageTarget struct {
	Endpoint            string `json:"endpoint"`
	Bucket              string `json:"bucket"`
	Region              string `json:"region"`
	ConfigurationPrefix string `json:"configuration_prefix"`
}

type StorageEncryption struct {
	Format string  `json:"format"`
	KeyRef *string `json:"key_ref"`
}

type StorageArtifact struct {
	VolumeID      string `json:"volume_id"`
	Role          string `json:"role"`
	Key           string `json:"key"`
	PlaintextMin  int64  `json:"plaintext_min"`
	PlaintextMax  int64  `json:"plaintext_max"`
	CiphertextMin int64  `json:"ciphertext_min"`
	CiphertextMax int64  `json:"ciphertext_max"`
}

// NativeDisks is the complete controller participant set. Schema 1 predates
// explicit selection support and is admitted only when no persistent disk is excluded.
func (s StorageSource) NativeDisks() []StorageVolume {
	if s.Schema == 2 {
		return s.NativeVolumes
	}
	return s.Volumes
}
