package models

// NativeTransactionRequest is a discriminated whole plan. It deliberately has
// no KubeVirt PVC/extent or display-name fields. Native parent authority is held.
type NativeTransactionRequest struct {
	Protocol      string            `json:"protocol"`
	OrgID         string            `json:"org_id"`
	AgentID       string            `json:"agent_id"`
	BackupID      string            `json:"backup_id"`
	ReservationID string            `json:"reservation_id"`
	PlanSHA256    string            `json:"plan_sha256"`
	Plan          NativeStoragePlan `json:"plan"`
}

type NativeStoragePlan struct {
	AttemptID         string                  `json:"attempt_id"`
	CapabilityProfile string                  `json:"capability_profile"`
	Provider          string                  `json:"provider"`
	Source            NativeStorageSource     `json:"source"`
	BackupType        string                  `json:"backup_type"`
	Parent            *StorageParent          `json:"parent"`
	Exclusions        []string                `json:"exclusions"`
	Target            StorageTarget           `json:"target"`
	CredentialRef     string                  `json:"credential_ref"`
	Encryption        StorageEncryption       `json:"encryption"`
	Artifacts         []NativeStorageArtifact `json:"artifacts"`
	ChecksumPolicy    string                  `json:"checksum_policy"`
}

// NativeStorageSource is the libvirt-native-fileset/1 source variant. Its
// inventory digest commits filesystem custody, not uploaded content. It is not
// interchangeable with StorageSource (the independently versioned KubeVirt representation).
type NativeStorageSource struct {
	Representation  string        `json:"representation"`
	AgentID         string        `json:"agent_id"`
	VMID            string        `json:"vm_id"`
	InventorySHA256 string        `json:"inventory_sha256"`
	Inventory       NativeFileSet `json:"inventory"`
}

// NativeStorageArtifact identifies a file, including common metadata with no
// disk association. The immutable inventory carries its path/member/checkpoint.
type NativeStorageArtifact struct {
	ArtifactID    string  `json:"artifact_id"`
	DiskID        *string `json:"disk_id"`
	Role          string  `json:"role"`
	Key           string  `json:"key"`
	PlaintextMin  int64   `json:"plaintext_min"`
	PlaintextMax  int64   `json:"plaintext_max"`
	CiphertextMin int64   `json:"ciphertext_min"`
	CiphertextMax int64   `json:"ciphertext_max"`
}

// NativeStorageReceipt retains schema-2 acceptance semantics but explicitly
// discriminates native membership. Old volume-pair readers must reject it.
type NativeStorageReceipt struct {
	Protocol       string                       `json:"protocol"`
	Schema         int                          `json:"schema"`
	Representation string                       `json:"representation"`
	ReservationID  string                       `json:"reservation_id"`
	BackupID       string                       `json:"backup_id"`
	Endpoint       string                       `json:"endpoint"`
	Bucket         string                       `json:"bucket"`
	Objects        []NativeStorageObjectReceipt `json:"objects"`
}

type NativeStorageObjectReceipt struct {
	ArtifactID       string  `json:"artifact_id"`
	DiskID           *string `json:"disk_id"`
	Role             string  `json:"role"`
	Key              string  `json:"key"`
	VersionID        *string `json:"version_id"`
	ETag             string  `json:"etag"`
	PlaintextBytes   int64   `json:"plaintext_bytes"`
	CiphertextBytes  int64   `json:"ciphertext_bytes"`
	PlaintextSHA256  string  `json:"plaintext_sha256"`
	CiphertextSHA256 string  `json:"ciphertext_sha256"`
}
