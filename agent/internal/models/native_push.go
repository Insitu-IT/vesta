package models

// NativePushManifest is producer content identity. NativeFileSet separately
// binds closed local inode custody, and NativeStorageReceipt binds upload bytes.
type NativeSourceDisk struct {
	Target string `json:"target"`
	Source string `json:"source"`
	Bus    string `json:"bus"`
	Format string `json:"format"`
}

type NativePushDisk struct {
	Target      string `json:"target"`
	File        string `json:"file"`
	SizeBytes   int64  `json:"size_bytes"`
	VirtualSize int64  `json:"virtual_size"`
	SHA256      string `json:"sha256"`
}

type NativePushManifest struct {
	Schema               string             `json:"schema"`
	BackupID             string             `json:"backup_id"`
	AttemptID            string             `json:"attempt_id"`
	DomainUUID           string             `json:"domain_uuid"`
	Checkpoint           string             `json:"checkpoint"`
	CheckpointSHA256     string             `json:"checkpoint_sha256"`
	ParentBackupID       *string            `json:"parent_backup_id"`
	ParentManifestSHA256 *string            `json:"parent_manifest_sha256"`
	Source               []NativeSourceDisk `json:"source"`
	Exclusions           []string           `json:"exclusions"`
	DomainXMLSHA256      string             `json:"domain_xml_sha256"`
	Disks                []NativePushDisk   `json:"disks"`
}

type NativePushResult struct {
	Manifest       NativePushManifest `json:"manifest"`
	ManifestSHA256 string             `json:"manifest_sha256"`
}
