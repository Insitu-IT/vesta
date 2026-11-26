package models

import "time"

// BackupRequest is a request to execute a backup.
// JSON tags must match Python BackupRequest field names exactly.
type BackupRequest struct {
	VMNamespace    string         `json:"vm_namespace,omitempty"`
	VMUID          string         `json:"vm_uid,omitempty"`
	BackupID       string         `json:"backup_id"`
	VMName         string         `json:"vm_name"`
	BackupType     BackupType     `json:"backup_type"`
	OutputPath     string         `json:"output_path"`
	Compression    *string        `json:"compression"`
	IncludeDisks   []string       `json:"include_disks"`
	ExcludeDisks   []string       `json:"exclude_disks"`
	Workers        *int           `json:"workers"`
	EncryptionType EncryptionType `json:"encryption_type"`
	EncryptionKey  *string        `json:"encryption_key"`
	ParentPath     *string        `json:"parent_path"`
	IncludeRaw     bool           `json:"include_raw"`
}

// BackupProgress is backup progress information.
// JSON tags must match Python BackupProgress field names exactly.
type BackupProgress struct {
	BackupID            string     `json:"backup_id"`
	Status              TaskStatus `json:"status"`
	VMName              *string    `json:"vm_name"`
	SystemdUnit         *string    `json:"systemd_unit"`
	StoragePath         *string    `json:"storage_path"`
	ProgressLogPath     *string    `json:"progress_log_path"`
	ProgressPercent     int        `json:"progress_percent"`
	CurrentDisk         *string    `json:"current_disk"`
	BytesTransferred    int64      `json:"bytes_transferred"`
	TotalBytes          *int64     `json:"total_bytes"`
	TransferRateMbps    *float64   `json:"transfer_rate_mbps"`
	StartedAt           *time.Time `json:"started_at"`
	EstimatedCompletion *time.Time `json:"estimated_completion"`
	ErrorMessage        *string    `json:"error_message"`
	S3Location          *string    `json:"s3_location"`
	CheckpointCommitted *bool      `json:"checkpoint_committed,omitempty"`
	CurrentOperation    *string    `json:"current_operation"`
}

// NewRunningBackupProgress creates a BackupProgress in RUNNING state.
func NewRunningBackupProgress(backupID, vmName string, systemdUnit *string) *BackupProgress {
	now := time.Now().UTC()
	return &BackupProgress{
		BackupID:    backupID,
		Status:      TaskStatusRunning,
		VMName:      &vmName,
		SystemdUnit: systemdUnit,
		StartedAt:   &now,
	}
}

// BackupResult is the backup completion result.
// JSON tags must match Python BackupResult field names exactly.
type BackupResult struct {
	BackupID       string                   `json:"backup_id"`
	Success        bool                     `json:"success"`
	CheckpointName string                   `json:"checkpoint_name"`
	TotalSizeBytes int64                    `json:"total_size_bytes"`
	DurationSecs   float64                  `json:"duration_seconds"`
	DisksBackedUp  []map[string]interface{} `json:"disks_backed_up"`
	Metadata       map[string]interface{}   `json:"metadata"`
	ErrorMessage   *string                  `json:"error_message"`
	Encrypted      bool                     `json:"encrypted"`
	EncryptionType *string                  `json:"encryption_type"`
	S3Location     *string                  `json:"s3_location"`
	LocalDeleted   bool                     `json:"local_deleted"`
}
