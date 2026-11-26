package models

// TaskStatus represents task execution status.
type TaskStatus string

const (
	TaskStatusPending         TaskStatus = "pending"
	TaskStatusRunning         TaskStatus = "running"
	TaskStatusCompleted       TaskStatus = "completed"
	TaskStatusFailed          TaskStatus = "failed"
	TaskStatusCancelled       TaskStatus = "cancelled"
	TaskStatusCleanupRequired TaskStatus = "cleanup_required"
)

// AllTaskStatuses returns all valid TaskStatus values.
func AllTaskStatuses() []TaskStatus {
	return []TaskStatus{
		TaskStatusPending,
		TaskStatusRunning,
		TaskStatusCompleted,
		TaskStatusFailed,
		TaskStatusCancelled,
		TaskStatusCleanupRequired,
	}
}

// BackupType represents backup types.
type BackupType string

const (
	BackupTypeFull         BackupType = "full"
	BackupTypeIncremental  BackupType = "incremental"
	BackupTypeDifferential BackupType = "differential"
)

// AllBackupTypes returns all valid BackupType values.
func AllBackupTypes() []BackupType {
	return []BackupType{
		BackupTypeFull,
		BackupTypeIncremental,
		BackupTypeDifferential,
	}
}

// EncryptionType represents encryption types.
type EncryptionType string

const (
	EncryptionTypeNone      EncryptionType = "none"
	EncryptionTypeFernet    EncryptionType = "fernet"
	EncryptionTypeAge       EncryptionType = "age"
	EncryptionTypeAES256GCM EncryptionType = "aes-256-gcm"
)

// AllEncryptionTypes returns all valid EncryptionType values.
func AllEncryptionTypes() []EncryptionType {
	return []EncryptionType{
		EncryptionTypeNone,
		EncryptionTypeFernet,
		EncryptionTypeAge,
		EncryptionTypeAES256GCM,
	}
}
