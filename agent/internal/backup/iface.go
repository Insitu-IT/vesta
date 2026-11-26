package backup

import (
	"errors"

	"vnbui/agent/internal/models"
)

// ErrUploadNotApplicable is returned by executors that use stream-through
// (backup+upload is one operation, e.g. KubeVirt VEP 25 pull mode).
var ErrUploadNotApplicable = errors.New("upload not applicable: backup uses stream-through")

// ExecutorIface abstracts backup execution. The libvirt executor runs
// virtnbdbackup locally; the kubevirt executor streams from VEP 25 endpoints.
type ExecutorIface interface {
	StartBackup(req *models.BackupRequest) (*models.BackupProgress, error)
	StartUpload(backupID, outputPath string) (*models.BackupProgress, error)
	GetProgress(backupID string) *models.BackupProgress
	CancelBackup(backupID string) error
	ActiveJobs() []string
	ActiveCount() int
	SetS3Config(raw map[string]interface{})
	SetEventCallback(cb func(map[string]interface{}))
}

// Compile-time check: Executor implements ExecutorIface.
var _ ExecutorIface = (*Executor)(nil)
