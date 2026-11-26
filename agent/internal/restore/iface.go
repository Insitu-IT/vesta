package restore

import (
	"errors"

	"vnbui/agent/internal/models"
)

// ErrPreJournalTargetReserved is returned only before a fresh restore journal
// is written or any destination resource is created. A received, authenticated
// response carrying this error can be treated differently from a lost reply.
var ErrPreJournalTargetReserved = errors.New("fresh restore target reserved before journal")

// ExecutorIface abstracts fresh restore execution. Native restores reconstruct
// raw disks and define an inactive domain; KubeVirt restores populate new PVCs
// with a private worker Job and create a Halted VM.
type ExecutorIface interface {
	StartRestore(req *models.RestoreRequest) (*models.RestoreProgress, error)
	GetProgress(restoreID string) *models.RestoreProgress
	ActiveCount() int
	SetEventCallback(cb func(map[string]interface{}))
}

// Compile-time check: Executor implements ExecutorIface.
var _ ExecutorIface = (*Executor)(nil)
