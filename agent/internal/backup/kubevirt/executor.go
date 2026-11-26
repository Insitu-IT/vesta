//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/security"
)

// Executor implements backup.ExecutorIface for KubeVirt VMs.
type Executor struct {
	cfg       *config.Config
	resources *resources.Manager
	dynamic   dynamic.Interface
	core      kubernetes.Interface
	namespace string

	mu      sync.RWMutex
	jobs    map[string]*models.BackupProgress
	cancels map[string]context.CancelFunc

	s3mu     sync.RWMutex
	s3Config *backup.S3Config

	onEvent       func(map[string]interface{})
	transactionMu sync.Mutex
	recovered     bool
	reported      map[string]bool
	storageRunner *transactionRunner
}

// SetCoreClient is called before runner startup; it shares the provider budget.
func (e *Executor) SetCoreClient(client interface{}) { e.core, _ = client.(kubernetes.Interface) }

// NewExecutor creates a KubeVirt backup executor.
func NewExecutor(cfg *config.Config, res *resources.Manager, dynClient dynamic.Interface, namespace string) *Executor {
	return &Executor{
		cfg:       cfg,
		resources: res,
		dynamic:   dynClient,
		namespace: namespace,
		jobs:      make(map[string]*models.BackupProgress),
		cancels:   make(map[string]context.CancelFunc),
		reported:  make(map[string]bool),
	}
}

func (e *Executor) SetEventCallback(cb func(map[string]interface{})) {
	e.onEvent = cb
}

func (e *Executor) SetS3Config(raw map[string]interface{}) {
	cfg, err := backup.ParseS3Config(raw)
	e.s3mu.Lock()
	defer e.s3mu.Unlock()
	if err != nil {
		e.s3Config = nil
		slog.Error("S3 config rejected", "error", err)
		return
	}
	if cfg == nil {
		e.s3Config = nil
		return
	}
	if e.s3Config == nil || e.s3Config.Endpoint != cfg.Endpoint || e.s3Config.Bucket != cfg.Bucket {
		slog.Info("S3 config updated", "endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "ssl", cfg.UseSSL)
	}
	e.s3Config = cfg
	go e.recoverTransactions(cfg)
}

func (e *Executor) getS3Config() *backup.S3Config {
	e.s3mu.RLock()
	defer e.s3mu.RUnlock()
	return e.s3Config
}

func (e *Executor) StartBackup(req *models.BackupRequest) (*models.BackupProgress, error) {
	if err := e.cfg.ValidateNativeLifetime(); err != nil {
		return nil, err
	}
	// Validate VM name
	if e.cfg.KubevirtPrefix() == "" {
		return nil, fmt.Errorf("invalid Kubernetes naming profile")
	}
	if err := security.ValidateVMName(req.VMName); err != nil {
		return nil, fmt.Errorf("invalid VM name: %w", err)
	}
	if req.VMNamespace == "" || req.VMUID == "" || !e.cfg.SourceNamespaceAllowed(req.VMNamespace) {
		return nil, fmt.Errorf("KubeVirt backup requires vm_namespace and stable vm_uid; refresh inventory")
	}

	if err := e.resources.AcquireBackupSlot(); err != nil {
		return nil, fmt.Errorf("no capacity: %w", err)
	}
	if req.BackupType != models.BackupTypeFull && req.BackupType != models.BackupTypeIncremental {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("KubeVirt backup type %q is unsupported; use full or incremental", req.BackupType)
	}

	s3Cfg := e.getS3Config()
	if s3Cfg == nil {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("S3 config not available (awaiting heartbeat)")
	}
	if e.cfg.ScratchPVC(req.VMNamespace) == "" {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("KubeVirt pull mode unavailable: KUBEVIRT_BACKUP_SCRATCH_PVC is required")
	}
	if !e.transactionMu.TryLock() {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("KubeVirt transaction active; retry after it finishes")
	}
	if !e.recovered {
		e.transactionMu.Unlock()
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("KubeVirt transaction recovery pending; inspect cleanup_required records and journal")
	}
	// A repeated delivery must not overwrite a terminal journal or reuse its
	// S3 prefix: subsequent compensation could otherwise erase committed data.
	if existing := e.GetProgress(req.BackupID); existing != nil {
		e.transactionMu.Unlock()
		e.resources.ReleaseBackupSlot()
		if existing.VMName == nil || *existing.VMName != req.VMName {
			return nil, fmt.Errorf("backup id already belongs to another VM; use a new backup id")
		}
		data, err := os.ReadFile(filepath.Join(e.transactionDir(), req.BackupID+".json"))
		var tx pullTransaction
		if err != nil || json.Unmarshal(data, &tx) != nil || tx.Namespace != req.VMNamespace || tx.VMUID != req.VMUID {
			return nil, fmt.Errorf("backup id has no matching stable VM identity; use a new backup id")
		}
		return existing, nil
	}

	now := time.Now().UTC()
	checkpointCommitted := false
	op := "creating incremental backup"
	if req.BackupType == models.BackupTypeFull {
		op = "creating full CBT seed"
	}
	progress := &models.BackupProgress{
		BackupID:            req.BackupID,
		Status:              models.TaskStatusRunning,
		VMName:              &req.VMName,
		ProgressPercent:     0,
		CurrentOperation:    &op,
		StartedAt:           &now,
		CheckpointCommitted: &checkpointCommitted,
	}

	ctx, cancel := context.WithCancel(context.Background())

	e.mu.Lock()
	e.jobs[req.BackupID] = progress
	e.cancels[req.BackupID] = cancel
	e.mu.Unlock()

	go e.runPullBackup(ctx, cancel, req, progress, s3Cfg)

	return progress, nil
}

func (e *Executor) StartUpload(backupID, outputPath string) (*models.BackupProgress, error) {
	return nil, backup.ErrUploadNotApplicable
}

func (e *Executor) GetProgress(backupID string) *models.BackupProgress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.jobs[backupID]
}

func (e *Executor) CancelBackup(backupID string) error {
	e.mu.RLock()
	cancel, ok := e.cancels[backupID]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("backup %s not found", backupID)
	}
	cancel()
	return nil
}

func (e *Executor) ActiveJobs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var ids []string
	for id, p := range e.jobs {
		if p.Status == models.TaskStatusRunning {
			ids = append(ids, id)
		}
	}
	return ids
}

func (e *Executor) ActiveCount() int {
	return e.resources.ActiveBackups()
}

// Compile-time check.
var _ backup.ExecutorIface = (*Executor)(nil)

var errVMIdentityChanged = errors.New("VM identity changed")

func (e *Executor) verifyVMIdentity(ctx context.Context, req *models.BackupRequest) error {
	if req.VMNamespace == "" || req.VMUID == "" || !e.cfg.SourceNamespaceAllowed(req.VMNamespace) {
		return fmt.Errorf("KubeVirt backup namespace/UID missing or outside agent scope")
	}
	vm, err := e.dynamic.Resource(kvtypes.VMResource).Namespace(req.VMNamespace).Get(ctx, req.VMName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read requested VM identity: %w", err)
	}
	if string(vm.GetUID()) != req.VMUID || vm.GetDeletionTimestamp() != nil {
		return fmt.Errorf("%w or is deleting; refresh inventory and request a new full baseline", errVMIdentityChanged)
	}
	return nil
}

// --- Helpers ---

func (e *Executor) setOp(p *models.BackupProgress, op string) {
	p.CurrentOperation = &op
}

func (e *Executor) fail(p *models.BackupProgress, req *models.BackupRequest, reason string) {
	p.Status = models.TaskStatusFailed
	p.ErrorMessage = &reason
	e.setOp(p, "failed")
	slog.Error("backup failed", "backup_id", req.BackupID, "reason", reason)
	e.emitEvent(req.BackupID, req.VMName, "failed", reason, p)
}

func (e *Executor) emitEvent(backupID, vmName, status, reason string, p *models.BackupProgress) {
	if e.onEvent == nil {
		return
	}
	event := map[string]interface{}{
		"type":       "backup_reconciled",
		"backup_id":  backupID,
		"vm_name":    vmName,
		"new_status": status,
		"old_status": "running",
		"reason":     reason,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	if p != nil && p.S3Location != nil {
		event["s3_location"] = *p.S3Location
	}
	if p != nil && p.CheckpointCommitted != nil {
		event["checkpoint_committed"] = *p.CheckpointCommitted
	}
	if p != nil && p.BytesTransferred > 0 {
		event["size_bytes"] = p.BytesTransferred
	}
	e.onEvent(event)
}
