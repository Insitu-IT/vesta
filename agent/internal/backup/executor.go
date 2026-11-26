package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
)

// Executor manages backup job execution and progress tracking.
type Executor struct {
	cfg       *config.Config
	resources *resources.Manager

	mu      sync.RWMutex
	jobs    map[string]*models.BackupProgress
	cancels map[string]context.CancelFunc

	s3mu     sync.RWMutex
	s3Config *S3Config

	onEvent      func(map[string]interface{})
	nativeRunner *nativeRunner
}

// NewExecutor creates a backup executor.
func NewExecutor(cfg *config.Config, res *resources.Manager) *Executor {
	return &Executor{
		cfg:       cfg,
		resources: res,
		jobs:      make(map[string]*models.BackupProgress),
		cancels:   make(map[string]context.CancelFunc),
	}
}

// SetEventCallback sets a callback for backup lifecycle events (completion, failure, cancel).
func (e *Executor) SetEventCallback(cb func(map[string]interface{})) {
	e.onEvent = cb
}

func (e *Executor) emitEvent(backupID, vmName, newStatus, reason string, progress *models.BackupProgress) {
	if e.onEvent == nil {
		return
	}
	event := map[string]interface{}{
		"type":       "backup_reconciled",
		"backup_id":  backupID,
		"vm_name":    vmName,
		"new_status": newStatus,
		"old_status": "running",
		"reason":     reason,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	if progress != nil {
		if progress.S3Location != nil {
			event["s3_location"] = *progress.S3Location
		}
		if progress.BytesTransferred > 0 {
			event["size_bytes"] = progress.BytesTransferred
		}
	}
	e.onEvent(event)
}

// SetS3Config updates the S3 configuration (called from heartbeat response).
func (e *Executor) SetS3Config(raw map[string]interface{}) {
	cfg, err := ParseS3Config(raw)
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

	// Only log when config actually changes
	if e.s3Config == nil || e.s3Config.Endpoint != cfg.Endpoint || e.s3Config.Bucket != cfg.Bucket {
		slog.Info("S3 config updated", "endpoint", cfg.Endpoint, "bucket", cfg.Bucket, "ssl", cfg.UseSSL)
	}
	e.s3Config = cfg
}

func (e *Executor) getS3Config() *S3Config {
	e.s3mu.RLock()
	defer e.s3mu.RUnlock()
	return e.s3Config
}

// StartBackup begins a backup job in a goroutine.
func (e *Executor) StartBackup(req *models.BackupRequest) (*models.BackupProgress, error) {
	// virtnbdbackup pull-mode cleanup aborts the domain's current job. That is
	// not safe when another VM-changing client may have replaced it. Native
	// production is admitted through RunNativePush with an attempt-bound source,
	// never this old path-only request (the mock remains useful for development).
	if !e.cfg.MockVirtnbdbackup {
		return nil, fmt.Errorf("libvirt requires an attempt-bound native push request; path-only backup execution is not supported")
	}
	// Check capacity
	if err := e.resources.AcquireBackupSlot(); err != nil {
		return nil, fmt.Errorf("no capacity: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(req.OutputPath, 0o755); err != nil {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	// Build command
	args, err := BuildCommand(e.cfg, req)
	if err != nil {
		e.resources.ReleaseBackupSlot()
		return nil, fmt.Errorf("build command: %w", err)
	}

	// Create progress tracker
	unitName := SystemdUnitName(req.BackupID)
	progress := NewRunningProgress(req.BackupID, req.VMName, unitName, req.OutputPath)

	// No global timeout — stall detection in runScope() (15min no progress)
	// and per-file S3 timeouts handle hangs. Cancel func still works for
	// user-initiated cancellation.
	ctx, cancel := context.WithCancel(context.Background())

	e.mu.Lock()
	e.jobs[req.BackupID] = progress
	e.cancels[req.BackupID] = cancel
	e.mu.Unlock()

	// Run in goroutine
	go e.runBackup(ctx, cancel, req, args, progress)

	return progress, nil
}

// GetProgress returns the current progress for a backup.
func (e *Executor) GetProgress(backupID string) *models.BackupProgress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.jobs[backupID]
}

// CancelBackup cancels a running backup.
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

// StartUpload begins an S3 upload for an existing local backup.
// Triggered by the backend as a separate phase after backup+encrypt completes.
func (e *Executor) StartUpload(backupID, outputPath string) (*models.BackupProgress, error) {
	if !e.cfg.MockVirtnbdbackup {
		return nil, fmt.Errorf("native upload requires its durable closed-file admission; path-only retries are unsupported")
	}
	s3Cfg := e.getS3Config()
	if s3Cfg == nil {
		return nil, fmt.Errorf("S3 not configured")
	}

	// Check output path exists
	if _, err := os.Stat(outputPath); err != nil {
		return nil, fmt.Errorf("backup output not found: %s", outputPath)
	}

	// Check for existing active job for this backup
	e.mu.RLock()
	existing := e.jobs[backupID]
	e.mu.RUnlock()
	if existing != nil && existing.Status == models.TaskStatusRunning {
		return nil, fmt.Errorf("job already running for %s", backupID)
	}

	progress := &models.BackupProgress{
		BackupID:        backupID,
		Status:          models.TaskStatusRunning,
		StoragePath:     &outputPath,
		ProgressPercent: 0,
	}
	op := "uploading to S3"
	progress.CurrentOperation = &op

	ctx, cancel := context.WithCancel(context.Background())

	e.mu.Lock()
	e.jobs[backupID] = progress
	e.cancels[backupID] = cancel
	e.mu.Unlock()

	go e.runUpload(ctx, cancel, backupID, outputPath, s3Cfg, progress)

	return progress, nil
}

func (e *Executor) runUpload(ctx context.Context, cancel context.CancelFunc, backupID string, outputPath string, s3Cfg *S3Config, progress *models.BackupProgress) {
	defer cancel()
	uploadStart := time.Now()

	slog.Info("starting S3 upload", "backup_id", backupID, "bucket", s3Cfg.Bucket)

	// Progress callback — updates progress per-part for real-time reporting
	onProgress := func(completedBytes, totalBytes int64) {
		progress.BytesTransferred = completedBytes
		if totalBytes > 0 {
			progress.ProgressPercent = int(completedBytes * 100 / totalBytes)
		}
	}

	s3Location, err := UploadToS3(ctx, *s3Cfg, outputPath, backupID, onProgress)
	if err != nil {
		msg := fmt.Sprintf("[uploading to S3, %d%%] S3 upload paused (resumable): %v", progress.ProgressPercent, err)
		progress.Status = models.TaskStatusFailed
		progress.ErrorMessage = &msg
		slog.Error("S3 upload failed (resumable)", "backup_id", backupID, "error", err,
			"bytes_uploaded", progress.BytesTransferred)
		e.emitEvent(backupID, "", "upload_failed", msg, nil)
		return
	}

	slog.Info("uploaded to S3", "backup_id", backupID, "location", s3Location)
	progress.S3Location = &s3Location

	metrics.BackupPhaseDuration.WithLabelValues("upload").Observe(time.Since(uploadStart).Seconds())

	// Final size from metadata if available
	meta, _ := ParseMetadata(outputPath)
	if meta != nil && meta.TotalSizeBytes > progress.BytesTransferred {
		progress.BytesTransferred = meta.TotalSizeBytes
	}

	// Clean up local data files, keep metadata for chains
	if s3Cfg.DeleteLocal {
		os.RemoveAll(outputPath)
	} else {
		cleanupDataFiles(outputPath)
	}

	progress.Status = models.TaskStatusCompleted
	progress.ProgressPercent = 100

	metrics.BackupOperationsTotal.WithLabelValues("uploaded", "s3").Inc()
	slog.Info("S3 upload completed", "backup_id", backupID, "location", s3Location)

	e.emitEvent(backupID, "", "completed", "S3 upload completed", progress)
}

// ActiveJobs returns backup IDs of all active jobs.
func (e *Executor) ActiveJobs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ids := make([]string, 0, len(e.jobs))
	for id, p := range e.jobs {
		if p.Status == models.TaskStatusRunning {
			ids = append(ids, id)
		}
	}
	return ids
}

// ActiveCount returns the number of active backups.
func (e *Executor) ActiveCount() int {
	return e.resources.ActiveBackups()
}

func (e *Executor) runBackup(ctx context.Context, cancel context.CancelFunc, req *models.BackupRequest, args []string, progress *models.BackupProgress) {
	defer cancel()
	defer e.resources.ReleaseBackupSlot()

	startTime := time.Now()
	unitName := SystemdUnitName(req.BackupID)

	slog.Info("starting backup",
		"backup_id", req.BackupID,
		"vm", req.VMName,
		"type", req.BackupType,
		"unit", unitName,
	)

	// For incremental/differential, symlink parent backup's metadata into output dir
	// so virtnbdbackup can find the previous backup's checkpoints and config
	if req.ParentPath != nil && *req.ParentPath != "" && req.BackupType != models.BackupTypeFull {
		if err := symlinkParentMetadata(*req.ParentPath, req.OutputPath); err != nil {
			e.failBackup(progress, fmt.Sprintf("prepare incremental: %v", err))
			return
		}
	}

	// Wrap with script for TTY simulation (tqdm progress capture)
	progressLog := filepath.Join(req.OutputPath, "progress.log")
	scriptArgs := WrapWithScript(args, progressLog)

	hasEncryption := req.EncryptionType != models.EncryptionTypeNone && req.EncryptionKey != nil && *req.EncryptionKey != ""
	hasS3 := e.getS3Config() != nil

	setOp := func(op string) {
		progress.CurrentOperation = &op
	}

	// Scale tqdm 0-100 → appropriate range based on post-backup stages
	maxBackupPct := 100
	if hasEncryption && hasS3 {
		maxBackupPct = 70
	} else if hasEncryption || hasS3 {
		maxBackupPct = 80
	}

	setOp("backing up")
	phaseStart := time.Now()

	// Run backup in systemd scope with progress monitoring
	err := e.runScope(ctx, unitName, scriptArgs, progressLog, progress, maxBackupPct)
	if err != nil {
		if ctx.Err() != nil {
			e.cancelBackup(progress)
			return
		}
		e.failBackup(progress, fmt.Sprintf("backup failed: %v; no foreign-job cancellation or retry was attempted", err))
		return
	}

	// Validate output
	setOp("validating")
	valid, reason := ValidateOutput(req.OutputPath)
	if !valid {
		// Include progress log content (virtnbdbackup stderr) in the error
		detail := reason
		if logData, logErr := os.ReadFile(progressLog); logErr == nil && len(logData) > 0 {
			tail := string(logData)
			if len(tail) > 2000 {
				tail = tail[len(tail)-2000:]
			}
			detail = fmt.Sprintf("%s\n--- virtnbdbackup output ---\n%s", reason, tail)
		}
		e.failBackup(progress, fmt.Sprintf("output validation failed: %s", detail))
		metrics.OperationErrorsTotal.WithLabelValues("backup", "validation").Inc()
		return
	}

	metrics.BackupPhaseDuration.WithLabelValues("backup").Observe(time.Since(phaseStart).Seconds())

	// Clean up progress log and parent symlinks (not needed in final backup output)
	if err := os.Remove(progressLog); err != nil && !os.IsNotExist(err) {
		slog.Debug("failed to remove progress log", "error", err)
	}
	cleanupParentSymlinks(req.OutputPath)

	// Parse metadata
	meta, err := ParseMetadata(req.OutputPath)
	if err != nil {
		slog.Warn("metadata parse error (non-fatal)", "error", err)
	}

	// Encrypt backup files if requested
	if hasEncryption {
		setOp("encrypting")
		phaseStart = time.Now()
		encPctStart := maxBackupPct
		progress.ProgressPercent = encPctStart
		slog.Info("encrypting backup", "backup_id", req.BackupID, "type", req.EncryptionType)

		key, err := encryption.DeriveKey(*req.EncryptionKey, string(req.EncryptionType))
		if err != nil {
			e.failBackup(progress, fmt.Sprintf("derive encryption key: %v", err))
			return
		}
		if err := encryption.EncryptDirectory(ctx, req.OutputPath, key); err != nil {
			e.failBackup(progress, fmt.Sprintf("encrypt backup: %v", err))
			return
		}
		metrics.BackupPhaseDuration.WithLabelValues("encrypt").Observe(time.Since(phaseStart).Seconds())
		if hasS3 {
			progress.ProgressPercent = 85
		} else {
			progress.ProgressPercent = 95
		}
		slog.Info("backup encrypted", "backup_id", req.BackupID)
	}

	// Re-parse metadata after encryption to get actual file sizes
	if hasEncryption {
		if postMeta, err := ParseMetadata(req.OutputPath); err == nil {
			meta = postMeta
		}
	}

	duration := time.Since(startTime).Seconds()

	// Calculate final backup size
	var sizeBytes int64
	if meta != nil {
		sizeBytes = meta.TotalSizeBytes
		metrics.BackupSizeBytes.WithLabelValues(string(req.BackupType)).Observe(float64(sizeBytes))
	}
	progress.BytesTransferred = sizeBytes

	// Mark complete — backup + encryption done, local data ready.
	// S3 upload is a separate phase triggered by the backend.
	progress.Status = models.TaskStatusCompleted
	progress.ProgressPercent = 100

	// Record metrics
	metrics.BackupOperationsTotal.WithLabelValues("completed", string(req.BackupType)).Inc()
	metrics.BackupDurationSeconds.WithLabelValues(string(req.BackupType)).Observe(duration)

	slog.Info("backup completed",
		"backup_id", req.BackupID,
		"vm", req.VMName,
		"duration_s", int(duration),
		"size_bytes", sizeBytes,
	)

	e.emitEvent(req.BackupID, req.VMName, "completed", fmt.Sprintf("completed in %ds", int(duration)), progress)
}

// runScope starts a command in a systemd scope, monitors progress, and waits.
// Returns nil on success, or an error (including stall/context errors).
func (e *Executor) runScope(ctx context.Context, unitName string, scriptArgs []string, progressLog string, progress *models.BackupProgress, maxPct int) error {
	cmd := RunInScope(unitName, scriptArgs)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Use Start() — systemd-run --scope blocks in foreground, so we wait in a goroutine
	// to allow MonitorProgress to run concurrently
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start scope: %w", err)
	}

	cmdDone := make(chan error, 1)
	go func() { cmdDone <- cmd.Wait() }()

	// Monitor progress log (written by script -O) concurrently
	stall := NewStallDetector(15 * time.Minute)
	progressDone := MonitorProgress(progressLog, 2*time.Second, func(pct int) {
		// Scale tqdm 0-100 to 0-maxPct
		progress.ProgressPercent = pct * maxPct / 100
		stall.Activity()
	})

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(progressDone)
			_ = cmd.Process.Kill()
			return ctx.Err()
		case err := <-cmdDone:
			close(progressDone)
			return err
		case <-ticker.C:
			if stall.IsStalled() {
				close(progressDone)
				_ = cmd.Process.Kill()
				metrics.OperationErrorsTotal.WithLabelValues("backup", "stall").Inc()
				return fmt.Errorf("backup stalled: no progress for 15 minutes")
			}
		}
	}
}

func (e *Executor) failBackup(progress *models.BackupProgress, errMsg string) {
	// Enrich error with stage and progress context so the user doesn't
	// need to investigate to understand what happened.
	stage := "unknown stage"
	if progress.CurrentOperation != nil {
		stage = *progress.CurrentOperation
	}
	enriched := fmt.Sprintf("[%s, %d%%] %s", stage, progress.ProgressPercent, errMsg)

	progress.Status = models.TaskStatusFailed
	progress.ErrorMessage = &enriched
	metrics.BackupOperationsTotal.WithLabelValues("failed", stage).Inc()
	slog.Error("backup failed", "backup_id", progress.BackupID, "stage", stage, "progress", progress.ProgressPercent, "error", errMsg)

	vmName := ""
	if progress.VMName != nil {
		vmName = *progress.VMName
	}
	e.emitEvent(progress.BackupID, vmName, "failed", enriched, nil)

	// Failure does not establish that a hypervisor writer has stopped. Keep
	// the exact attempt directory; cleanup needs separate custody resolution.
}

// cleanupDataFiles deletes large data files from a backup output dir,
// keeping metadata (checkpoints, vmconfig, cpt, log, qcow.json) for
// incremental chain continuity.
func cleanupDataFiles(outputPath string) {
	entries, err := os.ReadDir(outputPath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for _, suffix := range backupDataPatterns {
			pattern := strings.TrimPrefix(suffix, "*")
			if strings.HasSuffix(name, pattern) {
				path := filepath.Join(outputPath, name)
				if rmErr := os.Remove(path); rmErr != nil {
					slog.Warn("failed to remove data file", "file", name, "error", rmErr)
				} else {
					slog.Info("cleaned up local data file after S3 upload", "file", name)
				}
				break
			}
		}
	}
}

// isActiveBlockJobError checks the progress log for active block job errors.
func isActiveBlockJobError(progressLog string) bool {
	data, err := os.ReadFile(progressLog)
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "active block job") ||
		strings.Contains(content, "block copy job") ||
		strings.Contains(content, "blockjob")
}

func (e *Executor) cancelBackup(progress *models.BackupProgress) {
	msg := "cancelled by user"
	progress.Status = models.TaskStatusCancelled
	progress.ErrorMessage = &msg
	metrics.BackupOperationsTotal.WithLabelValues("cancelled", "unknown").Inc()
	slog.Info("backup cancelled", "backup_id", progress.BackupID)

	vmName := ""
	if progress.VMName != nil {
		vmName = *progress.VMName
	}
	e.emitEvent(progress.BackupID, vmName, "cancelled", "cancelled by user", nil)

	// Do not delete files that may still belong to a surviving producer.
}

// NewRunningProgress creates a BackupProgress for a new backup.
func NewRunningProgress(backupID, vmName, systemdUnit, storagePath string) *models.BackupProgress {
	now := time.Now().UTC()
	progressLog := filepath.Join(storagePath, "progress.log")
	return &models.BackupProgress{
		BackupID:        backupID,
		Status:          models.TaskStatusRunning,
		VMName:          &vmName,
		SystemdUnit:     &systemdUnit,
		StoragePath:     &storagePath,
		ProgressLogPath: &progressLog,
		StartedAt:       &now,
	}
}
