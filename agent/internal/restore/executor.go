package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
)

// Executor manages restore job execution.
type Executor struct {
	cfg       *config.Config
	resources *resources.Manager

	mu   sync.RWMutex
	jobs map[string]*models.RestoreProgress

	onEvent func(map[string]interface{})
	fresh   *nativeRestoreRunner
}

// NewExecutor creates a restore executor.
func NewExecutor(cfg *config.Config, res *resources.Manager) *Executor {
	return &Executor{
		cfg:       cfg,
		resources: res,
		jobs:      make(map[string]*models.RestoreProgress),
		fresh:     newNativeRestoreRunner(cfg, res),
	}
}

// SetEventCallback sets a callback for restore lifecycle events.
func (e *Executor) SetEventCallback(cb func(map[string]interface{})) {
	e.onEvent = cb
}

func (e *Executor) emitEvent(restoreID, newStatus, reason string) {
	if e.onEvent == nil {
		return
	}
	e.onEvent(map[string]interface{}{
		"type":       "restore_" + newStatus,
		"restore_id": restoreID,
		"new_status": newStatus,
		"old_status": "running",
		"reason":     reason,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

// StartRestore begins a restore job.
func (e *Executor) StartRestore(req *models.RestoreRequest) (*models.RestoreProgress, error) {
	return e.fresh.start(req)
}

// GetProgress returns restore progress.
func (e *Executor) GetProgress(restoreID string) *models.RestoreProgress {
	return e.fresh.progress(restoreID)
}

// ActiveCount returns the number of active restores.
func (e *Executor) ActiveCount() int {
	return e.fresh.activeCount()
}

func (e *Executor) runRestore(req *models.RestoreRequest, progress *models.RestoreProgress) {
	defer e.resources.ReleaseRestoreSlot()

	backupDir := req.BackupPath

	// S3 chain download
	if req.Source == "s3" && req.ChainMembers != nil {
		e.setOperation(progress, "downloading from S3")

		s3Cfg, members, err := parseS3RestoreConfig(req)
		if err != nil {
			e.failRestore(progress, fmt.Sprintf("parse S3 config: %v", err))
			return
		}

		tempDir := fmt.Sprintf("%s/s3-restore-%s", e.cfg.BackupStoragePath, req.RestoreID)

		// Clean stale staging dir from a previous failed attempt
		if err := os.RemoveAll(tempDir); err != nil {
			slog.Warn("failed to clean stale staging dir", "path", tempDir, "error", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		memberFiles, err := DownloadChain(ctx, s3Cfg, members, tempDir)
		if err != nil {
			e.failRestore(progress, fmt.Sprintf("S3 download: %v", err))
			return
		}
		backupDir = tempDir
		defer func() {
			if rmErr := os.RemoveAll(tempDir); rmErr != nil {
				slog.Warn("failed to clean up S3 staging dir", "path", tempDir, "error", rmErr)
			} else {
				slog.Info("cleaned up S3 staging dir", "path", tempDir)
			}
		}()

		// Per-member decryption for S3 chain restores —
		// each member may have a different key, so only decrypt that member's files
		for _, member := range members {
			if member.EncryptionKey != "" {
				key, err := encryption.DeriveKey(member.EncryptionKey, member.EncryptionType)
				if err != nil {
					e.failRestore(progress, fmt.Sprintf("derive key for member %s: %v", member.BackupID, err))
					return
				}
				if err := encryption.DecryptFiles(backupDir, key, memberFiles[member.BackupID]); err != nil {
					e.failRestore(progress, fmt.Sprintf("decrypt member %s: %v", member.BackupID, err))
					return
				}
			}
		}
	}

	// Local decryption (non-S3)
	if req.Source != "s3" && req.EncryptionType != nil && *req.EncryptionType != "none" {
		e.setOperation(progress, "decrypting")

		// Validate key hash if provided
		if req.EncryptionKeyHash != nil && *req.EncryptionKeyHash != "" && req.EncryptionKey != nil {
			hash := sha256.Sum256([]byte(*req.EncryptionKey))
			hashHex := hex.EncodeToString(hash[:])
			expected := *req.EncryptionKeyHash
			if len(expected) > len(hashHex) || hashHex[:len(expected)] != expected {
				e.failRestore(progress, "encryption key hash mismatch")
				return
			}
		}

		if req.EncryptionKey != nil {
			key, err := encryption.DeriveKey(*req.EncryptionKey, string(*req.EncryptionType))
			if err != nil {
				e.failRestore(progress, fmt.Sprintf("derive key: %v", err))
				return
			}

			if err := encryption.DecryptDirectory(backupDir, key); err != nil {
				e.failRestore(progress, fmt.Sprintf("decrypt: %v", err))
				return
			}
		}
	}

	// Create restore output directory (not needed for verify/dump)
	if req.Action != "verify" && req.Action != "dump" {
		if err := os.MkdirAll(req.RestorePath, 0o755); err != nil {
			e.failRestore(progress, fmt.Sprintf("create restore dir: %v", err))
			return
		}
	}

	// Run virtnbdrestore
	e.setOperation(progress, "restoring")
	progress.ProgressPercent = 50

	args, err := BuildCommand(e.cfg, req.RestorePath, req, backupDir)
	if err != nil {
		e.failRestore(progress, fmt.Sprintf("build command: %v", err))
		return
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		e.failRestore(progress, fmt.Sprintf("virtnbdrestore failed: %v", err))
		return
	}

	// Complete
	op := "completed"
	progress.Status = models.TaskStatusCompleted
	progress.ProgressPercent = 100
	progress.CurrentOperation = &op
	metrics.BackupOperationsTotal.WithLabelValues("completed", "restore").Inc()

	slog.Info("restore completed", "restore_id", req.RestoreID)
	e.emitEvent(req.RestoreID, "completed", "restore completed successfully")
}

func (e *Executor) setOperation(progress *models.RestoreProgress, op string) {
	progress.CurrentOperation = &op
}

func (e *Executor) failRestore(progress *models.RestoreProgress, errMsg string) {
	progress.Status = models.TaskStatusFailed
	progress.ErrorMessage = &errMsg
	metrics.OperationErrorsTotal.WithLabelValues("restore", "error").Inc()
	slog.Error("restore failed", "restore_id", progress.RestoreID, "error", errMsg)
	e.emitEvent(progress.RestoreID, "failed", errMsg)
}

func parseS3RestoreConfig(req *models.RestoreRequest) (S3Config, []ChainMember, error) {
	if req.S3Config == nil {
		return S3Config{}, nil, fmt.Errorf("s3_config is required for S3 restore")
	}

	cfg := S3Config{}
	if v, ok := req.S3Config["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	if v, ok := req.S3Config["bucket"].(string); ok {
		cfg.Bucket = v
	}
	if v, ok := req.S3Config["region"].(string); ok {
		cfg.Region = v
	}
	if v, ok := req.S3Config["access_key"].(string); ok {
		cfg.AccessKey = v
	}
	if v, ok := req.S3Config["secret_key"].(string); ok {
		cfg.SecretKey = v
	}

	// minio-go expects bare host:port, not a URL with scheme
	if strings.HasPrefix(cfg.Endpoint, "https://") {
		cfg.Endpoint = strings.TrimPrefix(cfg.Endpoint, "https://")
		cfg.UseSSL = true
	} else if strings.HasPrefix(cfg.Endpoint, "http://") {
		cfg.Endpoint = strings.TrimPrefix(cfg.Endpoint, "http://")
	}

	var members []ChainMember
	for _, m := range req.ChainMembers {
		member := ChainMember{}
		if v, ok := m["backup_id"].(string); ok {
			member.BackupID = v
		}
		if v, ok := m["s3_prefix"].(string); ok {
			member.S3Prefix = v
		}
		if v, ok := m["chain_position"].(float64); ok {
			member.ChainPosition = int(v)
		}
		if v, ok := m["encryption_key"].(string); ok {
			member.EncryptionKey = v
		}
		if v, ok := m["encryption_type"].(string); ok {
			member.EncryptionType = v
		}
		members = append(members, member)
	}

	return cfg, members, nil
}
