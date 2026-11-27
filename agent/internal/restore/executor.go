package restore

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"vnbui/agent/internal/config"
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

// StartRestore admits only the fresh native plan and its trusted receipt chain.
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
