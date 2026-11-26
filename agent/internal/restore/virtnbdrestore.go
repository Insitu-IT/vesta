package restore

import (
	"fmt"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/security"
)

// BuildCommand constructs the virtnbdrestore command arguments.
func BuildCommand(cfg *config.Config, restorePath string, req *models.RestoreRequest, backupDir string) ([]string, error) {
	if err := security.ValidatePath(backupDir); err != nil {
		return nil, fmt.Errorf("invalid backup path: %w", err)
	}

	args := []string{
		"sudo",
		cfg.VirtnbdrestorePath,
		"-U", cfg.LibvirtURI,
		"-i", backupDir,
	}

	// For verify/dump, -o takes the action name; for restore, -o takes the path
	if req.Action == "verify" || req.Action == "dump" {
		args = append(args, "-o", req.Action)
	} else {
		if err := security.ValidatePath(restorePath); err != nil {
			return nil, fmt.Errorf("invalid restore path: %w", err)
		}
		args = append(args, "-o", restorePath)
	}

	// Selected disks
	for _, disk := range req.SelectedDisks {
		if err := security.ValidateDiskName(disk); err != nil {
			return nil, fmt.Errorf("invalid selected disk: %w", err)
		}
		args = append(args, "-d", disk)
	}

	// Point-in-time restore
	if req.UntilCheckpoint != nil && *req.UntilCheckpoint != "" {
		if err := security.ValidateCheckpointName(*req.UntilCheckpoint); err != nil {
			return nil, err
		}
		args = append(args, "-u", *req.UntilCheckpoint)
	}

	// Target VM name
	if req.TargetName != nil && *req.TargetName != "" {
		if err := security.ValidateTargetName(*req.TargetName); err != nil {
			return nil, err
		}
		args = append(args, "-N", *req.TargetName)
	}

	// Auto-define VM
	if req.AutoDefine {
		args = append(args, "-D")
	}

	// Adjust config
	if req.AdjustConfig {
		args = append(args, "-c")
	}

	return args, nil
}
