package backup

import (
	"fmt"
	"path/filepath"
	"strings"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/security"
)

// BuildCommand constructs the virtnbdbackup command arguments.
func BuildCommand(cfg *config.Config, req *models.BackupRequest) ([]string, error) {
	// Validate inputs
	if err := security.ValidateVMName(req.VMName); err != nil {
		return nil, fmt.Errorf("invalid VM name: %w", err)
	}
	if err := security.ValidatePath(req.OutputPath); err != nil {
		return nil, fmt.Errorf("invalid output path: %w", err)
	}

	args := []string{
		"sudo",
		cfg.VirtnbdbackupPath,
		"-U", cfg.LibvirtURI,
		"--scratchdir", cfg.VirtnbdScratchDir,
		"-d", req.VMName,
		"-l", string(req.BackupType),
		"-o", req.OutputPath,
	}

	// Never pass -k or delete existing checkpoints: neither operation proves
	// ownership of the affected hypervisor job/checkpoint. This command builder
	// is retained for the mock path, not native production admission.

	// Include raw disks (copy mode) if requested
	if req.IncludeRaw {
		args = append(args, "--raw")
	}

	// Compression: -z <level> (e.g., "-z 9")
	if req.Compression != nil && *req.Compression != "" {
		if err := security.ValidateCompression(*req.Compression); err != nil {
			return nil, err
		}
		args = append(args, "-z", *req.Compression)
	}

	// Include disks: -i <disk1,disk2,...>
	if len(req.IncludeDisks) > 0 {
		for _, disk := range req.IncludeDisks {
			if err := security.ValidateDiskName(disk); err != nil {
				return nil, fmt.Errorf("invalid include disk: %w", err)
			}
		}
		args = append(args, "-i", strings.Join(req.IncludeDisks, ","))
	}

	// Exclude disks
	for _, disk := range req.ExcludeDisks {
		if err := security.ValidateDiskName(disk); err != nil {
			return nil, fmt.Errorf("invalid exclude disk: %w", err)
		}
		args = append(args, "-x", disk)
	}

	// Workers
	if req.Workers != nil && *req.Workers > 0 {
		if err := security.ValidateWorkers(*req.Workers); err != nil {
			return nil, err
		}
		args = append(args, "-w", fmt.Sprintf("%d", *req.Workers))
	}

	return args, nil
}

// WrapWithScript wraps a command with `script` for TTY simulation.
// virtnbdbackup uses tqdm for progress which requires a TTY.
// script -q -O <logfile> -c '<command>' captures the output.
func WrapWithScript(args []string, progressLog string) []string {
	// Build the inner command as a shell-safe string
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	innerCmd := strings.Join(quoted, " ")

	return []string{
		"script", "-q", "-e",
		"-O", progressLog,
		"-c", innerCmd,
	}
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " \t\n'\"\\$`!") {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}
	return s
}

// backupDataPatterns are file patterns for backup data files (plain and encrypted).
var backupDataPatterns = []string{
	"*.data", "*.data.enc",
	"*.raw", "*.raw.enc",
	"*.qcow2", "*.qcow2.enc",
	"*.img", "*.img.enc",
}

// ValidateOutput checks the backup output directory for expected files.
func ValidateOutput(outputPath string) (bool, string) {
	// Check for vmconfig*.xml
	matches, _ := filepath.Glob(filepath.Join(outputPath, "vmconfig*.xml"))
	if len(matches) == 0 {
		return false, "no vmconfig*.xml found"
	}

	// Check for backup data files (any supported format, plain or encrypted)
	for _, pattern := range backupDataPatterns {
		m, _ := filepath.Glob(filepath.Join(outputPath, pattern))
		if len(m) > 0 {
			return true, ""
		}
	}

	return false, "no backup data files found (.data, .raw, .qcow2, .img or encrypted variants)"
}

// SystemdUnitName returns the systemd scope unit name for a backup.
func SystemdUnitName(backupID string) string {
	// Must match Python exactly: vnbui-backup-{backup_id}.scope
	safe := strings.ReplaceAll(backupID, "/", "_")
	return fmt.Sprintf("vnbui-backup-%s", safe)
}
