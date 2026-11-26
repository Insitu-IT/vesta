package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// RunInScope starts a command via systemd-run --scope so it survives agent restart.
// systemd-run --scope returns immediately after creating the scope.
// Use WaitForUnit to poll until the unit completes.
func RunInScope(unitName string, args []string) *exec.Cmd {
	sysArgs := []string{
		"systemd-run",
		"--scope",
		"--unit=" + unitName,
		"--description=" + fmt.Sprintf("vnbui backup %s", unitName),
		"--property=KillMode=none",
		"--",
	}
	sysArgs = append(sysArgs, args...)

	cmd := exec.Command(sysArgs[0], sysArgs[1:]...)
	slog.Info("systemd-run scope", "unit", unitName, "cmd", strings.Join(args, " "))
	return cmd
}

// DiscoverRunningUnits finds surviving vnbui-backup-* systemd scopes.
func DiscoverRunningUnits() ([]string, error) {
	cmd := exec.Command("systemctl", "list-units", "--type=scope", "--no-legend", "--no-pager", "vnbui-backup-*")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list backup scopes: %w", err)
	}

	var units []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return units, nil
}

// WaitForUnit polls systemctl until the scope unit is no longer active.
// Returns nil when the unit finishes, or the context error if cancelled/timed out.
func WaitForUnit(ctx context.Context, unitName string, pollInterval time.Duration) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !UnitIsRunning(unitName) {
				return nil
			}
		}
	}
}

// CancelUnit stops a systemd scope unit.
func CancelUnit(unitName string) error {
	cmd := exec.Command("systemctl", "stop", unitName+".scope")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop %s: %w", unitName, err)
	}
	slog.Info("cancelled systemd scope", "unit", unitName)
	return nil
}

// UnitIsRunning checks if a systemd scope is active.
func UnitIsRunning(unitName string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", unitName+".scope")
	return cmd.Run() == nil
}
