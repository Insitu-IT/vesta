package reconcile

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/resources"
)

// ReconcileFunc is the type for provider-specific reconciliation.
// The libvirt reconciler retains uncertain attempts after losing observation.
// The kubevirt reconciler checks VMBackup CRDs.
type ReconcileFunc func(cfg *config.Config, client *http.Client, resMgr *resources.Manager) (*ReconcileResult, error)

// NewLibvirtReconciler returns a ReconcileFunc for libvirt agents.
func NewLibvirtReconciler(vmProvider provider.VMProvider) ReconcileFunc {
	return func(cfg *config.Config, client *http.Client, resMgr *resources.Manager) (*ReconcileResult, error) {
		return Reconcile(cfg, vmProvider, client, resMgr)
	}
}

// PendingJob represents a job the orchestrator thinks we're running.
type PendingJob struct {
	BackupID    string `json:"id"`
	VMName      string `json:"vm_name"`
	StoragePath string `json:"storage_path"`
	Status      string `json:"status"`
}

// pendingJobsResponse wraps the backend response format.
type pendingJobsResponse struct {
	Backups []PendingJob `json:"backups"`
}

// ReconcileResult summarizes what was found during reconciliation.
type ReconcileResult struct {
	PendingJobs  int
	RunningUnits int
	Reconciled   int
	Orphans      int
	Events       []map[string]interface{}
}

// Reconcile performs startup reconciliation:
// 1. GET /pending-jobs from orchestrator
// 2. Discover surviving systemd scopes
// 3. Cross-reference and generate events
func Reconcile(cfg *config.Config, vmProvider provider.VMProvider, client *http.Client, resMgr *resources.Manager) (*ReconcileResult, error) {
	result := &ReconcileResult{}

	// 1. Get pending jobs from orchestrator
	pendingJobs, err := fetchPendingJobs(cfg, client)
	if err != nil {
		slog.Warn("could not fetch pending jobs", "error", err)
		// Non-fatal: continue with local reconciliation
	}
	result.PendingJobs = len(pendingJobs)

	// 2. Discover running systemd units
	units, err := backup.DiscoverRunningUnits()
	if err != nil {
		slog.Warn("could not discover systemd units", "error", err)
	}
	result.RunningUnits = len(units)

	// Build set of running unit names
	runningUnits := make(map[string]bool)
	for _, unit := range units {
		runningUnits[unit] = true
	}

	// No libvirt public API supplies an attempt ID for the last completed job.
	// A scope name, current domain job, or output filename cannot recover the
	// uninterrupted observer's custody. Do not adopt or synthesize completion.
	for _, job := range pendingJobs {
		unitName := backup.SystemdUnitName(job.BackupID) + ".scope"
		delete(runningUnits, unitName) // Known name is diagnostic, not adoption.
		result.Events = append(result.Events, map[string]interface{}{
			"type": "backup_reconciled", "backup_id": job.BackupID,
			"new_status": "cleanup_required", "old_status": job.Status,
			"reason": "libvirt observer lost across restart; attempt remains uncertain; retain custody, checkpoints and output",
		})
		result.Reconciled++
	}

	// 4. Detect orphans: running units not in pending jobs
	for unit := range runningUnits {
		slog.Warn("reconcile: orphaned systemd unit",
			"unit", unit,
		)
		result.Orphans++
		result.Events = append(result.Events, map[string]interface{}{
			"type":   "orphan_detected",
			"unit":   unit,
			"action": "monitoring",
		})
	}

	slog.Info("reconciliation complete",
		"pending", result.PendingJobs,
		"running_units", result.RunningUnits,
		"reconciled", result.Reconciled,
		"orphans", result.Orphans,
		"events", len(result.Events),
	)

	return result, nil
}

func fetchPendingJobs(cfg *config.Config, client *http.Client) ([]PendingJob, error) {
	if cfg.AgentID == "" {
		return nil, fmt.Errorf("agent not registered (no agent_id)")
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/pending-jobs", cfg.OrchestratorURL, cfg.AgentID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Key", cfg.AgentAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var wrapper pendingJobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return wrapper.Backups, nil
}
