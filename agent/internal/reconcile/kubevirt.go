//go:build kubevirt

package reconcile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"vnbui/agent/internal/config"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
)

// NewKubevirtReconciler returns a ReconcileFunc for KubeVirt agents.
func NewKubevirtReconciler(dynClient dynamic.Interface, namespace string) ReconcileFunc {
	return func(cfg *config.Config, client *http.Client, resMgr *resources.Manager) (*ReconcileResult, error) {
		result := &ReconcileResult{}
		prefix := cfg.KubevirtPrefix()
		if prefix == "" {
			return result, fmt.Errorf("invalid Kubernetes naming profile")
		}

		// HTTP transaction activation is still held. A current transaction journal
		// (including unreadable/uncertain custody) must never enter legacy
		// name/list-based orphan cleanup or missing-export failure synthesis.
		root := filepath.Join(filepath.Dir(cfg.KeyFilePath), "storage-transactions")
		journalDir, openErr := os.Open(root)
		held := openErr != nil && !os.IsNotExist(openErr)
		if openErr == nil {
			entries, readErr := journalDir.ReadDir(1)
			held = len(entries) != 0 || (readErr != nil && readErr != io.EOF)
			_ = journalDir.Close()
		}
		if held {
			slog.Warn("transaction journal retained; transaction activation held; legacy reconciliation refused")
			return result, nil
		}

		// 1. Get pending jobs from orchestrator (same as libvirt)
		pendingJobs, err := fetchPendingJobs(cfg, client)
		if err != nil {
			slog.Warn("could not fetch pending jobs", "error", err)
		}
		result.PendingJobs = len(pendingJobs)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Build a set of pending backup IDs for quick lookup
		pendingSet := make(map[string]bool)
		for _, job := range pendingJobs {
			pendingSet[job.BackupID] = true
		}

		// 2. Check VMExport CRs managed by vnbui
		exports, err := dynClient.Resource(kvtypes.ExportResource).Namespace(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=" + prefix,
		})
		if err != nil {
			slog.Warn("could not list VMExports", "error", err)
		}

		exportedBackupIDs := make(map[string]bool)
		if exports != nil {
			for _, exp := range exports.Items {
				name := exp.GetName()
				if !strings.HasPrefix(name, prefix+"-") {
					continue
				}
				backupID := extractBackupIDWithPrefix(name, prefix)
				exportedBackupIDs[backupID] = true

				if pendingSet[backupID] {
					result.Reconciled++
				} else {
					// Orphaned export — clean up
					vmName := extractVMNameFromSnapshot(dynClient, namespace, exp)
					slog.Info("cleaning up orphaned VMExport", "name", name, "backup_id", backupID)
					cleanupCR(dynClient, kvtypes.ExportResource, namespace, name)
					result.Orphans++
					result.Events = append(result.Events, map[string]interface{}{
						"type":       "orphan_detected",
						"backup_id":  backupID,
						"vm_name":    vmName,
						"new_status": "cleaned",
						"reason":     "orphaned VMExport cleaned up",
						"timestamp":  time.Now().UTC().Format(time.RFC3339),
					})
				}
			}
		}

		// 3. Mark pending jobs with no matching VMExport as failed (interrupted)
		for _, job := range pendingJobs {
			// Durable Pull transactions are reconciled by the executor after S3
			// configuration arrives. Export existence is not a commit verdict.
			if filepath.Base(job.BackupID) == job.BackupID {
				_, err := os.Stat(filepath.Join(filepath.Dir(cfg.KeyFilePath), "pull-transactions", job.BackupID+".json"))
				if err == nil || !os.IsNotExist(err) {
					continue
				}
			}
			if !exportedBackupIDs[job.BackupID] {
				result.Events = append(result.Events, map[string]interface{}{
					"type":                 "backup_reconciled",
					"backup_id":            job.BackupID,
					"vm_name":              job.VMName,
					"new_status":           "failed",
					"checkpoint_committed": false,
					"old_status":           job.Status,
					"reason":               "no active VMExport found (agent restart during backup)",
					"timestamp":            time.Now().UTC().Format(time.RFC3339),
				})
			}
		}

		// 4. Count managed snapshots
		snapshots, err := dynClient.Resource(kvtypes.SnapshotResource).Namespace(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=" + prefix,
		})
		if err != nil {
			slog.Warn("could not list VMSnapshots", "error", err)
		} else {
			result.RunningUnits = len(snapshots.Items)
		}

		slog.Info("kubevirt reconciliation complete",
			"pending_jobs", result.PendingJobs,
			"snapshots", result.RunningUnits,
			"orphans", result.Orphans,
			"reconciled", result.Reconciled,
		)

		return result, nil
	}
}

// extractBackupID extracts the backup ID from a vnbui CR name.
// Format: "vnbui-{backupID}" or "vnbui-{backupID}-export"
func extractBackupID(name string) string { return extractBackupIDWithPrefix(name, "vnbui") }
func extractBackupIDWithPrefix(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix+"-")
	name = strings.TrimSuffix(name, "-export")
	name = strings.TrimSuffix(name, "-export-token")
	return name
}

// extractVMNameFromSnapshot looks up the associated snapshot to find the VM name.
func extractVMNameFromSnapshot(dynClient dynamic.Interface, namespace string, export unstructured.Unstructured) string {
	snapshotName, _, _ := unstructured.NestedString(export.Object, "spec", "source", "name")
	if snapshotName == "" {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := dynClient.Resource(kvtypes.SnapshotResource).Namespace(namespace).Get(ctx, snapshotName, metav1.GetOptions{})
	if err != nil {
		return "unknown"
	}
	vmName, _, _ := unstructured.NestedString(snap.Object, "spec", "source", "name")
	if vmName == "" {
		return "unknown"
	}
	return vmName
}

func cleanupCR(dynClient dynamic.Interface, gvr schema.GroupVersionResource, namespace, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := dynClient.Resource(gvr).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		slog.Warn("failed to delete orphaned resource", "name", name, "error", err)
	}
}
