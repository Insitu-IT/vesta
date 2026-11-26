//go:build kubevirt

package kubevirt

import (
	"slices"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func (e *Executor) observeTransactionUpload(request *models.StorageTransactionRequest, p storageupload.UploadProgress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	operation, checkpoint, now := "uploading", false, time.Now().UTC()
	progress := &models.BackupProgress{BackupID: request.BackupID, VMName: &request.Plan.VMName,
		Status: models.TaskStatusRunning, CurrentOperation: &operation, StartedAt: &now,
		BytesTransferred: p.BytesTransferred, TotalBytes: &p.TotalBytes, CheckpointCommitted: &checkpoint}
	if previous := e.jobs[request.BackupID]; previous != nil {
		progress.StartedAt = previous.StartedAt
	}
	if p.TotalBytes > 0 {
		progress.ProgressPercent = min(99, int(100*float64(p.BytesTransferred)/float64(p.TotalBytes)))
	}
	// HTTP/heartbeat readers keep immutable pointers. No journal or network IO.
	e.jobs[request.BackupID] = progress
}

func (e *Executor) observeTransactionFinalizing(request *models.StorageTransactionRequest) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if previous := e.jobs[request.BackupID]; previous != nil {
		next := *previous
		operation := "finalizing"
		next.Status, next.CurrentOperation = models.TaskStatusRunning, &operation
		e.jobs[request.BackupID] = &next
	}
}

// StorageObservationEvents repeats current observations each heartbeat, so a
// lost delivery cannot leave an uploading backup pending indefinitely. Progress
// never confers receipt acceptance, checkpoint publication or capacity release.
func (e *Executor) StorageObservationEvents() []map[string]interface{} {
	return append(e.StorageHoldEvents(), e.StorageProgressEvents()...)
}

func (e *Executor) StorageProgressEvents() []map[string]interface{} {
	e.mu.RLock()
	r := e.storageRunner
	e.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0)
	for id, work := range r.work {
		if !work.finished && e.jobs[id] != nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return nil
	}
	start := 0
	for index, id := range ids {
		if id > r.progressCursor {
			start = index
			break
		}
	}
	events := make([]map[string]interface{}, 0, min(len(ids), 64))
	for index := 0; index < min(len(ids), 64); index++ {
		id := ids[(start+index)%len(ids)]
		request, p := r.work[id].request, e.jobs[id]
		phase := "preparing"
		if p.Status == models.TaskStatusPending {
			phase = "pending"
		}
		if p.CurrentOperation != nil && *p.CurrentOperation == "uploading" {
			phase = "uploading"
		}
		if p.CurrentOperation != nil && *p.CurrentOperation == "finalizing" {
			phase = "finalizing"
		}
		var total int64
		if p.TotalBytes != nil {
			total = *p.TotalBytes
		}
		events = append(events, map[string]interface{}{
			"type": "storage_transaction_progress", "schema": 1,
			"backup_id": id, "reservation_id": request.ReservationID, "plan_sha256": request.PlanSHA256,
			"phase": phase, "bytes_transferred": p.BytesTransferred, "total_bytes": total,
		})
		r.progressCursor = id
	}
	return events
}
