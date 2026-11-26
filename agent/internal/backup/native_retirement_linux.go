//go:build linux

package backup

import (
	"context"
	"encoding/json"
	"path/filepath"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// RetireStorageTransaction consumes an independently recorded owner release.
// It never changes libvirt checkpoints, deletes payloads or releases capacity.
func (e *Executor) RetireStorageTransaction(ctx context.Context, backup, attempt string) error {
	e.mu.RLock()
	r := e.nativeRunner
	e.mu.RUnlock()
	if r == nil || ctx == nil || ctx.Err() != nil {
		return storageupload.ErrHeld
	}
	r.transactionMu.Lock()
	defer r.transactionMu.Unlock()
	r.mu.Lock()
	w := r.work[backup]
	if r.closed || r.ctx.Err() != nil || w == nil || !w.finished || !w.held || w.request.Intent.AttemptID != attempt {
		r.mu.Unlock()
		return storageupload.ErrHeld
	}
	for _, queued := range r.queue {
		if queued == w {
			r.mu.Unlock()
			return storageupload.ErrHeld
		}
	}
	i := w.request.Intent
	r.mu.Unlock()
	root := filepath.Join(r.root, "uploads")
	identity, err := storageupload.NativeHeldJournalIdentity(root, attempt, i.OrgID, i.AgentID, backup)
	if err != nil {
		return storageupload.ErrHeld
	}
	body, err := json.Marshal(map[string]string{
		"reservation_id": identity.ReservationID, "attempt_id": identity.AttemptID,
		"plan_sha256": identity.PlanSHA256, "journal_sha256": identity.JournalSHA256,
	})
	if err != nil {
		return storageupload.ErrHeld
	}
	credential := func(context.Context) (string, error) { return e.cfg.AgentAPIKey, nil }
	response, err := storageupload.RequestNativeRetirementProof(ctx, e.cfg.OrchestratorURL, backup, body, r.backend, credential)
	if err != nil {
		return storageupload.ErrHeld
	}
	var proof storageupload.RetirementProof
	if models.DecodeStorageValue(response, &proof, 4096) != nil || proof.Schema != 1 ||
		proof.OrgID != identity.OrgID || proof.BackupID != identity.BackupID ||
		proof.ReservationID != identity.ReservationID || proof.AttemptID != identity.AttemptID ||
		proof.PlanSHA256 != identity.PlanSHA256 || proof.JournalSHA256 != identity.JournalSHA256 {
		return storageupload.ErrHeld
	}
	if err := storageupload.RetireNativeFileSet(root, attempt, proof); err != nil {
		return storageupload.ErrHeld
	}
	r.mu.Lock()
	delete(r.work, backup)
	r.mu.Unlock()
	return nil
}
