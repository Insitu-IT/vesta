//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// RetireStorageTransaction asks the backend for the exact reviewed DB release
// while the producer is excluded. Neither the inbound caller nor a stored
// agent-side value can supply a retirement proof.
func (e *Executor) RetireStorageTransaction(ctx context.Context, backupID, reservationID string) error {
	e.mu.RLock()
	r := e.storageRunner
	e.mu.RUnlock()
	if r == nil || ctx == nil {
		return storageupload.ErrHeld
	}
	r.executor.transactionMu.Lock()
	defer r.executor.transactionMu.Unlock()
	r.mu.Lock()
	work := r.work[backupID]
	if r.closed || r.ctx.Err() != nil || ctx.Err() != nil || work == nil ||
		!work.finished || !work.held || work.request.ReservationID != reservationID {
		r.mu.Unlock()
		return storageupload.ErrHeld
	}
	for _, queued := range r.queue {
		if queued == work {
			r.mu.Unlock()
			return storageupload.ErrHeld
		}
	}
	request := append([]byte(nil), work.body...)
	r.mu.Unlock()

	journalHash, err := storageupload.HeldJournalSHA256(r.root, request)
	if err != nil {
		return storageupload.ErrHeld
	}
	proof, err := r.retirementProof(ctx, work, journalHash)
	if err != nil || proof.JournalSHA256 != journalHash {
		return storageupload.ErrHeld
	}
	if err := storageupload.Retire(r.root, request, proof); err != nil {
		return storageupload.ErrHeld
	}
	r.mu.Lock()
	delete(r.work, backupID)
	r.mu.Unlock()
	return nil
}

func (r *transactionRunner) retirementProof(ctx context.Context, work *transactionWork, journalHash string) (storageupload.RetirementProof, error) {
	var empty storageupload.RetirementProof
	binding := map[string]string{
		"reservation_id": work.request.ReservationID,
		"attempt_id":     work.request.Plan.AttemptID,
		"plan_sha256":    work.request.PlanSHA256,
		"journal_sha256": journalHash,
	}
	body, err := json.Marshal(binding)
	if err != nil {
		return empty, storageupload.ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	endpoint := r.executor.cfg.OrchestratorURL + "/api/v1/agents/backups/" + url.PathEscape(work.request.BackupID) + "/storage-retirement"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil || r.key == "" {
		return empty, storageupload.ErrHeld
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", r.key)
	resp, err := r.backend.Do(req)
	if err != nil {
		return empty, storageupload.ErrHeld
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		return empty, storageupload.ErrHeld
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return empty, storageupload.ErrHeld
	}
	value, err := models.DecodeStorageControlJSON(data)
	if err != nil || len(value) != 10 {
		return empty, storageupload.ErrHeld
	}
	var proof storageupload.RetirementProof
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF ||
		proof.Schema != 1 || proof.OrgID != work.request.OrgID ||
		proof.BackupID != work.request.BackupID ||
		proof.ReservationID != work.request.ReservationID ||
		proof.AttemptID != work.request.Plan.AttemptID ||
		proof.PlanSHA256 != work.request.PlanSHA256 || proof.JournalSHA256 != journalHash {
		return empty, storageupload.ErrHeld
	}
	if proof.OperationID == "" || proof.CapacityID == "" || proof.ReleaseSHA256 == "" {
		return empty, errors.New("retirement proof incomplete")
	}
	return proof, nil
}
