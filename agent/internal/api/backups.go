package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/models"
)

// BackupHandler handles backup API endpoints.
type BackupHandler struct {
	executor                  backup.ExecutorIface
	storageTransactionsSecure bool
}

type storageTransactionExecutor interface {
	StartStorageTransaction(context.Context, []byte) error
}

type storageRetirementExecutor interface {
	RetireStorageTransaction(context.Context, string, string) error
}

// RetireStorageTransaction handles an explicit operator-triggered retirement.
// Its input is an identity only; the agent fetches proof from the backend.
func (h *BackupHandler) RetireStorageTransaction(w http.ResponseWriter, r *http.Request) {
	executor, supported := h.executor.(storageRetirementExecutor)
	if !supported || !h.storageTransactionsSecure || r.TLS == nil {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "retirement requires authenticated HTTPS"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2049))
	if err != nil || len(body) > 2048 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid retirement request"})
		return
	}
	value, err := models.DecodeStorageControlJSON(body)
	if err != nil || len(value) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid retirement request"})
		return
	}
	reservation, ok := value["reservation_id"].(string)
	if !ok || reservation == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid retirement request"})
		return
	}
	id := chi.URLParam(r, "id")
	if err := executor.RetireStorageTransaction(r.Context(), id, reservation); err != nil {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "reviewed retirement unavailable; retain journal"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "retired", "backup_id": id, "reservation_id": reservation})
}

type nativeJobExecutor interface {
	StartNativeJob(context.Context, []byte) error
}

// NewBackupHandler creates a backup handler.
func NewBackupHandler(executor backup.ExecutorIface) *BackupHandler {
	return &BackupHandler{executor: executor}
}

// StartBackup handles POST /api/backups.
func (h *BackupHandler) StartBackup(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, models.MaxStorageRequestBytes+1))
	if err != nil || len(body) > models.MaxStorageRequestBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid backup request"})
		return
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid backup request"})
		return
	}
	if _, transaction := envelope["protocol"]; transaction {
		var protocol string
		_ = json.Unmarshal(envelope["protocol"], &protocol)
		if protocol == "vnbui-native-job/1" {
			request, err := backup.DecodeNativeJob(body)
			if err != nil {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"detail": "invalid native intent"})
				return
			}
			executor, supported := h.executor.(nativeJobExecutor)
			if !supported || !h.storageTransactionsSecure || r.TLS == nil {
				writeJSON(w, http.StatusLocked, map[string]string{"detail": "native push requires authenticated HTTPS"})
				return
			}
			if err := executor.StartNativeJob(r.Context(), body); err != nil {
				writeJSON(w, http.StatusLocked, map[string]string{"detail": "native intent not admitted; retain custody"})
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "backup_id": request.Intent.BackupID, "attempt_id": request.Intent.AttemptID, "intent_sha256": request.IntentSHA256})
			return
		}
		request, err := models.DecodeStorageTransaction(body)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"detail": "unsupported or malformed storage transaction"})
			return
		}
		executor, supported := h.executor.(storageTransactionExecutor)
		if !supported || !h.storageTransactionsSecure || r.TLS == nil {
			writeJSON(w, http.StatusLocked, map[string]string{"detail": "storage transactions require the authenticated HTTPS agent API"})
			return
		}
		if err := executor.StartStorageTransaction(r.Context(), body); err != nil {
			writeJSON(w, http.StatusLocked, map[string]string{"detail": "storage transaction not admitted; retain its reservation for reconciliation"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status": "accepted", "backup_id": request.BackupID,
			"reservation_id": request.ReservationID, "plan_sha256": request.PlanSHA256,
		})
		return
	}
	var req models.BackupRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"detail": "invalid backup request",
		})
		return
	}
	if _, transactional := h.executor.(storageTransactionExecutor); transactional {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "this provider requires a storage transaction request"})
		return
	}

	if req.EncryptionKey != nil && *req.EncryptionKey != "" && (!h.storageTransactionsSecure || r.TLS == nil) {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "backup credentials require authenticated HTTPS"})
		return
	}
	progress, err := h.executor.StartBackup(&req)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "no capacity" {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusAccepted, progress)
}

// GetBackup handles GET /api/backups/{id}.
func (h *BackupHandler) GetBackup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	progress := h.executor.GetProgress(id)
	if progress == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"detail": fmt.Sprintf("backup %s not found", id),
		})
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

// CancelBackup handles DELETE /api/backups/{id}.
func (h *BackupHandler) CancelBackup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.executor.CancelBackup(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"detail": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// StartUpload handles POST /api/backups/{id}/upload — trigger S3 upload for existing backup.
func (h *BackupHandler) StartUpload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		OutputPath string `json:"output_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.OutputPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"detail": "output_path required",
		})
		return
	}

	progress, err := h.executor.StartUpload(id, body.OutputPath)
	if errors.Is(err, backup.ErrUploadNotApplicable) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "already_uploaded",
			"detail": "this agent uses stream-through; upload is part of backup",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusAccepted, progress)
}

// StreamProgress handles GET /api/backups/{id}/stream — SSE endpoint.
func (h *BackupHandler) StreamProgress(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			progress := h.executor.GetProgress(id)
			if progress == nil {
				fmt.Fprintf(w, "data: {\"error\": \"not found\"}\n\n")
				flusher.Flush()
				return
			}

			data, _ := json.Marshal(progress)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

			// Stop streaming when complete
			if progress.Status == models.TaskStatusCompleted ||
				progress.Status == models.TaskStatusFailed ||
				progress.Status == models.TaskStatusCleanupRequired ||
				progress.Status == models.TaskStatusCancelled {
				return
			}
		}
	}
}
