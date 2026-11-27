package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"vnbui/agent/internal/filebackup"
)

type fileBackupExecutor interface {
	Submit(id, fileSet string, storage *filebackup.ExpectedStorage) (filebackup.Result, error)
	Get(id string) (filebackup.Result, error)
}

type fileBackupHandler struct {
	executor fileBackupExecutor
}

func (h fileBackupHandler) submit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BackupID string                      `json:"backup_id"`
		FileSet  string                      `json:"file_set"`
		Storage  *filebackup.ExpectedStorage `json:"storage"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF || req.Storage == nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"detail": "invalid managed file backup request"})
		return
	}
	result, err := h.executor.Submit(req.BackupID, req.FileSet, req.Storage)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, result)
	case errors.Is(err, filebackup.ErrInvalid), errors.Is(err, filebackup.ErrUnknown), errors.Is(err, filebackup.ErrScope):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"detail": err.Error()})
	case errors.Is(err, filebackup.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": err.Error()})
	case errors.Is(err, filebackup.ErrBusy):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"detail": err.Error()})
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "managed file backup journal unavailable"})
	}
}

func (h fileBackupHandler) get(w http.ResponseWriter, r *http.Request) {
	result, err := h.executor.Get(chi.URLParam(r, "id"))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, result)
	case errors.Is(err, filebackup.ErrInvalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"detail": err.Error()})
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "managed file backup not found"})
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "managed file backup journal unavailable"})
	}
}
