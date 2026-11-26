package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/restore"
)

// RestoreHandler handles restore API endpoints.
type RestoreHandler struct {
	executor    restore.ExecutorIface
	freshSecure bool
}

// NewRestoreHandler creates a restore handler.
func NewRestoreHandler(executor restore.ExecutorIface) *RestoreHandler {
	return &RestoreHandler{executor: executor}
}

// StartRestore handles POST /api/restores.
func (h *RestoreHandler) StartRestore(w http.ResponseWriter, r *http.Request) {
	if _, fresh := h.executor.(interface{ FreshKubeVirtRestore() }); fresh && (!h.freshSecure || r.TLS == nil) {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "fresh KubeVirt restore requires authenticated HTTPS"})
		return
	}
	if _, fresh := h.executor.(interface{ FreshNativeRestore() }); fresh && (!h.freshSecure || r.TLS == nil) {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "fresh native restore requires authenticated HTTPS"})
		return
	}
	var req models.RestoreRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"detail": "invalid restore request",
		})
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid restore request"})
		return
	}
	if req.KubeVirt != nil {
		if _, fresh := h.executor.(interface{ FreshKubeVirtRestore() }); !fresh {
			writeJSON(w, http.StatusLocked, map[string]string{"detail": "this provider does not implement fresh KubeVirt restore"})
			return
		}
	}
	if req.Native != nil {
		if _, fresh := h.executor.(interface{ FreshNativeRestore() }); !fresh || req.KubeVirt != nil {
			writeJSON(w, http.StatusLocked, map[string]string{"detail": "this provider does not implement the requested fresh native restore"})
			return
		}
	}

	progress, err := h.executor.StartRestore(&req)
	if err != nil {
		if errors.Is(err, restore.ErrPreJournalTargetReserved) && req.KubeVirt != nil {
			pvcNames := make([]string, 0, len(req.KubeVirt.Target.Disks))
			for _, disk := range req.KubeVirt.Target.Disks {
				pvcNames = append(pvcNames, disk.PVCName)
			}
			sort.Strings(pvcNames)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"code":             "prejournal_target_reserved",
				"restore_id":       req.KubeVirt.RestoreID,
				"target_vm_name":   req.KubeVirt.Target.VMName,
				"target_pvc_names": pvcNames,
				"journal_created":  false,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusAccepted, progress)
}

// GetRestore handles GET /api/restores/{id}.
func (h *RestoreHandler) GetRestore(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	progress := h.executor.GetProgress(id)
	if progress == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"detail": fmt.Sprintf("restore %s not found", id),
		})
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

// StreamProgress handles GET /api/restores/{id}/stream — SSE endpoint.
func (h *RestoreHandler) StreamProgress(w http.ResponseWriter, r *http.Request) {
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

			if progress.Status == models.TaskStatusCompleted ||
				progress.Status == models.TaskStatusFailed ||
				progress.Status == models.TaskStatus("cleanup_required") ||
				progress.Status == models.TaskStatusCancelled {
				return
			}
		}
	}
}
