package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/verification"
)

type VerificationExecutor interface {
	Submit(verification.Request) (*verification.Progress, error)
	Get(string, string) *verification.Progress
	Cancel(string, string, string) *verification.Progress
}

type VerificationHandler struct {
	executor VerificationExecutor
	secure   bool
	agentID  string
	provider string
}

// Capability binds a registered agent identity before read credentials are sent.
func (h *VerificationHandler) Capability(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"schema": verification.Schema, "agent_id": h.agentID, "provider": h.provider})
}

func (h *VerificationHandler) guard(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !h.secure || r.TLS == nil {
		writeJSON(w, http.StatusLocked, map[string]string{"detail": "verification requires authenticated HTTPS"})
		return false
	}
	return true
}

func (h *VerificationHandler) Submit(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, verification.MaxRequestBytes+1))
	req, decodeErr := verification.DecodeRequest(body)
	if err != nil || decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid verification request"})
		return
	}
	progress, err := h.executor.Submit(req)
	if err != nil {
		code, message := http.StatusServiceUnavailable, "verification unavailable"
		switch {
		case errors.Is(err, verification.ErrPlan):
			code, message = http.StatusUnprocessableEntity, "invalid verification plan or credentials"
		case errors.Is(err, verification.ErrConflict):
			code, message = http.StatusConflict, "verification plan conflicts with original custody"
		case errors.Is(err, verification.ErrBusy):
			canonical, canonicalErr := models.StorageCanonical(req.Plan)
			if canonicalErr == nil {
				sum := sha256.Sum256(canonical)
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"schema":          "vnbui-backup-verification-admission/1",
					"verification_id": req.Plan.VerificationID, "org_id": req.Plan.OrgID,
					"agent_id": req.Plan.AgentID, "plan_sha256": hex.EncodeToString(sum[:]),
					"status": "not_admitted", "reason": "agent_busy",
				})
				return
			}
		}
		writeJSON(w, code, map[string]string{"detail": message})
		return
	}
	writeJSON(w, http.StatusAccepted, progress)
}

func (h *VerificationHandler) Get(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	progress := h.executor.Get(chi.URLParam(r, "id"), r.URL.Query().Get("org_id"))
	if progress == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "verification not found"})
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

func (h *VerificationHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	progress := h.executor.Cancel(chi.URLParam(r, "id"), r.URL.Query().Get("org_id"), r.URL.Query().Get("plan_sha256"))
	if progress == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "verification not found"})
		return
	}
	writeJSON(w, http.StatusAccepted, progress)
}
