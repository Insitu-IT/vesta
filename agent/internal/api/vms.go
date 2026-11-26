package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"vnbui/agent/internal/provider"
)

// VMHandler handles VM-related endpoints.
type VMHandler struct {
	provider provider.VMProvider
}

// NewVMHandler creates a VM handler.
func NewVMHandler(p provider.VMProvider) *VMHandler {
	return &VMHandler{provider: p}
}

// ListVMs returns all VMs.
func (h *VMHandler) ListVMs(w http.ResponseWriter, r *http.Request) {
	vms, err := h.provider.ListVMs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"detail": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, vms)
}

// GetVM returns a single VM by name.
func (h *VMHandler) GetVM(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	vm, err := h.provider.GetVM(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"detail": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, vm)
}

// DiscoverVMs is an alias for ListVMs (matches Python agent API).
func (h *VMHandler) DiscoverVMs(w http.ResponseWriter, r *http.Request) {
	h.ListVMs(w, r)
}
