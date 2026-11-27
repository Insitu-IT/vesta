package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/sysutil"
)

// ResourceInfo provides active operation counts for health reporting.
type ResourceInfo interface {
	ActiveBackups() int
	ActiveRestores() int
	AvailableSlots() int
}

// HealthHandler handles health-related endpoints.
type HealthHandler struct {
	cfg         *config.Config
	version     string
	startTime   time.Time
	resources   ResourceInfo
	activation  map[string]string
	vmAvailable func() bool
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(cfg *config.Config, version string) *HealthHandler {
	return &HealthHandler{
		cfg:       cfg,
		version:   version,
		startTime: time.Now(),
	}
}

// SetResources wires the resource manager for capacity reporting.
func (h *HealthHandler) SetResources(r ResourceInfo) {
	h.resources = r
}

// SetActivation reports startup-only executor activation without exposing
// journal paths, credentials or other details from the underlying error.
func (h *HealthHandler) SetActivation(status map[string]string) {
	h.activation = make(map[string]string, len(status))
	for name, value := range status {
		h.activation[name] = value
	}
}

// Health is a simple liveness probe.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"version": h.version,
	})
}

// Ready is a readiness probe.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ready",
	})
}

// Detailed returns detailed health information.
func (h *HealthHandler) Detailed(w http.ResponseWriter, r *http.Request) {
	info, _ := sysutil.GetSystemInfo(h.cfg.StorageMeasurementPath())

	free, total, percent := info.DiskValues()
	hostname, _ := os.Hostname()

	result := map[string]interface{}{
		"status":     "healthy",
		"version":    h.version,
		"hostname":   hostname,
		"uptime_sec": int(time.Since(h.startTime).Seconds()),
		"activation": h.activation,
		"system": map[string]interface{}{
			"cpu_percent":    info.CPUPercent,
			"memory_percent": info.MemoryPercent,
			"cpu_cores":      info.CPUCores,
			"load_15m":       info.LoadAverage15m,
		},
		"storage": map[string]interface{}{
			"path":              h.cfg.StorageMeasurementPath(),
			"role":              h.cfg.StorageRole(),
			"measurement_error": info.DiskError,
			"free_bytes":        free,
			"total_bytes":       total,
			"used_pct":          percent,
		},
	}

	if h.vmAvailable != nil {
		workload := "unavailable"
		if h.vmAvailable() {
			workload = "available"
		}
		activation := make(map[string]string, len(h.activation)+1)
		for key, value := range h.activation {
			activation[key] = value
		}
		activation["vm_workload"] = workload
		result["activation"] = activation
	}
	writeJSON(w, http.StatusOK, result)
}

// Capacity returns resource availability.
func (h *HealthHandler) Capacity(w http.ResponseWriter, r *http.Request) {
	info, _ := sysutil.GetSystemInfo(h.cfg.StorageMeasurementPath())

	free, _, _ := info.DiskValues()
	admission := resources.Admission{MaxBackups: h.cfg.MaxConcurrentBackups, Reason: "resource admission unavailable"}
	if manager, ok := h.resources.(interface{ BackupAdmission() resources.Admission }); ok {
		admission = manager.BackupAdmission()
	}

	result := map[string]interface{}{
		"max_concurrent_backups": admission.MaxBackups,
		"active_backups":         admission.ActiveBackups,
		"available_slots":        admission.AvailableSlots,
		"cpu_percent":            info.CPUPercent,
		"memory_percent":         info.MemoryPercent,
		"disk_free_bytes":        free,
		"storage_role":           h.cfg.StorageRole(),
		"can_accept_backup":      admission.CanAccept,
		"resources_available":    admission.ResourcesOK,
		"admission_reason":       admission.Reason,
	}

	writeJSON(w, http.StatusOK, result)
}

// Version returns version info matching the Python agent format.
func (h *HealthHandler) Version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":  h.version,
		"hostname": h.cfg.Hostname,
		"runtime":  "go",
	})
}

func readVersion() string {
	for _, path := range []string{"VERSION", "/opt/vesta-agent/VERSION", "/opt/vnbui-agent/VERSION"} {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return "dev"
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
