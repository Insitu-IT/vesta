package resources

import (
	"fmt"
	"log/slog"
	"math"
	"sync"

	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/sysutil"
)

// Manager handles concurrency limits and admission control.
type Manager struct {
	mu             sync.Mutex
	maxBackups     int
	maxRestores    int
	activeBackups  int
	activeRestores int

	// Resource thresholds (percentage)
	cpuThreshold  float64
	memThreshold  float64
	diskThreshold float64
	storagePath   string

	// For testing: injectable system info function
	getSystemInfo func(string) (*sysutil.SystemInfo, error)
}

// New creates a resource manager.
func New(maxBackups, maxRestores int) *Manager {
	if maxRestores <= 0 {
		maxRestores = 1
	}
	m := &Manager{
		maxBackups:    maxBackups,
		maxRestores:   maxRestores,
		cpuThreshold:  90.0,
		memThreshold:  90.0,
		diskThreshold: 95.0,
		getSystemInfo: sysutil.GetSystemInfo,
	}

	metrics.MaxConcurrentOperations.WithLabelValues("backup").Set(float64(maxBackups))
	metrics.MaxConcurrentOperations.WithLabelValues("restore").Set(float64(maxRestores))
	return m
}

// SetStoragePath sets the storage path for disk threshold checks.
func (m *Manager) SetStoragePath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storagePath = path
}

// SetThresholds configures resource thresholds (percentage).
func (m *Manager) SetThresholds(cpu, mem, disk float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cpuThreshold = cpu
	m.memThreshold = mem
	m.diskThreshold = disk
}

// DiskAdmissionThreshold is the used percentage at which this agent refuses a new slot.
func (m *Manager) DiskAdmissionThreshold() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.diskThreshold
}

// CheckResources verifies system resources are below thresholds.
func (m *Manager) CheckResources() (bool, string) {
	m.mu.Lock()
	storagePath := m.storagePath
	cpuThresh := m.cpuThreshold
	memThresh := m.memThreshold
	diskThresh := m.diskThreshold
	m.mu.Unlock()

	if storagePath == "" {
		return true, "" // No storage path configured, skip check
	}

	info, err := m.getSystemInfo(storagePath)
	if err != nil || info == nil || !info.DiskKnown {
		return false, "storage measurement unavailable"
	}

	for _, value := range []float64{cpuThresh, memThresh, diskThresh} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 100 {
			return false, "resource threshold configuration invalid"
		}
	}
	for _, value := range []float64{info.CPUPercent, info.MemoryPercent, info.DiskPercent} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
			return false, "resource measurement invalid"
		}
	}
	if info.CPUPercent >= cpuThresh {
		return false, fmt.Sprintf("CPU at %.0f%% (threshold: %.0f%%)", info.CPUPercent, cpuThresh)
	}
	if info.MemoryPercent >= memThresh {
		return false, fmt.Sprintf("memory at %.0f%% (threshold: %.0f%%)", info.MemoryPercent, memThresh)
	}
	if info.DiskPercent >= diskThresh {
		return false, fmt.Sprintf("disk at %.0f%% (threshold: %.0f%%)", info.DiskPercent, diskThresh)
	}

	return true, ""
}

// AcquireBackupSlot tries to acquire a backup slot. Returns error if at capacity or resources exceeded.
func (m *Manager) AcquireBackupSlot() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeBackups >= m.maxBackups {
		return fmt.Errorf("at backup capacity (%d/%d)", m.activeBackups, m.maxBackups)
	}

	// Check resource thresholds (unlock for I/O, recheck after)
	m.mu.Unlock()
	ok, reason := m.CheckResources()
	m.mu.Lock()
	if !ok {
		return fmt.Errorf("resource threshold exceeded: %s", reason)
	}
	// Another acquisition or a configuration reduction can win while metrics
	// I/O runs without the lock. The initial check is not a reservation.
	if m.activeBackups >= m.maxBackups {
		return fmt.Errorf("at backup capacity (%d/%d)", m.activeBackups, m.maxBackups)
	}

	m.activeBackups++
	metrics.ConcurrentOperations.WithLabelValues("backup").Set(float64(m.activeBackups))
	return nil
}

// AdoptBackupSlot accounts for a backup discovered during reconciliation.
// Does not reject even if over limit — the backup is already running.
func (m *Manager) AdoptBackupSlot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeBackups++
	metrics.ConcurrentOperations.WithLabelValues("backup").Set(float64(m.activeBackups))
	if m.activeBackups > m.maxBackups {
		slog.Warn("adopted backup exceeds concurrency limit",
			"active", m.activeBackups, "max", m.maxBackups)
	}
}

// ReleaseBackupSlot releases a backup slot.
func (m *Manager) ReleaseBackupSlot() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeBackups > 0 {
		m.activeBackups--
	}
	metrics.ConcurrentOperations.WithLabelValues("backup").Set(float64(m.activeBackups))
}

// AcquireRestoreSlot tries to acquire a restore slot.
func (m *Manager) AcquireRestoreSlot() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeRestores >= m.maxRestores {
		return fmt.Errorf("at restore capacity (%d/%d)", m.activeRestores, m.maxRestores)
	}
	m.mu.Unlock()
	ok, reason := m.CheckResources()
	m.mu.Lock()
	if !ok {
		return fmt.Errorf("resource threshold exceeded: %s", reason)
	}
	if m.activeRestores >= m.maxRestores {
		return fmt.Errorf("at restore capacity (%d/%d)", m.activeRestores, m.maxRestores)
	}
	m.activeRestores++
	metrics.ConcurrentOperations.WithLabelValues("restore").Set(float64(m.activeRestores))
	return nil
}

// ReleaseRestoreSlot releases a restore slot.
func (m *Manager) ReleaseRestoreSlot() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeRestores > 0 {
		m.activeRestores--
	}
	metrics.ConcurrentOperations.WithLabelValues("restore").Set(float64(m.activeRestores))
}

// ActiveBackups returns the number of active backups.
func (m *Manager) ActiveBackups() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeBackups
}

// ActiveRestores returns the number of active restores.
func (m *Manager) ActiveRestores() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeRestores
}

// AvailableSlots returns the number of available backup slots.
func (m *Manager) AvailableSlots() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return max(0, m.maxBackups-m.activeBackups)
}

// Admission is an observation of the same gates used by acquisition. A free
// job slot alone says nothing about storage, CPU or memory admission.
type Admission struct {
	MaxBackups     int    `json:"max_concurrent_backups"`
	ActiveBackups  int    `json:"active_backups"`
	AvailableSlots int    `json:"available_slots"`
	ResourcesOK    bool   `json:"resources_available"`
	CanAccept      bool   `json:"can_accept_backup"`
	Reason         string `json:"reason"`
}

func (m *Manager) BackupAdmission() Admission {
	ok, reason := m.CheckResources()
	m.mu.Lock()
	defer m.mu.Unlock()
	slots := max(0, m.maxBackups-m.activeBackups)
	if slots == 0 && reason == "" {
		reason = "backup concurrency exhausted"
	}
	return Admission{MaxBackups: m.maxBackups, ActiveBackups: m.activeBackups,
		AvailableSlots: slots, ResourcesOK: ok, CanAccept: ok && slots > 0, Reason: reason}
}

// UpdateMaxBackups updates the max concurrent backups (from remote config).
func (m *Manager) UpdateMaxBackups(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxBackups = max
	metrics.MaxConcurrentOperations.WithLabelValues("backup").Set(float64(max))
}
