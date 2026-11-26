package resources

import (
	"sync"
	"testing"

	"vnbui/agent/internal/sysutil"
)

func TestAcquireReleaseBackupSlots(t *testing.T) {
	m := New(2, 1)

	// Acquire first slot
	if err := m.AcquireBackupSlot(); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if m.ActiveBackups() != 1 {
		t.Errorf("active = %d, want 1", m.ActiveBackups())
	}

	// Acquire second slot
	if err := m.AcquireBackupSlot(); err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if m.ActiveBackups() != 2 {
		t.Errorf("active = %d, want 2", m.ActiveBackups())
	}

	// Third should fail — at capacity
	if err := m.AcquireBackupSlot(); err == nil {
		t.Fatal("expected capacity error, got nil")
	}

	// Release one and retry
	m.ReleaseBackupSlot()
	if err := m.AcquireBackupSlot(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

func TestAcquireReleaseRestoreSlots(t *testing.T) {
	m := New(2, 1)

	if err := m.AcquireRestoreSlot(); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if m.ActiveRestores() != 1 {
		t.Errorf("active = %d, want 1", m.ActiveRestores())
	}

	// Second should fail — max 1
	if err := m.AcquireRestoreSlot(); err == nil {
		t.Fatal("expected capacity error, got nil")
	}

	m.ReleaseRestoreSlot()
	if m.ActiveRestores() != 0 {
		t.Errorf("active = %d after release, want 0", m.ActiveRestores())
	}
}

func TestAvailableSlots(t *testing.T) {
	m := New(3, 1)

	if m.AvailableSlots() != 3 {
		t.Errorf("available = %d, want 3", m.AvailableSlots())
	}

	m.AcquireBackupSlot()
	if m.AvailableSlots() != 2 {
		t.Errorf("available = %d, want 2", m.AvailableSlots())
	}

	m.AcquireBackupSlot()
	m.AcquireBackupSlot()
	if m.AvailableSlots() != 0 {
		t.Errorf("available = %d, want 0", m.AvailableSlots())
	}
}

func TestUpdateMaxBackups(t *testing.T) {
	m := New(1, 1)

	m.AcquireBackupSlot()
	if err := m.AcquireBackupSlot(); err == nil {
		t.Fatal("expected capacity error before update")
	}

	// Increase capacity
	m.UpdateMaxBackups(3)
	if err := m.AcquireBackupSlot(); err != nil {
		t.Fatalf("acquire after update: %v", err)
	}
	if m.AvailableSlots() != 1 {
		t.Errorf("available = %d, want 1", m.AvailableSlots())
	}
}

func TestReleaseNeverGoesNegative(t *testing.T) {
	m := New(2, 2)

	// Release without acquire — should stay at 0
	m.ReleaseBackupSlot()
	m.ReleaseRestoreSlot()

	if m.ActiveBackups() != 0 {
		t.Errorf("backups = %d, want 0", m.ActiveBackups())
	}
	if m.ActiveRestores() != 0 {
		t.Errorf("restores = %d, want 0", m.ActiveRestores())
	}
}

func TestDefaultRestoreSlots(t *testing.T) {
	// maxRestores <= 0 should default to 1
	m := New(2, 0)
	if err := m.AcquireRestoreSlot(); err != nil {
		t.Fatalf("acquire with default max: %v", err)
	}
	if err := m.AcquireRestoreSlot(); err == nil {
		t.Fatal("expected capacity error with default max=1")
	}
}

func TestAdoptBackupSlot(t *testing.T) {
	m := New(2, 1)

	// Adopt a slot
	m.AdoptBackupSlot()
	if m.ActiveBackups() != 1 {
		t.Errorf("active = %d, want 1", m.ActiveBackups())
	}

	// Adopt beyond max (should still work, just logs warning)
	m.AdoptBackupSlot()
	m.AdoptBackupSlot()
	if m.ActiveBackups() != 3 {
		t.Errorf("active = %d, want 3 (over limit)", m.ActiveBackups())
	}

	// Release should work normally
	m.ReleaseBackupSlot()
	if m.ActiveBackups() != 2 {
		t.Errorf("active = %d after release, want 2", m.ActiveBackups())
	}
}

func TestCheckResourcesThresholds(t *testing.T) {
	m := New(2, 1)
	m.SetStoragePath("/tmp")
	m.SetThresholds(50.0, 50.0, 50.0) // Low thresholds for testing

	// Inject mock system info
	m.getSystemInfo = func(path string) (*sysutil.SystemInfo, error) {
		return &sysutil.SystemInfo{
			DiskKnown:     true,
			CPUPercent:    60.0, // Above 50% threshold
			MemoryPercent: 40.0,
			DiskPercent:   30.0,
		}, nil
	}

	ok, reason := m.CheckResources()
	if ok {
		t.Error("should fail with CPU above threshold")
	}
	if reason == "" {
		t.Error("reason should not be empty")
	}

	// All below threshold
	m.getSystemInfo = func(path string) (*sysutil.SystemInfo, error) {
		return &sysutil.SystemInfo{
			DiskKnown:     true,
			CPUPercent:    30.0,
			MemoryPercent: 30.0,
			DiskPercent:   30.0,
		}, nil
	}

	ok, _ = m.CheckResources()
	if !ok {
		t.Error("should pass with all below threshold")
	}
}

func TestCheckResourcesNoStoragePath(t *testing.T) {
	m := New(2, 1)
	// No storage path set — should pass
	ok, _ := m.CheckResources()
	if !ok {
		t.Error("should pass with no storage path")
	}
}

func TestAcquireBackupSlotWithThresholds(t *testing.T) {
	m := New(2, 1)
	m.SetStoragePath("/tmp")
	m.SetThresholds(50.0, 50.0, 50.0)

	// Mock high CPU
	m.getSystemInfo = func(path string) (*sysutil.SystemInfo, error) {
		return &sysutil.SystemInfo{
			DiskKnown:     true,
			CPUPercent:    80.0,
			MemoryPercent: 30.0,
			DiskPercent:   30.0,
		}, nil
	}

	err := m.AcquireBackupSlot()
	if err == nil {
		t.Error("should fail when CPU above threshold")
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := New(100, 100)
	var wg sync.WaitGroup

	// 50 goroutines acquiring and releasing
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.AcquireBackupSlot(); err == nil {
				m.ReleaseBackupSlot()
			}
		}()
	}

	wg.Wait()

	if m.ActiveBackups() != 0 {
		t.Errorf("active = %d after concurrent acquire/release, want 0", m.ActiveBackups())
	}
}
