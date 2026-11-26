package resources

import (
	"errors"
	"math"
	"testing"

	"vnbui/agent/internal/sysutil"
)

func TestAdmissionRechecksConcurrencyAfterMeasurement(t *testing.T) {
	for _, restore := range []bool{false, true} {
		name := "backup"
		if restore {
			name = "restore"
		}
		t.Run(name, func(t *testing.T) {
			m := New(1, 1)
			m.SetStoragePath("/journal")
			entered, release := make(chan struct{}, 2), make(chan struct{})
			m.getSystemInfo = func(string) (*sysutil.SystemInfo, error) {
				entered <- struct{}{}
				<-release
				return &sysutil.SystemInfo{DiskKnown: true}, nil
			}
			acquire := m.AcquireBackupSlot
			if restore {
				acquire = m.AcquireRestoreSlot
			}
			results := make(chan error, 2)
			for range 2 {
				go func() { results <- acquire() }()
			}
			<-entered
			<-entered
			close(release)
			accepted := 0
			for range 2 {
				if <-results == nil {
					accepted++
				}
			}
			if accepted != 1 {
				t.Fatalf("%d acquisitions passed for one slot", accepted)
			}
		})
	}
}

func TestAdmissionHonorsLimitReducedDuringMeasurement(t *testing.T) {
	m := New(1, 1)
	m.SetStoragePath("/journal")
	entered, release := make(chan struct{}), make(chan struct{})
	m.getSystemInfo = func(string) (*sysutil.SystemInfo, error) {
		close(entered)
		<-release
		return &sysutil.SystemInfo{DiskKnown: true}, nil
	}
	result := make(chan error, 1)
	go func() { result <- m.AcquireBackupSlot() }()
	<-entered
	m.UpdateMaxBackups(0)
	close(release)
	if <-result == nil || m.ActiveBackups() != 0 {
		t.Fatal("measurement bypassed the reduced admission limit")
	}
}

func TestUnknownOrExhaustedResourcesRefuseAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		info *sysutil.SystemInfo
		err  error
	}{
		{"measurement error", nil, errors.New("unavailable")},
		{"missing sample", nil, nil},
		{"unknown disk", &sysutil.SystemInfo{}, nil},
		{"disk at boundary", &sysutil.SystemInfo{DiskKnown: true, DiskPercent: 95}, nil},
		{"nonfinite cpu", &sysutil.SystemInfo{DiskKnown: true, CPUPercent: math.NaN()}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(1, 1)
			m.SetStoragePath("/journal")
			m.getSystemInfo = func(string) (*sysutil.SystemInfo, error) { return tc.info, tc.err }
			if m.AcquireBackupSlot() == nil || m.AcquireRestoreSlot() == nil {
				t.Fatal("unavailable resources admitted work")
			}
			a := m.BackupAdmission()
			if a.CanAccept || a.ResourcesOK || a.AvailableSlots != 1 || a.Reason == "" {
				t.Fatalf("misleading capacity: %+v", a)
			}
		})
	}
}

func TestAdoptedOvercommitDoesNotAdvertiseNegativeSlots(t *testing.T) {
	m := New(1, 1)
	m.AdoptBackupSlot()
	m.AdoptBackupSlot()
	if m.AvailableSlots() != 0 || m.BackupAdmission().CanAccept {
		t.Fatal("adopted custody must block new admission without negative availability")
	}
}
