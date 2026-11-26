package sysutil

import (
	"math"
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
)

func TestDiskUsageFitsHeartbeatByteCounts(t *testing.T) {
	for _, tc := range []struct {
		free, total uint64
		known       bool
	}{
		{0, 1024, true},
		{math.MaxInt64, math.MaxInt64, true},
		{0, math.MaxInt64 + 1, false},
		{2048, 1024, false},
	} {
		info := &SystemInfo{}
		err := info.setDiskUsage(&disk.UsageStat{Free: tc.free, Total: tc.total})
		free, total, percent := info.DiskValues()
		if (err == nil) != tc.known || info.DiskKnown != tc.known || (free != nil && total != nil && percent != nil) != tc.known {
			t.Fatalf("free %d, total %d: known %v, error %v", tc.free, tc.total, info.DiskKnown, err)
		}
		if tc.known && (uint64(*free) != tc.free || uint64(*total) != tc.total) {
			t.Fatalf("unexpected counts %d, %d", *free, *total)
		}
	}
}

func TestMissingStorageMeasurementIsUnknown(t *testing.T) {
	info, err := GetSystemInfo(t.TempDir() + "/not-mounted")
	free, total, percent := info.DiskValues()
	if err == nil || info.DiskKnown || info.DiskError == "" || free != nil || total != nil || percent != nil {
		t.Fatal("failed stat reported as zero storage")
	}
}
func TestConfirmedZeroRemainsMeasurement(t *testing.T) {
	info := &SystemInfo{DiskKnown: true, DiskFreeBytes: 0, DiskTotalBytes: 1024}
	free, total, _ := info.DiskValues()
	if free == nil || *free != 0 || total == nil || *total != 1024 {
		t.Fatal("zero free storage lost")
	}
}
