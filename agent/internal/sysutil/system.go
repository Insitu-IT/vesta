package sysutil

import (
	"errors"
	"math"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemInfo holds a snapshot of system metrics.
type SystemInfo struct {
	CPUPercent     float64
	MemoryPercent  float64
	CPUCores       int
	LoadAverage15m float64
	DiskKnown      bool
	DiskError      string
	DiskPercent    float64
	DiskFreeBytes  int64
	DiskTotalBytes int64
	UptimeSeconds  uint64
}

// GetSystemInfo collects current system metrics.
func GetSystemInfo(storagePath string) (*SystemInfo, error) {
	info := &SystemInfo{}

	// CPU percent (average over 500ms)
	cpuPcts, err := cpu.Percent(500*time.Millisecond, false)
	if err == nil && len(cpuPcts) > 0 {
		info.CPUPercent = cpuPcts[0]
	}

	// CPU cores
	cores, err := cpu.Counts(true)
	if err == nil {
		info.CPUCores = cores
	}

	// Memory
	vmStat, err := mem.VirtualMemory()
	if err == nil {
		info.MemoryPercent = vmStat.UsedPercent
	}

	// Load average
	loadStat, err := load.Avg()
	if err == nil {
		info.LoadAverage15m = loadStat.Load15
	}

	// Disk usage for storage path
	diskStat, storageErr := disk.Usage(storagePath)
	if storageErr == nil {
		storageErr = info.setDiskUsage(diskStat)
	}
	if storageErr != nil {
		info.DiskError = storageErr.Error()
	}

	// Uptime
	uptime, err := host.Uptime()
	if err == nil {
		info.UptimeSeconds = uptime
	}

	return info, storageErr
}

func (i *SystemInfo) setDiskUsage(usage *disk.UsageStat) error {
	if usage.Total > math.MaxInt64 || usage.Free > usage.Total {
		return errors.New("filesystem capacity exceeds supported range")
	}
	i.DiskFreeBytes = int64(usage.Free)
	i.DiskTotalBytes = int64(usage.Total)
	i.DiskPercent = usage.UsedPercent
	i.DiskKnown = true
	return nil
}

// DiskValues preserves unavailable measurements as JSON null, distinct from zero free bytes.
func (i *SystemInfo) DiskValues() (free, total *int64, percent *float64) {
	if !i.DiskKnown {
		return nil, nil, nil
	}
	f, t := i.DiskFreeBytes, i.DiskTotalBytes
	return &f, &t, &i.DiskPercent
}
