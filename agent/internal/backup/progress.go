package backup

import (
	"bufio"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// tqdm output pattern: " 45%|████ | 123/274 [00:45<01:02, 2.44it/s]"
var tqdmRe = regexp.MustCompile(`(\d+)%`)

// ANSI escape codes from script(1) TTY capture
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\r`)

// ParseProgressLog reads the tail of the progress.log file and extracts the latest percentage.
// The log is written by script -O which captures tqdm output including ANSI codes.
func ParseProgressLog(logPath string) (int, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Read last 4KB (enough for recent tqdm output)
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	readSize := int64(4096)
	if info.Size() < readSize {
		readSize = info.Size()
	}
	if readSize == 0 {
		return 0, nil
	}
	f.Seek(info.Size()-readSize, 0)

	buf := make([]byte, readSize)
	n, _ := f.Read(buf)
	content := string(buf[:n])

	// Strip ANSI escape codes
	content = ansiRe.ReplaceAllString(content, "")

	lastPercent := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "saving disk") || strings.Contains(line, "%|") {
			if matches := tqdmRe.FindStringSubmatch(line); len(matches) > 1 {
				if pct, err := strconv.Atoi(matches[1]); err == nil && pct <= 100 {
					lastPercent = pct
				}
			}
		}
	}

	return lastPercent, nil
}

// StallDetector monitors for backup output stalls.
type StallDetector struct {
	lastActivity time.Time
	stallTimeout time.Duration
}

// NewStallDetector creates a stall detector with the given timeout.
func NewStallDetector(timeout time.Duration) *StallDetector {
	return &StallDetector{
		lastActivity: time.Now(),
		stallTimeout: timeout,
	}
}

// Activity records that output was seen.
func (d *StallDetector) Activity() {
	d.lastActivity = time.Now()
}

// IsStalled returns true if no activity for the stall timeout duration.
func (d *StallDetector) IsStalled() bool {
	return time.Since(d.lastActivity) > d.stallTimeout
}

// backupDataSuffixes lists all file extensions that are backup data files.
var backupDataSuffixes = []string{
	".data", ".data.enc",
	".raw", ".raw.enc",
	".qcow2", ".qcow2.enc",
	".img", ".img.enc",
}

// ScanOutputDir counts data files and total size in a backup output directory.
func ScanOutputDir(outputPath string) (fileCount int, totalBytes int64) {
	entries, err := os.ReadDir(outputPath)
	if err != nil {
		return 0, 0
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for _, suffix := range backupDataSuffixes {
			if strings.HasSuffix(name, suffix) {
				info, err := entry.Info()
				if err == nil {
					fileCount++
					totalBytes += info.Size()
				}
				break
			}
		}
	}

	return
}

// MonitorProgress polls the progress log and libvirt block job at an interval.
// Returns when ctx is cancelled or the done channel is closed.
func MonitorProgress(logPath string, interval time.Duration, update func(pct int)) chan struct{} {
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				pct, err := ParseProgressLog(logPath)
				if err != nil {
					slog.Debug("progress log read error", "error", err)
					continue
				}
				if pct > 0 {
					update(pct)
				}
			}
		}
	}()

	return done
}
