package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

func TestBuildCommand(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	req := &models.BackupRequest{
		BackupID:   "test-001",
		VMName:     "my-vm",
		BackupType: models.BackupTypeFull,
		OutputPath: "/var/lib/vnbui/backups/test-001",
	}

	args, err := BuildCommand(cfg, req)
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	// Should start with sudo + binary path
	if args[0] != "sudo" {
		t.Errorf("args[0]: got %q, want 'sudo'", args[0])
	}
	if args[1] != "/usr/bin/virtnbdbackup" {
		t.Errorf("args[1]: got %q", args[1])
	}

	// Should contain -U libvirt URI
	if !containsPair(args, "-U", "qemu:///system") {
		t.Error("missing -U qemu:///system")
	}

	// Should contain --scratchdir
	if !containsPair(args, "--scratchdir", "/var/tmp") {
		t.Error("missing --scratchdir /var/tmp")
	}

	// Should contain -d vm-name
	if !containsPair(args, "-d", "my-vm") {
		t.Error("missing -d my-vm")
	}
}

func TestBuildCommandWithOptions(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	comp := "5"
	workers := 4
	req := &models.BackupRequest{
		BackupID:     "test-002",
		VMName:       "encrypted-vm",
		BackupType:   models.BackupTypeIncremental,
		OutputPath:   "/var/lib/vnbui/backups/test-002",
		Compression:  &comp,
		ExcludeDisks: []string{"vdb"},
		Workers:      &workers,
	}

	args, err := BuildCommand(cfg, req)
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	// Check compression: -z <level> (matches virtnbdbackup CLI)
	if !containsPair(args, "-z", "5") {
		t.Error("missing -z 5")
	}

	// Check exclude disks
	if !containsPair(args, "-x", "vdb") {
		t.Error("missing -x vdb")
	}

	// Check workers: -w <count>
	if !containsPair(args, "-w", "4") {
		t.Error("missing -w 4")
	}
}

func TestBuildCommandInvalidVM(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	req := &models.BackupRequest{
		BackupID:   "test",
		VMName:     "../../../etc/passwd",
		BackupType: models.BackupTypeFull,
		OutputPath: "/var/lib/vnbui/backups/test",
	}

	_, err := BuildCommand(cfg, req)
	if err == nil {
		t.Error("expected error for path traversal in VM name")
	}
}

func TestSystemdUnitName(t *testing.T) {
	tests := []struct {
		backupID string
		expected string
	}{
		{"abc-123", "vnbui-backup-abc-123"},
		{"uuid-with-dashes", "vnbui-backup-uuid-with-dashes"},
	}

	for _, tt := range tests {
		got := SystemdUnitName(tt.backupID)
		if got != tt.expected {
			t.Errorf("SystemdUnitName(%q): got %q, want %q", tt.backupID, got, tt.expected)
		}
	}
}

func TestValidateOutput(t *testing.T) {
	dir := t.TempDir()

	// Empty dir → invalid
	valid, _ := ValidateOutput(dir)
	if valid {
		t.Error("empty dir should be invalid")
	}

	// With vmconfig but no data → invalid
	os.WriteFile(filepath.Join(dir, "vmconfig.xml"), []byte("<domain/>"), 0o644)
	valid, _ = ValidateOutput(dir)
	if valid {
		t.Error("vmconfig only should be invalid")
	}

	// With vmconfig + data → valid
	os.WriteFile(filepath.Join(dir, "vda.data"), []byte("data"), 0o644)
	valid, _ = ValidateOutput(dir)
	if !valid {
		t.Error("vmconfig + data should be valid")
	}

	// With vmconfig + encrypted data → valid
	dir2 := t.TempDir()
	os.WriteFile(filepath.Join(dir2, "vmconfig.xml"), []byte("<domain/>"), 0o644)
	os.WriteFile(filepath.Join(dir2, "vda.data.enc"), []byte("enc"), 0o644)
	valid, _ = ValidateOutput(dir2)
	if !valid {
		t.Error("vmconfig + data.enc should be valid")
	}
}

func TestParseProgressLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "progress.log")

	// Write tqdm-style output
	content := ` 10%|█         | 27/274 [00:10<01:30, 2.74it/s]
 45%|████▌     | 123/274 [00:45<00:55, 2.74it/s]
 90%|█████████ | 247/274 [01:30<00:10, 2.74it/s]
`
	os.WriteFile(logPath, []byte(content), 0o644)

	pct, err := ParseProgressLog(logPath)
	if err != nil {
		t.Fatalf("ParseProgressLog: %v", err)
	}
	if pct != 90 {
		t.Errorf("expected 90%%, got %d%%", pct)
	}
}

func TestStallDetector(t *testing.T) {
	d := NewStallDetector(100 * time.Millisecond)

	if d.IsStalled() {
		t.Error("should not be stalled immediately")
	}

	time.Sleep(150 * time.Millisecond)
	if !d.IsStalled() {
		t.Error("should be stalled after timeout")
	}

	d.Activity()
	if d.IsStalled() {
		t.Error("should not be stalled after activity")
	}
}

func TestBuildCommandIncludeDisks(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	req := &models.BackupRequest{
		BackupID:     "test-inc",
		VMName:       "disk-vm",
		BackupType:   models.BackupTypeFull,
		OutputPath:   "/var/lib/vnbui/backups/test-inc",
		IncludeDisks: []string{"vda", "vdb"},
	}

	args, err := BuildCommand(cfg, req)
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	// Should contain -i vda,vdb
	if !containsPair(args, "-i", "vda,vdb") {
		t.Error("missing -i vda,vdb")
	}
}

func TestBuildCommandIncludeDisksInvalidName(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	req := &models.BackupRequest{
		BackupID:     "test-bad",
		VMName:       "vm1",
		BackupType:   models.BackupTypeFull,
		OutputPath:   "/var/lib/vnbui/backups/test-bad",
		IncludeDisks: []string{"../etc/passwd"},
	}

	_, err := BuildCommand(cfg, req)
	if err == nil {
		t.Error("expected error for invalid include disk name")
	}
}

func TestValidateOutputMultipleFormats(t *testing.T) {
	// Test .raw, .qcow2, .img extensions
	for _, ext := range []string{".raw", ".qcow2", ".img", ".raw.enc", ".qcow2.enc", ".img.enc"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "vmconfig.xml"), []byte("<domain/>"), 0o644)
		os.WriteFile(filepath.Join(dir, "vda"+ext), []byte("data"), 0o644)

		valid, reason := ValidateOutput(dir)
		if !valid {
			t.Errorf("vmconfig + vda%s should be valid: %s", ext, reason)
		}
	}
}

func TestIsActiveBlockJobError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "progress.log")

	// No log file → false
	if isActiveBlockJobError(logPath) {
		t.Error("should return false when log doesn't exist")
	}

	// Log with active block job → true
	os.WriteFile(logPath, []byte("error: active block job for disk vda"), 0o644)
	if !isActiveBlockJobError(logPath) {
		t.Error("should detect active block job")
	}

	// Log without block job → false
	os.WriteFile(logPath, []byte("normal backup progress output"), 0o644)
	if isActiveBlockJobError(logPath) {
		t.Error("should not falsely detect block job")
	}
}

func TestBuildCommandRawFlag(t *testing.T) {
	cfg := &config.Config{
		VirtnbdbackupPath: "/usr/bin/virtnbdbackup",
		VirtnbdScratchDir: "/var/tmp",
		LibvirtURI:        "qemu:///system",
	}

	// Without IncludeRaw
	req := &models.BackupRequest{
		BackupID:   "test-noraw",
		VMName:     "vm1",
		BackupType: models.BackupTypeFull,
		OutputPath: "/backups/test",
	}
	args, _ := BuildCommand(cfg, req)
	for _, a := range args {
		if a == "--raw" {
			t.Error("should not have --raw without IncludeRaw")
		}
	}

	// With IncludeRaw
	req.IncludeRaw = true
	args, _ = BuildCommand(cfg, req)
	found := false
	for _, a := range args {
		if a == "--raw" {
			found = true
		}
	}
	if !found {
		t.Error("should have --raw with IncludeRaw=true")
	}
}

func TestCleanupDataFiles(t *testing.T) {
	dir := t.TempDir()

	// Create data files + metadata
	os.WriteFile(filepath.Join(dir, "vda.full.data.enc"), []byte("encrypted"), 0o644)
	os.WriteFile(filepath.Join(dir, "vda.full.data.chksum"), []byte("abc123"), 0o644)
	os.WriteFile(filepath.Join(dir, "vmconfig.virtnbdbackup.0.xml"), []byte("<domain/>"), 0o644)
	os.WriteFile(filepath.Join(dir, "autostart.virtnbdbackup.0"), []byte("1"), 0o644)
	os.MkdirAll(filepath.Join(dir, "checkpoints"), 0o755)
	os.WriteFile(filepath.Join(dir, "checkpoints", "virtnbdbackup.0.xml"), []byte("<cp/>"), 0o644)

	cleanupDataFiles(dir)

	// Data file should be gone
	if _, err := os.Stat(filepath.Join(dir, "vda.full.data.enc")); err == nil {
		t.Error("data.enc file should have been deleted")
	}
	// Metadata should remain
	if _, err := os.Stat(filepath.Join(dir, "vmconfig.virtnbdbackup.0.xml")); err != nil {
		t.Error("vmconfig should be kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "vda.full.data.chksum")); err != nil {
		t.Error("chksum should be kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "checkpoints", "virtnbdbackup.0.xml")); err != nil {
		t.Error("checkpoint should be kept")
	}
}

func TestActivityReader(t *testing.T) {
	data := []byte("hello world")
	reader := &activityReader{
		r:            bytes.NewReader(data),
		lastActivity: &atomic.Int64{},
	}

	before := time.Now().UnixNano()
	buf := make([]byte, 5)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Errorf("expected 'hello', got %q", buf[:n])
	}
	if reader.lastActivity.Load() < before {
		t.Error("lastActivity should be updated after read")
	}
}

func containsPair(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}
