package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBackupRequestJSONRoundTrip(t *testing.T) {
	comp := "5"
	key := "dGVzdGtleQ=="
	req := BackupRequest{
		BackupID:       "test-001",
		VMName:         "my-vm",
		BackupType:     BackupTypeFull,
		OutputPath:     "/var/lib/vnbui/backups/test-001",
		Compression:    &comp,
		ExcludeDisks:   []string{"vdb"},
		Workers:        nil,
		EncryptionType: EncryptionTypeAES256GCM,
		EncryptionKey:  &key,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out BackupRequest
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.BackupID != req.BackupID {
		t.Errorf("backup_id: got %q, want %q", out.BackupID, req.BackupID)
	}
	if out.BackupType != BackupTypeFull {
		t.Errorf("backup_type: got %q, want %q", out.BackupType, BackupTypeFull)
	}
	if out.EncryptionType != EncryptionTypeAES256GCM {
		t.Errorf("encryption_type: got %q, want %q", out.EncryptionType, EncryptionTypeAES256GCM)
	}
}

func TestBackupRequestFieldNames(t *testing.T) {
	// Verify JSON field names match Python model exactly
	req := BackupRequest{
		BackupID:   "test",
		VMName:     "vm",
		BackupType: BackupTypeFull,
		OutputPath: "/tmp",
	}

	data, _ := json.Marshal(req)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{
		"backup_id", "vm_name", "backup_type", "output_path",
		"compression", "include_disks", "exclude_disks", "workers",
		"encryption_type", "encryption_key",
	}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestRestoreRequestFieldNames(t *testing.T) {
	req := RestoreRequest{
		RestoreID:   "test",
		BackupPath:  "/path",
		RestorePath: "/out",
		Action:      "restore",
		Source:      "local",
	}

	data, _ := json.Marshal(req)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{
		"restore_id", "backup_path", "restore_path", "action",
		"selected_disks", "target_name", "until_checkpoint",
		"auto_define", "adjust_config", "encryption_type",
		"encryption_key", "encryption_key_hash", "source",
		"s3_config", "chain_members",
	}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestAgentHeartbeatFieldNames(t *testing.T) {
	hb := AgentHeartbeat{
		Status:            "online",
		LibvirtAccessible: true,
		Events:            []map[string]interface{}{},
	}

	data, _ := json.Marshal(hb)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{
		"status", "version", "ip_address", "port",
		"active_backups", "active_restores",
		"cpu_usage_percent", "memory_usage_percent",
		"cpu_cores", "load_average_15m", "disk_usage_percent",
		"backup_storage_path", "backup_storage_free_bytes",
		"backup_storage_total_bytes",
		"libvirt_accessible", "last_error", "events",
	}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestBackupProgressFieldNames(t *testing.T) {
	bp := BackupProgress{
		BackupID: "test",
		Status:   TaskStatusRunning,
	}

	data, _ := json.Marshal(bp)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{
		"backup_id", "status", "vm_name", "systemd_unit",
		"storage_path", "progress_log_path", "progress_percent",
		"current_disk", "bytes_transferred", "total_bytes",
		"transfer_rate_mbps", "started_at", "estimated_completion",
		"error_message",
	}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestNewRunningBackupProgress(t *testing.T) {
	unit := "vnbui-backup-test.scope"
	bp := NewRunningBackupProgress("test-id", "my-vm", &unit)

	if bp.Status != TaskStatusRunning {
		t.Errorf("status: got %q, want %q", bp.Status, TaskStatusRunning)
	}
	if *bp.VMName != "my-vm" {
		t.Errorf("vm_name: got %q, want %q", *bp.VMName, "my-vm")
	}
	if *bp.SystemdUnit != unit {
		t.Errorf("systemd_unit: got %q, want %q", *bp.SystemdUnit, unit)
	}
	if bp.StartedAt == nil {
		t.Error("started_at should be set")
	}
	if bp.StartedAt.Location() != time.UTC {
		t.Error("started_at should be UTC")
	}
}

func TestEnumValues(t *testing.T) {
	// TaskStatus
	statuses := AllTaskStatuses()
	if len(statuses) != 6 {
		t.Errorf("expected 6 task statuses, got %d", len(statuses))
	}
	statusSet := map[TaskStatus]bool{}
	for _, s := range statuses {
		statusSet[s] = true
	}
	for _, expected := range []TaskStatus{
		TaskStatusPending, TaskStatusRunning, TaskStatusCompleted,
		TaskStatusFailed, TaskStatusCancelled, TaskStatusCleanupRequired,
	} {
		if !statusSet[expected] {
			t.Errorf("missing task status %q", expected)
		}
	}

	// BackupType
	types := AllBackupTypes()
	if len(types) != 3 {
		t.Errorf("expected 3 backup types, got %d", len(types))
	}

	// EncryptionType
	etypes := AllEncryptionTypes()
	if len(etypes) != 4 {
		t.Errorf("expected 4 encryption types, got %d", len(etypes))
	}
	// Check the critical one
	found := false
	for _, et := range etypes {
		if et == EncryptionTypeAES256GCM {
			found = true
		}
	}
	if !found {
		t.Error("missing aes-256-gcm encryption type")
	}
}

func TestVMInfoFieldNames(t *testing.T) {
	vm := VMInfo{
		Name:      "test-vm",
		UUID:      "abc-123",
		State:     "running",
		MemoryKB:  2048,
		VCPUCount: 2,
		Disks:     []map[string]interface{}{},
		Metadata:  map[string]interface{}{},
	}

	data, _ := json.Marshal(vm)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{"name", "uuid", "state", "memory_kb", "vcpu_count", "disks", "metadata"}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestBackupResultFieldNames(t *testing.T) {
	br := BackupResult{
		BackupID:       "test",
		Success:        true,
		CheckpointName: "cp-1",
		TotalSizeBytes: 1024,
		DurationSecs:   10.5,
		DisksBackedUp:  []map[string]interface{}{},
		Metadata:       map[string]interface{}{},
	}

	data, _ := json.Marshal(br)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{
		"backup_id", "success", "checkpoint_name", "total_size_bytes",
		"duration_seconds", "disks_backed_up", "metadata", "error_message",
		"encrypted", "encryption_type", "s3_location", "local_deleted",
	}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestAgentRegistrationFieldNames(t *testing.T) {
	reg := AgentRegistration{
		Hostname:     "host1",
		IPAddress:    "10.0.0.1",
		Port:         8090,
		LibvirtURI:   "qemu:///system",
		Version:      "5.0.0",
		Capabilities: map[string]interface{}{},
	}

	data, _ := json.Marshal(reg)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{"hostname", "ip_address", "port", "libvirt_uri", "version", "capabilities"}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestRestoreProgressFieldNames(t *testing.T) {
	rp := RestoreProgress{
		RestoreID: "test",
		Status:    TaskStatusRunning,
	}

	data, _ := json.Marshal(rp)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	expected := []string{"restore_id", "status", "progress_percent", "current_operation", "error_message"}
	for _, f := range expected {
		if _, ok := m[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}
