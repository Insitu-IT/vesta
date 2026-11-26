// gen-contracts generates agent/contracts/contracts.py from Go model structs.
//
// It uses reflection to extract JSON tags from all model types and writes
// a Python module containing field name sets and enum value sets. This file
// is used by backend contract tests to validate backend→agent payloads
// without importing the Go agent code.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func jsonFields(t reflect.Type) []string {
	var fields []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
}

func formatSet(name string, values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf("%s = {%s}", name, strings.Join(quoted, ", "))
}

func main() {
	// Read version from VERSION file
	exePath, _ := os.Executable()
	agentDir := filepath.Dir(filepath.Dir(filepath.Dir(exePath)))

	// Try VERSION relative to working directory first, then relative to executable
	version := "0.0.0"
	for _, base := range []string{".", agentDir} {
		data, err := os.ReadFile(filepath.Join(base, "VERSION"))
		if err == nil {
			version = strings.TrimSpace(string(data))
			break
		}
	}

	// Collect enum values
	taskStatuses := make([]string, 0)
	for _, v := range models.AllTaskStatuses() {
		taskStatuses = append(taskStatuses, string(v))
	}

	backupTypes := make([]string, 0)
	for _, v := range models.AllBackupTypes() {
		backupTypes = append(backupTypes, string(v))
	}

	encryptionTypes := make([]string, 0)
	for _, v := range models.AllEncryptionTypes() {
		encryptionTypes = append(encryptionTypes, string(v))
	}

	// Collect struct fields via reflection
	type modelDef struct {
		pyName string
		goType reflect.Type
	}

	defs := []modelDef{
		{"NATIVE_STORAGE_SOURCE_FIELDS", reflect.TypeOf(models.NativeStorageSource{})},
		{"NATIVE_TRANSACTION_REQUEST_FIELDS", reflect.TypeOf(models.NativeTransactionRequest{})},
		{"NATIVE_STORAGE_PLAN_FIELDS", reflect.TypeOf(models.NativeStoragePlan{})},
		{"NATIVE_STORAGE_ARTIFACT_FIELDS", reflect.TypeOf(models.NativeStorageArtifact{})},
		{"NATIVE_STORAGE_RECEIPT_FIELDS", reflect.TypeOf(models.NativeStorageReceipt{})},
		{"NATIVE_STORAGE_OBJECT_RECEIPT_FIELDS", reflect.TypeOf(models.NativeStorageObjectReceipt{})},
		{"NATIVE_FILESET_FIELDS", reflect.TypeOf(models.NativeFileSet{})},
		{"NATIVE_DISK_FIELDS", reflect.TypeOf(models.NativeDisk{})},
		{"NATIVE_FILE_FIELDS", reflect.TypeOf(models.NativeFile{})},
		{"STORAGE_RECEIPT_FIELDS", reflect.TypeOf(models.StorageReceipt{})},
		{"STORAGE_OBJECT_RECEIPT_FIELDS", reflect.TypeOf(models.StorageObjectReceipt{})},
		{"STORAGE_ACCEPTANCE_FIELDS", reflect.TypeOf(models.StorageAcceptance{})},
		{"STORAGE_FINALIZE_BINDING_FIELDS", reflect.TypeOf(storageupload.FinalizeBinding{})},
		{"STORAGE_CHECKPOINT_PROOF_FIELDS", reflect.TypeOf(storageupload.CheckpointProof{})},
		{"STORAGE_VERIFICATION_FIELDS", reflect.TypeOf(models.StorageVerification{})},
		{"STORAGE_REQUEST_FIELDS", reflect.TypeOf(models.StorageTransactionRequest{})},
		{"STORAGE_PLAN_FIELDS", reflect.TypeOf(models.StorageTransactionPlan{})},
		{"STORAGE_SOURCE_FIELDS", reflect.TypeOf(models.StorageSource{})},
		{"STORAGE_VOLUME_FIELDS", reflect.TypeOf(models.StorageVolume{})},
		{"STORAGE_MAPPING_FIELDS", reflect.TypeOf(models.StorageDiskMapping{})},
		{"STORAGE_PARENT_FIELDS", reflect.TypeOf(models.StorageParent{})},
		{"STORAGE_TARGET_FIELDS", reflect.TypeOf(models.StorageTarget{})},
		{"STORAGE_ENCRYPTION_FIELDS", reflect.TypeOf(models.StorageEncryption{})},
		{"STORAGE_ARTIFACT_FIELDS", reflect.TypeOf(models.StorageArtifact{})},
		{"BACKUP_REQUEST_FIELDS", reflect.TypeOf(models.BackupRequest{})},
		{"BACKUP_PROGRESS_FIELDS", reflect.TypeOf(models.BackupProgress{})},
		{"BACKUP_RESULT_FIELDS", reflect.TypeOf(models.BackupResult{})},
		{"RESTORE_REQUEST_FIELDS", reflect.TypeOf(models.RestoreRequest{})},
		{"RESTORE_PROGRESS_FIELDS", reflect.TypeOf(models.RestoreProgress{})},
		{"VM_INFO_FIELDS", reflect.TypeOf(models.VMInfo{})},
		{"AGENT_HEARTBEAT_FIELDS", reflect.TypeOf(models.AgentHeartbeat{})},
		{"AGENT_REGISTRATION_FIELDS", reflect.TypeOf(models.AgentRegistration{})},
		{"HEARTBEAT_RESPONSE_FIELDS", reflect.TypeOf(models.HeartbeatResponse{})},
	}

	var b strings.Builder
	b.WriteString(`"""Agent contract definitions — auto-generated from Go structs.

DO NOT EDIT. Run 'make gen-contracts' in the agent/ directory to regenerate.

This module provides:
- Enum value sets (TASK_STATUSES, BACKUP_TYPES, ENCRYPTION_TYPES)
- Model field name sets (e.g., BACKUP_REQUEST_FIELDS)
- Agent version string

Used by backend/tests/test_contracts.py and test_consistency.py to validate
backend→agent payloads without importing Go agent code.
"""

`)
	b.WriteString(fmt.Sprintf("AGENT_VERSION = %q\n\n", version))

	b.WriteString("# Enum values\n")
	b.WriteString(formatSet("STORAGE_PROTOCOLS", []string{models.StorageProtocol}) + "\n")
	b.WriteString(formatSet("NATIVE_STORAGE_REPRESENTATIONS", []string{models.NativeFileSetFormat}) + "\n")
	b.WriteString(formatSet("STORAGE_PROFILES", models.StorageProfiles()) + "\n")
	b.WriteString(formatSet("STORAGE_TRANSFER_PROFILES", []string{models.KubevirtTransfer32}) + "\n")
	b.WriteString(formatSet("STORAGE_PLAN_OPTIONAL_FIELDS", []string{"transfer_profile"}) + "\n")
	b.WriteString(formatSet("STORAGE_SOURCE_SCHEMA2_FIELDS", []string{"native_volumes"}) + "\n")
	b.WriteString(formatSet("STORAGE_SOURCE_SCHEMAS", []string{"1", "2"}) + "\n")
	b.WriteString(formatSet("STORAGE_NATIVE_DISK_PROFILES", []string{models.KubevirtNativeDisks}) + "\n")
	b.WriteString(formatSet("TASK_STATUSES", taskStatuses) + "\n")
	b.WriteString(formatSet("BACKUP_TYPES", backupTypes) + "\n")
	b.WriteString(formatSet("ENCRYPTION_TYPES", encryptionTypes) + "\n")

	b.WriteString("\n# Model field names (from JSON struct tags)\n")
	for _, d := range defs {
		fields := jsonFields(d.goType)
		b.WriteString(formatSet(d.pyName, fields) + "\n")
	}

	// Determine output path
	outPath := "contracts/contracts.py"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s (%d bytes)\n", outPath, len(b.String()))
}
