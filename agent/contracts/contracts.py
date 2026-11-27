"""Agent contract definitions — auto-generated from Go structs.

DO NOT EDIT. Run 'make gen-contracts' in the agent/ directory to regenerate.

This module provides:
- Enum value sets (TASK_STATUSES, BACKUP_TYPES, ENCRYPTION_TYPES)
- Model field name sets (e.g., BACKUP_REQUEST_FIELDS)
- Agent version string

Used by backend/tests/test_contracts.py and test_consistency.py to validate
backend→agent payloads without importing Go agent code.
"""

AGENT_VERSION = "6.2.0"

# Enum values
STORAGE_PROTOCOLS = {"vnbui-storage-transaction/1"}
NATIVE_STORAGE_REPRESENTATIONS = {"libvirt-native-fileset/1"}
STORAGE_PROFILES = {"checksum-enforced/1", "consumer-verified/1", "db-rooted-consumer-verified/1"}
STORAGE_TRANSFER_PROFILES = {"kubevirt-32m/1"}
STORAGE_PLAN_OPTIONAL_FIELDS = {"transfer_profile"}
STORAGE_SOURCE_SCHEMA2_FIELDS = {"native_volumes"}
STORAGE_SOURCE_SCHEMAS = {"1", "2"}
STORAGE_NATIVE_DISK_PROFILES = {"kubevirt-native-disks/1"}
TASK_STATUSES = {"pending", "running", "completed", "failed", "cancelled", "cleanup_required"}
BACKUP_TYPES = {"full", "incremental", "differential"}
ENCRYPTION_TYPES = {"none", "fernet", "age", "aes-256-gcm"}

# Model field names (from JSON struct tags)
NATIVE_STORAGE_SOURCE_FIELDS = {"agent_id", "inventory", "inventory_sha256", "representation", "vm_id"}
NATIVE_TRANSACTION_REQUEST_FIELDS = {"agent_id", "backup_id", "org_id", "plan", "plan_sha256", "protocol", "reservation_id"}
NATIVE_STORAGE_PLAN_FIELDS = {"artifacts", "attempt_id", "backup_type", "capability_profile", "checksum_policy", "credential_ref", "encryption", "exclusions", "parent", "provider", "source", "target"}
NATIVE_STORAGE_ARTIFACT_FIELDS = {"artifact_id", "ciphertext_max", "ciphertext_min", "disk_id", "key", "plaintext_max", "plaintext_min", "role"}
NATIVE_STORAGE_RECEIPT_FIELDS = {"backup_id", "bucket", "endpoint", "objects", "protocol", "representation", "reservation_id", "schema"}
NATIVE_STORAGE_OBJECT_RECEIPT_FIELDS = {"artifact_id", "ciphertext_bytes", "ciphertext_sha256", "disk_id", "etag", "key", "plaintext_bytes", "plaintext_sha256", "role", "version_id"}
NATIVE_FILESET_FIELDS = {"attempt_id", "backup_id", "checkpoint", "disks", "domain_uuid", "files", "format", "job_id"}
NATIVE_DISK_FIELDS = {"bus", "id", "serial", "target"}
NATIVE_FILE_FIELDS = {"artifact_id", "ctime_ns", "device", "disk_id", "inode", "member_backup_id", "member_checkpoint", "mtime_ns", "path", "role", "size"}
STORAGE_RECEIPT_FIELDS = {"backup_id", "bucket", "endpoint", "objects", "protocol", "reservation_id", "schema"}
STORAGE_OBJECT_RECEIPT_FIELDS = {"ciphertext_bytes", "ciphertext_sha256", "etag", "key", "plaintext_bytes", "plaintext_sha256", "role", "version_id", "volume_id"}
STORAGE_ACCEPTANCE_FIELDS = {"acceptance_id", "accepted", "protocol", "receipt_sha256", "reservation_id", "scrub_required", "verification"}
STORAGE_FINALIZE_BINDING_FIELDS = {"acceptance_id", "attempt_id", "checkpoint", "guest_consistency", "guest_evidence_source", "namespace", "parent", "plan_sha256", "protocol", "receipt_sha256", "reservation_id", "started_at", "tracker_name", "tracker_uid", "vm_uid", "vmb_name", "vmb_uid", "vmi_uid", "volumes"}
STORAGE_CHECKPOINT_PROOF_FIELDS = {"checkpoint", "checkpoint_creation_time", "guest_consistency", "intent_id", "terminal_resource_version", "tracker_resource_version", "vmb_absent"}
STORAGE_VERIFICATION_FIELDS = {"assurance", "key", "reason", "version_id"}
STORAGE_REQUEST_FIELDS = {"agent_id", "backup_id", "org_id", "plan", "plan_sha256", "protocol", "reservation_id"}
STORAGE_PLAN_FIELDS = {"artifacts", "attempt_id", "backup_type", "capability_profile", "checksum_policy", "credential_ref", "encryption", "exclusions", "parent", "provider", "source", "target", "transfer_profile", "vm_name"}
STORAGE_SOURCE_FIELDS = {"agent_id", "namespace", "native_volumes", "schema", "vm_id", "vm_uid", "vmi_uid", "volumes"}
STORAGE_VOLUME_FIELDS = {"capacity_bytes", "mapping", "name", "pvc_name", "pvc_resource_version", "pvc_uid"}
STORAGE_MAPPING_FIELDS = {"bus", "device", "disk_name", "serial"}
STORAGE_PARENT_FIELDS = {"backup_id", "checkpoint", "generation_id", "receipt_sha256", "root_backup_id", "tracker_uid"}
STORAGE_TARGET_FIELDS = {"bucket", "configuration_prefix", "endpoint", "region"}
STORAGE_ENCRYPTION_FIELDS = {"format", "key_ref"}
STORAGE_ARTIFACT_FIELDS = {"ciphertext_max", "ciphertext_min", "key", "plaintext_max", "plaintext_min", "role", "volume_id"}
BACKUP_REQUEST_FIELDS = {"backup_id", "backup_type", "compression", "encryption_key", "encryption_type", "exclude_disks", "include_disks", "include_raw", "output_path", "parent_path", "vm_name", "vm_namespace", "vm_uid", "workers"}
BACKUP_PROGRESS_FIELDS = {"backup_id", "bytes_transferred", "checkpoint_committed", "current_disk", "current_operation", "error_message", "estimated_completion", "progress_log_path", "progress_percent", "s3_location", "started_at", "status", "storage_path", "systemd_unit", "total_bytes", "transfer_rate_mbps", "vm_name"}
BACKUP_RESULT_FIELDS = {"backup_id", "checkpoint_name", "disks_backed_up", "duration_seconds", "encrypted", "encryption_type", "error_message", "local_deleted", "metadata", "s3_location", "success", "total_size_bytes"}
RESTORE_REQUEST_FIELDS = {"action", "adjust_config", "auto_define", "backup_path", "chain_members", "encryption_key", "encryption_key_hash", "encryption_type", "kubevirt", "native", "restore_id", "restore_path", "s3_config", "selected_disks", "source", "target_name", "until_checkpoint"}
RESTORE_PROGRESS_FIELDS = {"current_operation", "error_message", "progress_percent", "restore_id", "result", "status"}
VM_INFO_FIELDS = {"disks", "memory_kb", "metadata", "name", "namespace", "provider", "state", "uuid", "vcpu_count", "vm_uid", "vmi_uid"}
AGENT_HEARTBEAT_FIELDS = {"active_backups", "active_restores", "backup_storage_free_bytes", "backup_storage_path", "backup_storage_total_bytes", "capabilities", "cpu_cores", "cpu_usage_percent", "disk_usage_percent", "events", "ip_address", "last_error", "libvirt_accessible", "load_average_15m", "memory_usage_percent", "port", "provider", "provider_accessible", "scope", "status", "storage_measurement_error", "storage_role", "version"}
AGENT_REGISTRATION_FIELDS = {"capabilities", "display_name", "hostname", "ip_address", "libvirt_uri", "port", "version"}
HEARTBEAT_RESPONSE_FIELDS = {"agent_id", "config", "s3_config", "status", "timestamp"}
