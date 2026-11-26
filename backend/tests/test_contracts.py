"""Contract tests: verify backend→agent payloads match agent model definitions.

These tests import the SAME builder functions the backend uses to construct
agent request dicts, then validate them against the agent's contract definitions
(field name sets and enum value sets generated from Go structs).

Catches at test time:
- Enum value mismatches (e.g., backend sends "aes-256-gcm" but agent doesn't have it)
- Missing/extra fields in request dicts
- Response shape drift (fields backend reads from agent that don't exist)
"""

import base64
import os
import sys

# Path setup (also in conftest.py, but explicit here for standalone clarity)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent"))

from contracts.contracts import (  # noqa: E402
    TASK_STATUSES,
    BACKUP_TYPES,
    ENCRYPTION_TYPES,
    BACKUP_REQUEST_FIELDS,
    BACKUP_PROGRESS_FIELDS,
    RESTORE_REQUEST_FIELDS,
    RESTORE_PROGRESS_FIELDS,
    AGENT_HEARTBEAT_FIELDS,
    HEARTBEAT_RESPONSE_FIELDS,
)

from core.agent_requests import (  # noqa: E402
    build_backup_request,
    build_restore_request,
    build_s3_restore_request,
    build_s3_config,
    build_chain_member,
    build_heartbeat_response,
)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. ENUM PARITY — verify every string the backend can send is a valid enum
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnumParity:
    """Ensure backend string literals match agent enum values."""

    def test_encryption_type_aes_256_gcm(self):
        """The most critical contract: KMS envelope encryption type."""
        assert "aes-256-gcm" in ENCRYPTION_TYPES

    def test_encryption_type_fernet(self):
        """Legacy encryption type."""
        assert "fernet" in ENCRYPTION_TYPES

    def test_encryption_type_none(self):
        """No encryption."""
        assert "none" in ENCRYPTION_TYPES

    def test_backup_type_full(self):
        assert "full" in BACKUP_TYPES

    def test_backup_type_incremental(self):
        assert "incremental" in BACKUP_TYPES

    def test_backup_type_differential(self):
        assert "differential" in BACKUP_TYPES

    def test_task_status_values(self):
        """All status values the backend can set on a backup/restore."""
        expected = {
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "cleanup_required",
        }
        assert expected == TASK_STATUSES

    def test_encryption_type_env_var_values(self):
        """ENCRYPTION_TYPE env var can produce any of these — all must be valid."""
        for val in ["fernet", "aes-256-gcm", "none"]:
            assert val in ENCRYPTION_TYPES, f"{val} not in ENCRYPTION_TYPES"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. BACKUP REQUEST — uses the real build_backup_request() from the backend
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackupRequestContract:
    """Validate build_backup_request() output against agent's BackupRequest fields."""

    def test_basic_backup_no_encryption(self):
        d = build_backup_request(
            backup_id="test-001",
            vm_name="my-vm",
            backup_type="full",
            output_path="/var/lib/vnbui/backups/test-001",
        )
        assert set(d.keys()).issubset(BACKUP_REQUEST_FIELDS)
        assert d["backup_id"] == "test-001"
        assert d["backup_type"] in BACKUP_TYPES
        assert d["compression"] is None
        assert "encryption_type" not in d  # Omitted when no encryption

    def test_kms_envelope_encryption(self):
        dek = os.urandom(32)
        d = build_backup_request(
            backup_id="test-002",
            vm_name="encrypted-vm",
            backup_type="incremental",
            output_path="/var/lib/vnbui/backups/test-002",
            compression="5",
            exclude_disks=["vdb"],
            workers=4,
            encryption_type="aes-256-gcm",
            encryption_key=base64.b64encode(dek).decode(),
        )
        assert set(d.keys()).issubset(BACKUP_REQUEST_FIELDS)
        assert d["encryption_type"] in ENCRYPTION_TYPES
        assert d["encryption_key"] == base64.b64encode(dek).decode()
        assert d["backup_type"] in BACKUP_TYPES

    def test_legacy_fernet_encryption(self):
        from cryptography.fernet import Fernet

        fernet_key = Fernet.generate_key().decode()
        d = build_backup_request(
            backup_id="test-003",
            vm_name="legacy-vm",
            backup_type="full",
            output_path="/var/lib/vnbui/backups/test-003",
            encryption_type="fernet",
            encryption_key=fernet_key,
        )
        assert set(d.keys()).issubset(BACKUP_REQUEST_FIELDS)
        assert d["encryption_type"] in ENCRYPTION_TYPES

    def test_all_backup_types(self):
        for bt in ["full", "incremental", "differential"]:
            d = build_backup_request(
                backup_id=f"test-{bt}",
                vm_name="vm1",
                backup_type=bt,
                output_path=f"/tmp/{bt}",
            )
            assert d["backup_type"] in BACKUP_TYPES

    def test_all_compression_levels(self):
        for comp in [None, "2", "5", "9"]:
            d = build_backup_request(
                backup_id=f"test-comp-{comp}",
                vm_name="vm1",
                backup_type="full",
                output_path="/tmp/test",
                compression=comp,
            )
            assert d["compression"] == comp

    def test_exclude_disks_list(self):
        d = build_backup_request(
            backup_id="test-disks",
            vm_name="vm1",
            backup_type="full",
            output_path="/tmp/test",
            exclude_disks=["vdb", "vdc"],
        )
        assert d["exclude_disks"] == ["vdb", "vdc"]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. RESTORE REQUEST — uses the real build_restore_request() builders
# ═══════════════════════════════════════════════════════════════════════════════


class TestRestoreRequestContract:
    """Validate restore request builders against agent's RestoreRequest fields."""

    def test_basic_local_restore(self):
        d = build_restore_request(
            restore_id="restore-001",
            backup_path="/var/lib/vnbui/backups/backup-001",
            restore_path="/var/lib/vnbui/restores/restore-001",
        )
        assert set(d.keys()).issubset(RESTORE_REQUEST_FIELDS)
        assert d["restore_id"] == "restore-001"

    def test_encrypted_local_restore_envelope(self):
        dek = os.urandom(32)
        d = build_restore_request(
            restore_id="restore-002",
            backup_path="/var/lib/vnbui/backups/backup-002",
            restore_path="/var/lib/vnbui/restores/restore-002",
            target_name="restored-vm",
            auto_define=True,
            adjust_config=True,
            encryption_type="aes-256-gcm",
            encryption_key=base64.b64encode(dek).decode(),
            encryption_key_hash="abcdef0123456789",
        )
        assert set(d.keys()).issubset(RESTORE_REQUEST_FIELDS)
        assert d["encryption_type"] in ENCRYPTION_TYPES
        assert d["auto_define"] is True

    def test_encrypted_local_restore_legacy(self):
        d = build_restore_request(
            restore_id="restore-003",
            backup_path="/var/lib/vnbui/backups/backup-003",
            restore_path="/var/lib/vnbui/restores/restore-003",
            selected_disks=["vda"],
            encryption_type="fernet",
            encryption_key="some-fernet-key",
            encryption_key_hash="abcdef0123456789",
        )
        assert set(d.keys()).issubset(RESTORE_REQUEST_FIELDS)
        assert d["encryption_type"] in ENCRYPTION_TYPES

    def test_s3_chain_restore(self):
        dek = os.urandom(32)
        d = build_s3_restore_request(
            restore_id="restore-004",
            restore_path="/var/lib/vnbui/restores/restore-004",
            s3_config=build_s3_config(
                endpoint="https://minio.example.com:9000",
                bucket="backups",
                region="us-east-1",
                access_key="minioadmin",
                secret_key="minioadmin",
            ),
            chain_members=[
                build_chain_member(
                    backup_id="backup-full-001",
                    s3_prefix="backups/backup-full-001/",
                    chain_position=0,
                    encryption_key=base64.b64encode(dek).decode(),
                    encryption_type="aes-256-gcm",
                ),
                build_chain_member(
                    backup_id="backup-inc-002",
                    s3_prefix="backups/backup-inc-002/",
                    chain_position=1,
                ),
            ],
            target_name="restored-vm",
        )
        assert set(d.keys()).issubset(RESTORE_REQUEST_FIELDS)
        assert d["source"] == "s3"
        assert d["s3_config"] is not None
        assert len(d["chain_members"]) == 2

    def test_s3_restore_no_encryption(self):
        d = build_s3_restore_request(
            restore_id="restore-005",
            restore_path="/var/lib/vnbui/restores/restore-005",
            s3_config=build_s3_config(
                endpoint=None,
                bucket="my-bucket",
                region="us-east-1",
                access_key="key",
                secret_key="secret",
            ),
            chain_members=[
                build_chain_member(
                    backup_id="backup-001",
                    s3_prefix="backups/backup-001/",
                    chain_position=0,
                ),
            ],
        )
        assert set(d.keys()).issubset(RESTORE_REQUEST_FIELDS)
        assert d["source"] == "s3"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. BACKUP PROGRESS — verify fields the backend reads from agent responses
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackupProgressContract:
    """Verify BackupProgress has every field monitor_backup() reads via .get()."""

    def test_all_monitored_fields_exist(self):
        """Fields read in backup_executor.py:397-428 must exist on BackupProgress."""
        monitored_fields = [
            "status",
            "progress_percent",
            "bytes_transferred",
            "error_message",
            "transfer_rate_mbps",
            "estimated_completion",
            "current_disk",
        ]
        for field in monitored_fields:
            assert (
                field in BACKUP_PROGRESS_FIELDS
            ), f"BackupProgress missing field '{field}' that backend reads"

    def test_backup_progress_has_tracking_fields(self):
        """BackupProgress must have systemd_unit and vm_name for tracking."""
        assert "systemd_unit" in BACKUP_PROGRESS_FIELDS
        assert "vm_name" in BACKUP_PROGRESS_FIELDS

    def test_backup_progress_fields_complete(self):
        """BackupProgress must have all expected fields."""
        expected = {
            "backup_id",
            "status",
            "vm_name",
            "systemd_unit",
            "storage_path",
            "progress_log_path",
            "progress_percent",
            "current_disk",
            "bytes_transferred",
            "total_bytes",
            "transfer_rate_mbps",
            "started_at",
            "estimated_completion",
            "error_message",
            "s3_location",
            "current_operation",
            "checkpoint_committed",
        }
        assert expected == BACKUP_PROGRESS_FIELDS


class TestRestoreProgressContract:
    """Verify RestoreProgress has fields the backend reads."""

    def test_restore_progress_fields(self):
        expected = {
            "restore_id",
            "status",
            "progress_percent",
            "current_operation",
            "error_message",
            "result",
        }
        assert expected == RESTORE_PROGRESS_FIELDS


# ═══════════════════════════════════════════════════════════════════════════════
# 5. HEARTBEAT RESPONSE — uses the real build_heartbeat_response()
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeartbeatResponseContract:
    """Verify heartbeat response shape (health.py:434-440)."""

    def test_heartbeat_response_shape(self):
        d = build_heartbeat_response(
            agent_id="agent-001",
            timestamp="2026-03-08T12:00:00Z",
            config={},
        )
        assert HEARTBEAT_RESPONSE_FIELDS == set(d.keys())

    def test_heartbeat_response_with_s3(self):
        d = build_heartbeat_response(
            agent_id="agent-001",
            timestamp="2026-03-08T12:00:00Z",
            config={"backup_path": "/var/lib/vnbui"},
            s3_config={
                "endpoint": "https://minio:9000",
                "bucket": "backups",
                "region": "us-east-1",
                "access_key": "key",
                "secret_key": "secret",
                "prefix": "backups",
                "delete_local_after_upload": False,
            },
        )
        assert HEARTBEAT_RESPONSE_FIELDS.issubset(set(d.keys()))
        assert d["s3_config"]["bucket"] == "backups"

    def test_heartbeat_response_null_config(self):
        """Backend passes agent.config which can be None."""
        d = build_heartbeat_response(
            agent_id="agent-001",
            timestamp="2026-03-08T12:00:00Z",
            config=None,
        )
        assert d["config"] == {}  # Builder normalizes None → {}


# ═══════════════════════════════════════════════════════════════════════════════
# 6. AGENT HEARTBEAT REQUEST — verify agent→backend heartbeat shape
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentHeartbeatContract:
    """Verify the AgentHeartbeat field set covers what the backend expects."""

    def test_minimal_heartbeat_fields(self):
        """Heartbeat must have status and events at minimum."""
        assert "status" in AGENT_HEARTBEAT_FIELDS
        assert "events" in AGENT_HEARTBEAT_FIELDS

    def test_full_heartbeat_fields(self):
        """All expected heartbeat fields must be present."""
        expected = {
            "status",
            "provider",
            "capabilities",
            "scope",
            "storage_role",
            "storage_measurement_error",
            "version",
            "ip_address",
            "port",
            "active_backups",
            "active_restores",
            "cpu_usage_percent",
            "memory_usage_percent",
            "cpu_cores",
            "load_average_15m",
            "disk_usage_percent",
            "backup_storage_path",
            "backup_storage_free_bytes",
            "backup_storage_total_bytes",
            "libvirt_accessible",
            "provider_accessible",
            "last_error",
            "events",
        }
        assert expected == AGENT_HEARTBEAT_FIELDS


# ═══════════════════════════════════════════════════════════════════════════════
# 7. BUILDER UNIT TESTS — verify builder functions themselves
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuilderFunctions:
    """Verify builder functions produce correct dict shapes."""

    def test_build_chain_member_no_encryption(self):
        m = build_chain_member("b-001", "backups/b-001/", 0)
        assert m == {
            "backup_id": "b-001",
            "s3_prefix": "backups/b-001/",
            "chain_position": 0,
        }
        assert "encryption_key" not in m

    def test_build_chain_member_with_encryption(self):
        m = build_chain_member(
            "b-001",
            "backups/b-001/",
            0,
            encryption_key="abc",
            encryption_type="aes-256-gcm",
        )
        assert m["encryption_key"] == "abc"
        assert m["encryption_type"] == "aes-256-gcm"

    def test_build_s3_config_null_endpoint(self):
        c = build_s3_config(
            endpoint=None, bucket="b", region=None, access_key="a", secret_key="s"
        )
        assert c["endpoint"] is None
        assert c["region"] == "us-east-1"

    def test_build_backup_request_no_encryption_omits_fields(self):
        d = build_backup_request("id", "vm", "full", "/tmp/out")
        assert "encryption_type" not in d
        assert "encryption_key" not in d

    def test_build_restore_request_no_encryption_omits_fields(self):
        d = build_restore_request("id", "/path", "/out")
        assert "encryption_type" not in d
        assert "encryption_key" not in d
        assert "encryption_key_hash" not in d
