"""
Tests for incremental backup chain tracking (v4.1).

Covers:
1. Chain resolution: _resolve_chain() assigns chain_id, parent, position
2. Chain retrieval: get_chain() returns ordered, completed members
3. Chain manifest: _upload_chain_manifest() uploads correct JSON to S3
4. S3 restore request: _build_s3_restore_request() builds chain-aware payloads
5. Chain-aware retention: full backups protected while incrementals alive
6. Model fields: chain_id, parent_backup_id, chain_position nullable/persisted
"""

import base64
import json
import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

# Fixtures (db_engine, session_factory, db_session, patch_session_local,
# set_encryption_env, _clean_db) provided by conftest.py


def _make_agent(db_session):
    """Create a minimal agent."""
    from models import Agent

    agent = Agent(
        id=str(uuid.uuid4()),
        hostname=f"host-{uuid.uuid4().hex[:6]}",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    db_session.add(agent)
    db_session.commit()
    return agent


def _make_vm(db_session, agent):
    """Create a minimal VM linked to an agent."""
    from models import VM

    vm = VM(
        id=str(uuid.uuid4()),
        name=f"vm-{uuid.uuid4().hex[:6]}",
        provider="libvirt",
        agent_id=agent.id,
        disks=[{"target": "vda", "format": "qcow2"}],
    )
    db_session.add(vm)
    db_session.commit()
    return vm


def _make_backup(db_session, vm, **kwargs):
    """Create a backup record with sensible defaults."""
    from models import Backup

    defaults = dict(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="pending",
        backup_type="full",
        tags={},
        storage_path=f"file:///var/lib/vnbui/backups/{uuid.uuid4()}",
    )
    defaults.update(kwargs)
    backup = Backup(**defaults)
    db_session.add(backup)
    db_session.commit()
    db_session.refresh(backup)
    return backup


# =============================================================================
# 1. CHAIN RESOLUTION  --  BackupService._resolve_chain()
# =============================================================================


class TestChainResolution:
    """Test _resolve_chain() assigns chain_id, parent_backup_id, chain_position."""

    def _make_service(self, db_session, monkeypatch):
        """Create a BackupService with settings mocked for create_backup."""
        monkeypatch.setattr(
            "core.settings_reader.is_maintenance_mode", lambda db: False
        )
        monkeypatch.setattr(
            "core.settings_reader.get_max_concurrent_backups", lambda db: 100
        )
        monkeypatch.setattr(
            "core.settings_reader.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.settings_reader.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )
        from core.backup_service import BackupService

        return BackupService(db_session)

    def test_full_backup_gets_chain_id_self(self, db_session, monkeypatch):
        """Full backup -> chain_id = self.id, position = 0."""
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        svc = self._make_service(db_session, monkeypatch)

        result = svc.create_backup(vm_id=vm.id, backup_type="full")
        assert result.success
        b = result.backup

        assert b.chain_id == b.id
        assert b.chain_position == 0
        assert b.parent_backup_id is None

    def test_completed_row_does_not_select_native_parent(self, db_session, monkeypatch):
        """Only accepted native generation, not a completed row, selects parent."""
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        svc = self._make_service(db_session, monkeypatch)

        # Create and complete a full backup
        full_result = svc.create_backup(vm_id=vm.id, backup_type="full")
        full = full_result.backup
        full.status = "completed"
        full.completed_at = datetime.utcnow()
        db_session.commit()

        # Create incremental
        inc_result = svc.create_backup(vm_id=vm.id, backup_type="incremental")
        assert inc_result.success
        inc = inc_result.backup

        assert inc.backup_type == "incremental"
        assert inc.parent_backup_id is None
        assert inc.chain_id is None
        assert inc.chain_position is None

    def test_multiple_completed_rows_do_not_infer_native_chain(
        self, db_session, monkeypatch
    ):
        """Source-bound native lineage is admitted later, never guessed here."""
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        svc = self._make_service(db_session, monkeypatch)

        # Full
        full_result = svc.create_backup(vm_id=vm.id, backup_type="full")
        full = full_result.backup
        full.status = "completed"
        full.completed_at = datetime.utcnow()
        db_session.commit()

        # Inc1
        inc1_result = svc.create_backup(vm_id=vm.id, backup_type="incremental")
        inc1 = inc1_result.backup
        inc1.status = "completed"
        inc1.completed_at = datetime.utcnow()
        db_session.commit()

        # Inc2
        inc2_result = svc.create_backup(vm_id=vm.id, backup_type="incremental")
        assert inc2_result.success
        inc2 = inc2_result.backup

        assert inc2.backup_type == "incremental"
        assert inc2.chain_id is None
        assert inc2.parent_backup_id is None
        assert inc2.chain_position is None

    def test_native_incremental_without_baseline_is_not_promoted(
        self, db_session, monkeypatch
    ):
        """No accepted baseline means later refusal, never a different backup type."""
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        svc = self._make_service(db_session, monkeypatch)

        result = svc.create_backup(vm_id=vm.id, backup_type="incremental")
        assert result.success
        b = result.backup

        assert b.backup_type == "incremental"
        assert b.chain_id is None
        assert b.chain_position is None
        assert b.parent_backup_id is None

    def test_incremental_ignores_failed_parent(self, db_session, monkeypatch):
        """Failed rows neither supply native lineage nor change backup type."""
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        svc = self._make_service(db_session, monkeypatch)

        # Create a full backup that failed
        full_result = svc.create_backup(vm_id=vm.id, backup_type="full")
        full = full_result.backup
        full.status = "failed"
        db_session.commit()

        # A failed row cannot supply a parent or change the requested type.
        inc_result = svc.create_backup(vm_id=vm.id, backup_type="incremental")
        assert inc_result.success
        inc = inc_result.backup

        assert inc.backup_type == "incremental"
        assert inc.chain_id is None
        assert inc.chain_position is None


# =============================================================================
# 2. GET CHAIN  --  BackupService.get_chain()
# =============================================================================


class TestGetChain:
    """Test get_chain() returns ordered, completed chain members."""

    def test_get_chain_returns_ordered(self, db_session):
        """Full + 2 incrementals -> returns 3 in chain_position order."""
        from core.backup_service import BackupService

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())

        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            completed_at=datetime.utcnow() - timedelta(hours=3),
        )
        inc1 = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            completed_at=datetime.utcnow() - timedelta(hours=2),
        )
        inc2 = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=inc1.id,
            chain_position=2,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )

        svc = BackupService(db_session)
        chain = svc.get_chain(chain_id)

        assert len(chain) == 3
        assert chain[0].id == full.id
        assert chain[0].chain_position == 0
        assert chain[1].id == inc1.id
        assert chain[1].chain_position == 1
        assert chain[2].id == inc2.id
        assert chain[2].chain_position == 2

    def test_get_chain_excludes_failed(self, db_session):
        """Failed backup in chain not returned by get_chain."""
        from core.backup_service import BackupService

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())

        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            completed_at=datetime.utcnow(),
        )
        _make_backup(
            db_session,
            vm,
            status="failed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
        )

        svc = BackupService(db_session)
        chain = svc.get_chain(chain_id)

        assert len(chain) == 1
        assert chain[0].id == full.id

    def test_get_chain_empty(self, db_session):
        """Nonexistent chain_id -> empty list."""
        from core.backup_service import BackupService

        svc = BackupService(db_session)
        chain = svc.get_chain("nonexistent-chain-id")
        assert chain == []


# =============================================================================
# 3. CHAIN MANIFEST  --  BackupExecutor._upload_chain_manifest()
# =============================================================================


class TestChainManifest:
    """Test _upload_chain_manifest() uploads correct JSON to S3."""

    @pytest.mark.asyncio
    async def test_manifest_structure(self, db_session, patch_session_local):
        """Mock boto3, create 2-backup chain, verify JSON structure."""
        from core.backup_executor import BackupExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())

        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            size_bytes=1024000,
            completed_at=datetime.utcnow() - timedelta(hours=2),
        )
        inc = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            size_bytes=512000,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )

        # Mock S3 config
        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "vnbui-backups",
            "region": "us-east-1",
            "access_key": "test-key",
            "secret_key": "test-secret",
            "prefix": "backups",
        }

        mock_s3_client = MagicMock()
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        with patch(
            "core.settings_service.SettingsService"
        ) as MockSettingsSvc, patch.dict("sys.modules", {"boto3": mock_boto3}):
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = BackupExecutor.__new__(BackupExecutor)
            await executor._upload_chain_manifest(full, db_session)

        # Verify put_object was called
        assert mock_s3_client.put_object.called
        call_kwargs = mock_s3_client.put_object.call_args[1]

        assert call_kwargs["Bucket"] == "vnbui-backups"
        assert call_kwargs["ContentType"] == "application/json"
        assert vm.name in call_kwargs["Key"]
        assert chain_id in call_kwargs["Key"]

        # Parse the body JSON
        manifest = json.loads(call_kwargs["Body"])
        assert manifest["version"] == 1
        assert manifest["chain_id"] == chain_id
        assert manifest["vm_name"] == vm.name
        assert len(manifest["backups"]) == 2

        b0 = manifest["backups"][0]
        assert b0["backup_id"] == full.id
        assert b0["backup_type"] == "full"
        assert b0["chain_position"] == 0
        assert b0["size_bytes"] == 1024000

        b1 = manifest["backups"][1]
        assert b1["backup_id"] == inc.id
        assert b1["backup_type"] == "incremental"
        assert b1["chain_position"] == 1

    @pytest.mark.asyncio
    async def test_manifest_skipped_no_s3(self, db_session, patch_session_local):
        """No S3 config -> no error, no upload."""
        from core.backup_executor import BackupExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            completed_at=datetime.utcnow(),
        )

        with patch("core.settings_service.SettingsService") as MockSettingsSvc:
            MockSettingsSvc.return_value.get_s3_config.return_value = None

            executor = BackupExecutor.__new__(BackupExecutor)
            # Should not raise
            await executor._upload_chain_manifest(full, db_session)

    @pytest.mark.asyncio
    async def test_manifest_includes_encryption(self, db_session, patch_session_local):
        """Backup with encryption_key_id + wrapped_dek -> manifest entry has those fields."""
        from core.backup_executor import BackupExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())
        enc_key_id = str(uuid.uuid4())
        wrapped_dek_b64 = base64.b64encode(os.urandom(48)).decode()

        # Need an encryption key record for FK
        from models import EncryptionKey

        ek = EncryptionKey(
            id=enc_key_id,
            name="test-kek",
            key_hash="abc123",
            encrypted_material="x",
            status="active",
            provider="local",
        )
        db_session.add(ek)
        db_session.commit()

        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            completed_at=datetime.utcnow(),
            encryption_key_id=enc_key_id,
            wrapped_dek=wrapped_dek_b64,
        )

        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "test-bucket",
            "region": "us-east-1",
            "access_key": "ak",
            "secret_key": "sk",
            "prefix": "backups",
        }

        mock_s3_client = MagicMock()
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        with patch(
            "core.settings_service.SettingsService"
        ) as MockSettingsSvc, patch.dict("sys.modules", {"boto3": mock_boto3}):
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = BackupExecutor.__new__(BackupExecutor)
            await executor._upload_chain_manifest(full, db_session)

        call_kwargs = mock_s3_client.put_object.call_args[1]
        manifest = json.loads(call_kwargs["Body"])
        entry = manifest["backups"][0]
        assert entry["encryption_key_id"] == enc_key_id
        assert entry["wrapped_dek"] == wrapped_dek_b64


# =============================================================================
# 4. S3 RESTORE REQUEST  --  RestoreExecutor._build_s3_restore_request()
# =============================================================================


class TestS3RestoreRequest:
    """Test _build_s3_restore_request() builds chain-aware payloads."""

    def _make_restore(self, db_session, backup):
        """Create a minimal Restore record."""
        from models import Restore, User

        # Need a user for created_by
        user = User(
            id=str(uuid.uuid4()),
            username=f"test-{uuid.uuid4().hex[:6]}",
            password_hash="x",
        )
        db_session.add(user)
        db_session.commit()

        restore = Restore(
            id=str(uuid.uuid4()),
            backup_id=backup.id,
            created_by=user.id,
            status="pending",
        )
        db_session.add(restore)
        db_session.commit()
        db_session.refresh(restore)
        return restore

    @pytest.mark.asyncio
    async def test_builds_chain_members(self, db_session, patch_session_local):
        """2-backup chain -> request has 2 chain_members with s3_prefix, chain_position."""
        from core.restore_executor import RestoreExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            storage_path=f"s3://bucket/backups/{chain_id}",
            completed_at=datetime.utcnow() - timedelta(hours=2),
        )
        inc = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            storage_path=f"s3://bucket/backups/{uuid.uuid4()}",
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )

        restore = self._make_restore(db_session, inc)

        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "vnbui-backups",
            "region": "us-east-1",
            "access_key": "ak",
            "secret_key": "sk",
            "prefix": "backups",
        }

        with patch("core.settings_service.SettingsService") as MockSettingsSvc:
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = RestoreExecutor.__new__(RestoreExecutor)
            result = await executor._build_s3_restore_request(restore, inc, db_session)

        assert result is not None
        assert result["source"] == "s3"
        assert len(result["chain_members"]) == 2

        m0 = result["chain_members"][0]
        assert m0["backup_id"] == full.id
        assert m0["chain_position"] == 0
        assert "backups/" in m0["s3_prefix"]

        m1 = result["chain_members"][1]
        assert m1["backup_id"] == inc.id
        assert m1["chain_position"] == 1

    @pytest.mark.asyncio
    async def test_unwraps_deks_per_member(self, db_session, patch_session_local):
        """Chain with encrypted backups -> each member gets unwrapped DEK."""
        from core.restore_executor import RestoreExecutor
        from core.kms.registry import reset_provider
        from core.kms.local import LocalKMSProvider

        reset_provider()
        kms = LocalKMSProvider()

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        # Create KMS key and wrap DEKs
        key = await kms.create_key("chain-enc-key")
        dek_full = os.urandom(32)
        dek_inc = os.urandom(32)
        wrapped_full = await kms.wrap_dek(dek_full, key.id)
        wrapped_inc = await kms.wrap_dek(dek_inc, key.id)

        chain_id = str(uuid.uuid4())
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            storage_path=f"s3://bucket/backups/{chain_id}",
            completed_at=datetime.utcnow() - timedelta(hours=2),
            encryption_key_id=key.id,
            wrapped_dek=base64.b64encode(wrapped_full).decode(),
            tags={"encrypted": True, "encryption_type": "aes-256-gcm"},
        )
        inc = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            storage_path=f"s3://bucket/backups/{uuid.uuid4()}",
            completed_at=datetime.utcnow() - timedelta(hours=1),
            encryption_key_id=key.id,
            wrapped_dek=base64.b64encode(wrapped_inc).decode(),
            tags={"encrypted": True, "encryption_type": "aes-256-gcm"},
        )

        restore = self._make_restore(db_session, inc)

        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "test-bucket",
            "region": "us-east-1",
            "access_key": "ak",
            "secret_key": "sk",
            "prefix": "backups",
        }

        with patch("core.settings_service.SettingsService") as MockSettingsSvc:
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = RestoreExecutor.__new__(RestoreExecutor)
            result = await executor._build_s3_restore_request(restore, inc, db_session)

        assert result is not None
        assert len(result["chain_members"]) == 2

        # Verify each member has an encryption_key (unwrapped DEK)
        for member in result["chain_members"]:
            assert "encryption_key" in member
            assert "encryption_type" in member

        # Verify the actual DEK values are correct by decoding
        m0_dek = base64.b64decode(result["chain_members"][0]["encryption_key"])
        m1_dek = base64.b64decode(result["chain_members"][1]["encryption_key"])
        assert m0_dek == dek_full
        assert m1_dek == dek_inc

    @pytest.mark.asyncio
    async def test_fails_if_no_chain(self, db_session, patch_session_local):
        """Backup with no chain -> returns None, restore status=failed."""
        from core.restore_executor import RestoreExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        backup = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="full",
            chain_id=str(uuid.uuid4()),  # chain_id that has no members in DB
            chain_position=0,
            storage_path="s3://bucket/backups/test",
            completed_at=datetime.utcnow(),
        )
        # The backup itself is completed but get_chain queries for chain_id
        # that won't match because backup.chain_id != backup.id and no
        # other backups share it. Actually, let's use a chain_id that
        # points to nothing completed.
        # We need the chain query to return empty. Set the backup status
        # to something other than completed so get_chain finds nothing.
        backup.status = "failed"
        db_session.commit()

        # Re-create a pending backup to test against
        backup2 = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="full",
            chain_id="orphan-chain-id",  # No other backups in this chain
            chain_position=0,
            storage_path="s3://bucket/backups/test",
            completed_at=datetime.utcnow(),
        )
        # Make chain_id point to a nonexistent chain by removing this backup from completed
        backup2.status = "failed"
        db_session.commit()

        restore = self._make_restore(db_session, backup2)

        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "test-bucket",
            "region": "us-east-1",
            "access_key": "ak",
            "secret_key": "sk",
            "prefix": "backups",
        }

        with patch("core.settings_service.SettingsService") as MockSettingsSvc:
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = RestoreExecutor.__new__(RestoreExecutor)
            result = await executor._build_s3_restore_request(
                restore, backup2, db_session
            )

        assert result is None
        db_session.refresh(restore)
        assert restore.status == "failed"
        assert "No chain" in restore.error_message

    @pytest.mark.asyncio
    async def test_respects_chain_position(self, db_session, patch_session_local):
        """Restoring from inc1 (position=1) -> only includes position 0 and 1, not 2."""
        from core.restore_executor import RestoreExecutor

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            storage_path=f"s3://bucket/backups/{chain_id}",
            completed_at=datetime.utcnow() - timedelta(hours=3),
        )
        inc1 = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            storage_path=f"s3://bucket/backups/{uuid.uuid4()}",
            completed_at=datetime.utcnow() - timedelta(hours=2),
        )
        _inc2 = _make_backup(  # noqa: F841
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=inc1.id,
            chain_position=2,
            storage_path=f"s3://bucket/backups/{uuid.uuid4()}",
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )

        # Restore from inc1 (position 1), not inc2
        restore = self._make_restore(db_session, inc1)

        mock_s3_config = {
            "endpoint": "https://minio.example.com",
            "bucket": "test-bucket",
            "region": "us-east-1",
            "access_key": "ak",
            "secret_key": "sk",
            "prefix": "backups",
        }

        with patch("core.settings_service.SettingsService") as MockSettingsSvc:
            MockSettingsSvc.return_value.get_s3_config.return_value = mock_s3_config

            executor = RestoreExecutor.__new__(RestoreExecutor)
            result = await executor._build_s3_restore_request(restore, inc1, db_session)

        assert result is not None
        # Should only include position 0 and 1, not 2
        positions = [m["chain_position"] for m in result["chain_members"]]
        assert 0 in positions
        assert 1 in positions
        assert 2 not in positions
        assert len(result["chain_members"]) == 2


# =============================================================================
# 5. CHAIN-AWARE RETENTION
# =============================================================================


class TestChainAwareRetention:
    """Test that retention enforcement respects chain dependencies."""

    @pytest.mark.asyncio
    async def test_full_protected_while_inc_active(
        self, db_session, patch_session_local
    ):
        """Full backup expired but incremental is not -> full NOT deleted."""
        from core.retention import RetentionPolicyEnforcer

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())

        # Full backup: expired (completed 60 days ago, retention 30 days)
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            retention_days=30,
            completed_at=datetime.utcnow() - timedelta(days=60),
        )

        # Incremental: NOT expired (completed 10 days ago, retention 30 days)
        _inc = _make_backup(  # noqa: F841
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            retention_days=30,
            completed_at=datetime.utcnow() - timedelta(days=10),
        )

        enforcer = RetentionPolicyEnforcer()
        enforcer.dry_run = True  # Don't actually delete

        # Mock enforce_all's DB access to use our session
        with patch("core.retention.SessionLocal", lambda: db_session), patch(
            "core.retention.get_setting", return_value=True
        ), patch.object(
            enforcer, "_cleanup_orphaned_manifests", new_callable=AsyncMock
        ):
            result = await enforcer.enforce_all()

        # Full should NOT have been "deleted" (dry_run counts it)
        # In dry_run mode, _delete_backup still runs but logs instead
        # The key check: full should be skipped because chain is protected
        assert result["deleted_count"] == 0

        # Verify both backups still exist
        from models import Backup

        remaining = (
            db_session.query(Backup).filter(Backup.status == "completed").count()
        )
        assert remaining == 2

    @pytest.mark.asyncio
    async def test_full_deleted_when_all_expired(self, db_session, patch_session_local):
        """Full and all incrementals expired -> full IS deleted."""
        from core.retention import RetentionPolicyEnforcer

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())

        # Full: expired
        full = _make_backup(
            db_session,
            vm,
            id=chain_id,
            status="completed",
            backup_type="full",
            chain_id=chain_id,
            chain_position=0,
            retention_days=30,
            completed_at=datetime.utcnow() - timedelta(days=60),
        )

        # Incremental: also expired
        _inc = _make_backup(  # noqa: F841
            db_session,
            vm,
            status="completed",
            backup_type="incremental",
            chain_id=chain_id,
            parent_backup_id=full.id,
            chain_position=1,
            retention_days=30,
            completed_at=datetime.utcnow() - timedelta(days=60),
        )

        enforcer = RetentionPolicyEnforcer()
        enforcer.dry_run = True

        with patch("core.retention.SessionLocal", lambda: db_session), patch(
            "core.retention.get_setting", return_value=True
        ), patch.object(
            enforcer, "_cleanup_orphaned_manifests", new_callable=AsyncMock
        ):
            result = await enforcer.enforce_all()

        # Both expired and chain has no non-expired members -> both "deleted"
        assert result["deleted_count"] == 2

    @pytest.mark.asyncio
    async def test_non_chain_backup_unaffected(self, db_session, patch_session_local):
        """Backup without chain_id deleted normally when expired."""
        from core.retention import RetentionPolicyEnforcer

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        # Non-chain backup: expired
        _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="full",
            chain_id=None,
            chain_position=None,
            retention_days=30,
            completed_at=datetime.utcnow() - timedelta(days=60),
        )

        enforcer = RetentionPolicyEnforcer()
        enforcer.dry_run = True

        with patch("core.retention.SessionLocal", lambda: db_session), patch(
            "core.retention.get_setting", return_value=True
        ), patch.object(
            enforcer, "_cleanup_orphaned_manifests", new_callable=AsyncMock
        ):
            result = await enforcer.enforce_all()

        assert result["deleted_count"] == 1


# =============================================================================
# 6. MODEL FIELDS
# =============================================================================


class TestBackupChainModel:
    """Test chain fields on Backup model."""

    def test_chain_fields_nullable(self, db_session):
        """Backup without chain fields -> all NULL."""
        from models import Backup

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        backup = _make_backup(db_session, vm, status="completed")

        fetched = db_session.query(Backup).filter(Backup.id == backup.id).first()
        assert fetched.chain_id is None
        assert fetched.parent_backup_id is None
        assert fetched.chain_position is None

    def test_chain_fields_set(self, db_session):
        """Backup with chain_id, parent_backup_id, chain_position -> all persisted."""
        from models import Backup

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        chain_id = str(uuid.uuid4())
        parent_id = str(uuid.uuid4())

        # Create parent first (for FK if enabled)
        _parent = _make_backup(  # noqa: F841
            db_session,
            vm,
            id=parent_id,
            status="completed",
            chain_id=chain_id,
            chain_position=0,
        )

        child = _make_backup(
            db_session,
            vm,
            status="completed",
            chain_id=chain_id,
            parent_backup_id=parent_id,
            chain_position=1,
        )

        fetched = db_session.query(Backup).filter(Backup.id == child.id).first()
        assert fetched.chain_id == chain_id
        assert fetched.parent_backup_id == parent_id
        assert fetched.chain_position == 1
