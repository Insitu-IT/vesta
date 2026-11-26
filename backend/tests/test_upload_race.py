"""Tests for S3 upload phase race conditions and status handling.

Covers:
- Heartbeat not regressing from uploading/upload_failed to completed
- loose-bound upload work refuses without changing local completion evidence
- Valid status transitions during upload lifecycle
"""

import asyncio
import os
import sys
import uuid

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# Ensure backend + agent are on path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
TESTS_DIR = os.path.join(BACKEND_DIR, "tests")
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, os.path.join(PROJECT_DIR, "agent"))
sys.path.insert(0, TESTS_DIR)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _run(coro):
    """Run async in sync test."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_agent(db_session, hostname="ctrl01"):
    from models import Agent

    agent = Agent(
        id=str(uuid.uuid4()),
        hostname=hostname,
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    db_session.add(agent)
    db_session.commit()
    return agent


def _make_vm(db_session, agent, name="test-vm"):
    from models import VM

    vm = VM(
        id=str(uuid.uuid4()),
        name=name,
        agent_id=agent.id,
        state="running",
        uuid=str(uuid.uuid4()),
        memory_kb=2048,
        vcpu_count=2,
        disks=[{"target": "vda", "format": "qcow2"}],
    )
    db_session.add(vm)
    db_session.commit()
    return vm


def _make_backup(db_session, vm, **kwargs):
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


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def agent_and_vm(db_session):
    """Create agent + VM for heartbeat tests."""
    agent = _make_agent(db_session)
    vm = _make_vm(db_session, agent, name="alex-desktop-linux")
    return agent, vm


def _reconciled_event(backup_id, new_status, old_status="running"):
    return {
        "type": "backup_reconciled",
        "backup_id": backup_id,
        "new_status": new_status,
        "old_status": old_status,
        "reason": "test event",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Heartbeat reconciliation: status regression guard
# ═══════════════════════════════════════════════════════════════════════════════


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
def test_heartbeat_does_not_regress_uploading_to_completed(
    mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """Stale 'completed' event from backup phase must not overwrite 'uploading'."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="uploading")

    _run(
        _process_agent_events(
            agent, [_reconciled_event(backup.id, "completed")], db_session
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "uploading"


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
def test_heartbeat_does_not_regress_upload_failed_to_completed(
    mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """Stale 'completed' event must not overwrite 'upload_failed'."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(
        db_session, vm, status="upload_failed", tags={"upload_error": "stalled"}
    )

    _run(
        _process_agent_events(
            agent, [_reconciled_event(backup.id, "completed")], db_session
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "upload_failed"


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
def test_heartbeat_allows_upload_failed_on_uploading(
    mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """upload_failed should be accepted when backup is currently uploading."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="uploading")

    _run(
        _process_agent_events(
            agent,
            [_reconciled_event(backup.id, "upload_failed", "uploading")],
            db_session,
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "upload_failed"


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
def test_heartbeat_allows_failed_on_uploading(
    mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """failed should be accepted when backup is uploading (e.g. local data lost)."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="uploading")

    _run(
        _process_agent_events(
            agent,
            [_reconciled_event(backup.id, "failed", "uploading")],
            db_session,
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "failed"


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
def test_heartbeat_normal_completed_from_running(
    mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """Normal flow: completed from running should still work."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="running")

    _run(
        _process_agent_events(
            agent, [_reconciled_event(backup.id, "completed")], db_session
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "completed"
    assert backup.completed_at is not None


# ═══════════════════════════════════════════════════════════════════════════════
# S3 verification before declaring upload-phase backups failed
# ═══════════════════════════════════════════════════════════════════════════════


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
@patch("routers.health._check_s3_for_backup")
def test_upload_phase_failed_checks_s3_and_recovers(
    mock_s3_check, mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """If agent says upload-phase backup failed but data is in S3, recover it."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="uploading")

    mock_s3_check.return_value = f"s3://bucket/prefix/{backup.id}"

    _run(
        _process_agent_events(
            agent,
            [_reconciled_event(backup.id, "failed", "uploading")],
            db_session,
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "completed"
    assert backup.storage_path.startswith("s3://")


@patch("routers.health.websocket_manager", new_callable=MagicMock)
@patch("routers.health.notify_backup_success", new_callable=AsyncMock)
@patch("routers.health.notify_backup_failure", new_callable=AsyncMock)
@patch("routers.health._check_s3_for_backup")
def test_upload_phase_failed_not_in_s3_stays_failed(
    mock_s3_check, mock_fail, mock_success, mock_ws, db_session, agent_and_vm
):
    """If agent says upload-phase backup failed and not in S3, accept failure."""
    from routers.health import _process_agent_events

    mock_ws.broadcast = AsyncMock()
    agent, vm = agent_and_vm
    backup = _make_backup(db_session, vm, status="uploading")

    mock_s3_check.return_value = None

    _run(
        _process_agent_events(
            agent,
            [_reconciled_event(backup.id, "failed", "uploading")],
            db_session,
        )
    )
    db_session.commit()

    db_session.refresh(backup)
    assert backup.status == "failed"


# ═══════════════════════════════════════════════════════════════════════════════
# execute_upload exception handling
# ═══════════════════════════════════════════════════════════════════════════════


def test_execute_upload_without_provenance_preserves_local_completion(
    db_session, session_factory, agent_and_vm
):
    """A path/status cannot supply original authority or a safe replay contract."""
    from core.backup_executor import BackupExecutor

    agent, vm = agent_and_vm
    backup = _make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="file:///var/lib/vnbui/backups/test",
    )

    executor = BackupExecutor()

    # Patch SessionLocal at the import site in backup_executor
    with (
        patch("core.backup_executor.SessionLocal", side_effect=AssertionError("DB")),
        patch.object(
            executor, "_get_agent_url", side_effect=RuntimeError("unexpected")
        ),
    ):
        result = _run(executor.execute_upload(backup.id))
        assert result == {"status": "held", "reason": "delivery_provenance_required"}

    db_session.refresh(backup)
    assert backup.status == "completed"
    assert "upload_error" not in (backup.tags or {})


# ═══════════════════════════════════════════════════════════════════════════════
# Startup orphan recovery
# ═══════════════════════════════════════════════════════════════════════════════


def test_recover_orphaned_uploads_does_not_infer_upload_authority(
    db_session, session_factory, agent_and_vm
):
    """Current S3 settings cannot manufacture historical upload authority."""
    agent, vm = agent_and_vm
    orphan = _make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="file:///var/lib/vnbui/backups/orphan",
    )
    # Already on S3 — should NOT be touched
    s3_backup = _make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="s3://bucket/prefix/done",
    )

    mock_s3_config = {"bucket": "hq-vm-backups", "endpoint": "https://minio01:9000"}

    with (
        patch("app.SessionLocal", session_factory),
        patch("core.tenant_work.organization_work_ids", return_value=("default",)),
        patch(
            "core.settings_service.SettingsService.get_s3_config",
            return_value=mock_s3_config,
        ) as current_config,
    ):
        from app import _recover_orphaned_uploads

        _run(_recover_orphaned_uploads())
        current_config.assert_not_called()

    db_session.refresh(orphan)
    db_session.refresh(s3_backup)
    assert orphan.status == "completed"
    assert "upload_error" not in (orphan.tags or {})
    assert s3_backup.status == "completed"  # untouched


def test_recover_orphaned_uploads_noop_without_s3(
    db_session, session_factory, agent_and_vm
):
    """No S3 configured — nothing should change."""
    agent, vm = agent_and_vm
    backup = _make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="file:///var/lib/vnbui/backups/local-only",
    )

    with (
        patch("app.SessionLocal", session_factory),
        patch("core.tenant_work.organization_work_ids", return_value=("default",)),
        patch("core.settings_service.SettingsService.get_s3_config", return_value=None),
    ):
        from app import _recover_orphaned_uploads

        _run(_recover_orphaned_uploads())

    db_session.refresh(backup)
    assert backup.status == "completed"
