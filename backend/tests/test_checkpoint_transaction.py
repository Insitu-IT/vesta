"""A durable payload is insufficient evidence of a committed CBT checkpoint."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.checkpoint_state import apply_checkpoint_state
from .test_upload_race import _make_agent, _make_backup, _make_vm, _reconciled_event


@pytest.mark.parametrize("status", ["failed", "cleanup_required", "completed"])
def test_checkpoint_state_retains_attribution_without_promoting(status):
    backup = SimpleNamespace(
        tags=None, storage_path="file:///backups/id", completed_at=None
    )
    result = apply_checkpoint_state(
        backup,
        {"checkpoint_committed": False, "s3_location": "s3://bucket/backups/id"},
        status,
    )
    assert result == ("cleanup_required" if status == "completed" else status)
    assert backup.storage_path == "s3://bucket/backups/id"
    assert backup.tags["checkpoint_required"]
    assert not backup.tags["checkpoint_committed"]
    assert apply_checkpoint_state(backup, {}, "completed") == "cleanup_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["failed", "cleanup_required", "completed"])
async def test_heartbeat_never_recovers_uncommitted_payload_from_s3(db_session, status):
    from routers.health import _process_agent_events

    agent = _make_agent(db_session)
    vm = _make_vm(db_session, agent)
    backup = _make_backup(
        db_session, vm, status="uploading", storage_path="file:///backups/id"
    )
    event = _reconciled_event(backup.id, status, "uploading")
    event.update(
        checkpoint_committed=False, s3_location=f"s3://bucket/backups/{backup.id}"
    )
    with (
        patch(
            "routers.health._check_s3_for_backup", return_value=event["s3_location"]
        ) as probe,
        patch("routers.health.notify_backup_failure", new_callable=AsyncMock),
        patch(
            "routers.health.notify_backup_success", new_callable=AsyncMock
        ) as success,
        patch("routers.health.websocket_manager", broadcast=AsyncMock()),
    ):
        await _process_agent_events(agent, [event], db_session)
        db_session.commit()
        db_session.refresh(backup)
        assert backup.status == (
            "cleanup_required" if status == "completed" else status
        )
        assert backup.storage_path == event["s3_location"]
        assert backup.completed_at is None
        probe.assert_not_called()
        success.assert_not_called()


@pytest.mark.asyncio
async def test_monitor_terminal_label_cannot_supply_checkpoint_authority(db_session):
    from core.backup_executor import BackupExecutor
    from core.backup_monitor import MonitorBinding

    agent = _make_agent(db_session)
    vm = _make_vm(db_session, agent)
    backup = _make_backup(
        db_session, vm, status="running", storage_path="file:///backups/id"
    )
    executor = BackupExecutor()
    data = {
        "backup_id": backup.id,
        "status": "cleanup_required",
        "checkpoint_committed": False,
        "s3_location": f"s3://bucket/backups/{backup.id}",
        "error_message": "delete denied",
    }
    response = MagicMock()
    response.json.return_value = data
    with (
        patch("core.backup_executor.SessionLocal", return_value=db_session),
        patch("core.backup_monitor.admit", return_value=backup),
        patch.object(db_session, "close"),
        patch.object(
            executor.http_client, "get", new_callable=AsyncMock, return_value=response
        ),
        patch("core.backup_executor.asyncio.sleep", new_callable=AsyncMock),
        patch("core.backup_executor.emit_backup_event", new_callable=AsyncMock),
        patch("core.notifications.notify_backup_failure", new_callable=AsyncMock),
        patch.object(
            executor, "_upload_chain_manifest", new_callable=AsyncMock
        ) as manifest,
    ):
        await executor.monitor_backup(
            MonitorBinding(
                backup.id, "org", "actor", agent.id, "source", "http://agent"
            )
        )
        assert backup.status == "cleanup_required"
        assert backup.tags["cleanup_required"] is True
        assert backup.storage_path == "file:///backups/id"
        assert not backup.tags.get("checkpoint_committed")
        assert backup.completed_at is None
        manifest.assert_not_called()
    await executor.http_client.aclose()


@pytest.mark.asyncio
async def test_chain_manifest_excludes_uncommitted_and_failed_members(db_session):
    import json
    from core.backup_executor import BackupExecutor

    agent = _make_agent(db_session)
    vm = _make_vm(db_session, agent)
    good = _make_backup(db_session, vm, status="completed")
    good.chain_id = "chain"
    good.tags = {"checkpoint_required": True, "checkpoint_committed": True}
    members = [good]
    for status in ("failed", "cleanup_required", "completed"):
        member = _make_backup(db_session, vm, status=status)
        member.tags = {"checkpoint_required": True, "checkpoint_committed": False}
        members.append(member)
    executor = BackupExecutor()
    with (
        patch(
            "core.settings_service.SettingsService.get_s3_config",
            return_value={"bucket": "bucket"},
        ),
        patch("core.backup_service.BackupService.get_chain", return_value=members),
        patch("boto3.client") as client,
    ):
        await executor._upload_chain_manifest(good, db_session)
        manifest = json.loads(client.return_value.put_object.call_args.kwargs["Body"])
        assert [entry["backup_id"] for entry in manifest["backups"]] == [good.id]
    await executor.http_client.aclose()
