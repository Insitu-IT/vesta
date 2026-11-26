"""Deletion requires accepted ownership; every success retains its catalog row.

Exact VersionId, provider-failure and retained-dependency coverage lives in
test_storage_deletion.py and the restricted PostgreSQL deletion suite.
"""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from core.backup_deletion import BackupDeletionError, BackupDependencyError
from core.retention import RetentionPolicyEnforcer
from fastapi import HTTPException
from models import VM, Agent, Backup
from routers import backups as backups_router


def _backup(db, path=None, *, released=False, status="completed"):
    agent = Agent(id=str(uuid.uuid4()), hostname="deletion-unit-agent", status="online")
    vm = VM(
        id=str(uuid.uuid4()),
        name="deletion-unit-vm",
        agent_id=agent.id,
        state="running",
    )
    row = Backup(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status=status,
        completed_at=datetime.utcnow(),
        tags={"preserved": "original"},
    )
    row.storage_path = path.replace("BACKUP_ID", row.id) if path else path
    if released:
        row.capacity_state = "released"
        row.capacity_id = str(uuid.uuid4())
        row.capacity_reserved_at = datetime.utcnow()
        row.capacity_policy_revision = 1
        row.capacity_release = {"schema": 1, "reason": "unit-fixture-reconciled"}
    db.add_all([agent, vm, row])
    db.commit()
    return row


@pytest.mark.parametrize(
    "path",
    [
        None,
        "file:///var/lib/vnbui/backups/BACKUP_ID",
        "/var/lib/vnbui/backups/BACKUP_ID",
        "s3://vnbui/backups/BACKUP_ID",
        "s3://foreign/neighbor",
    ],
)
@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("released", [False, True])
def test_unowned_backup_refuses_before_provider_or_catalog_removal(
    db_session, path, force, released
):
    row = _backup(db_session, path, released=released)
    identity = row.id
    with patch("boto3.client") as provider, patch.object(
        backups_router, "log_activity"
    ) as audit:
        with pytest.raises(HTTPException) as error:
            backups_router.delete_backup(
                identity, force=force, db=db_session, current_user=object()
            )
    assert error.value.status_code == 409
    assert "no accepted ownership receipts" in error.value.detail
    provider.assert_not_called()
    audit.assert_not_called()
    db_session.expire_all()
    retained = db_session.get(Backup, identity)
    assert retained.status == "completed" and retained.tags == {"preserved": "original"}
    assert retained.storage_path == (
        path.replace("BACKUP_ID", identity) if path else path
    )


def test_failed_released_attempt_does_not_authorize_path_deletion(db_session):
    row = _backup(
        db_session,
        "file:///var/lib/vnbui/backups/BACKUP_ID",
        released=True,
        status="failed",
    )
    with pytest.raises(HTTPException) as error:
        backups_router.delete_backup(
            row.id, force=True, db=db_session, current_user=object()
        )
    assert error.value.status_code == 409
    assert db_session.get(Backup, row.id).status == "failed"


def test_modern_success_retains_deleted_tombstone(db_session):
    row = _backup(db_session, released=True)

    def settle(db, identity):
        assert db is db_session and identity == row.id
        row.status = "deleted"
        db.commit()
        return 123

    with patch("core.storage_deletion.is_transaction_backup", return_value=True), patch(
        "core.storage_deletion.delete_transaction_payload", side_effect=settle
    ) as delete, patch.object(backups_router, "log_activity"):
        result = backups_router.delete_backup(
            row.id, db=db_session, current_user=object()
        )
    delete.assert_called_once_with(db_session, row.id)
    assert result["deleted_bytes"] == 123
    assert db_session.get(Backup, row.id).status == "deleted"
    assert row.tags == {"preserved": "original"}


def test_modern_provider_failure_retains_attribution(db_session):
    row = _backup(db_session, released=True)
    with patch("core.storage_deletion.is_transaction_backup", return_value=True), patch(
        "core.storage_deletion.delete_transaction_payload",
        side_effect=RuntimeError("storage offline"),
    ), pytest.raises(HTTPException) as error:
        backups_router.delete_backup(row.id, db=db_session, current_user=object())
    assert error.value.status_code == 502
    db_session.expire_all()
    retained = db_session.get(Backup, row.id)
    assert retained.status == "completed"
    assert retained.tags["preserved"] == "original"
    assert retained.tags["deletion_error"] == "storage offline"


def test_modern_dependency_refusal_retains_original_catalog(db_session):
    row = _backup(db_session, released=True)
    with patch("core.storage_deletion.is_transaction_backup", return_value=True), patch(
        "core.storage_deletion.delete_transaction_payload",
        side_effect=BackupDependencyError("retained child"),
    ), pytest.raises(HTTPException) as error:
        backups_router.delete_backup(row.id, db=db_session, current_user=object())
    assert error.value.status_code == 409
    assert db_session.get(Backup, row.id).tags == {"preserved": "original"}


def test_single_delete_refuses_success_without_tombstone(db_session):
    row = _backup(db_session)
    with patch.object(
        backups_router.backup_deletion_service,
        "delete_payload",
        AsyncMock(return_value=123),
    ), patch.object(backups_router, "log_activity") as audit, pytest.raises(
        HTTPException
    ) as error:
        backups_router.delete_backup(row.id, db=db_session, current_user=object())
    assert error.value.status_code == 502 and "tombstone" in error.value.detail
    audit.assert_not_called()
    assert db_session.get(Backup, row.id).status == "completed"


@pytest.mark.asyncio
async def test_retention_refuses_success_without_tombstone(db_session):
    row = _backup(db_session)
    with patch(
        "core.retention.backup_deletion_service.delete_payload",
        AsyncMock(return_value=123),
    ), pytest.raises(BackupDeletionError, match="tombstone"):
        await RetentionPolicyEnforcer()._delete_backup(db_session, row)
    assert db_session.get(Backup, row.id).status == "completed"
