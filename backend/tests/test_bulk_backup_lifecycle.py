"""Bulk routes must preserve the database state claimed in their responses."""

import uuid
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks
from models import (
    Agent,
    Backup,
    VM,
    User,
    OperatorDispatch,
    OperatorRequest,
    ActivityLog,
)
from routers import bulk as bulk_router
from schemas import BulkBackupCreate, BulkBackupDelete, BulkBackupTag


def _backup(db_session, status, storage_path=None):
    agent = Agent(
        id=str(uuid.uuid4()),
        hostname="bulk-agent",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    vm = VM(id=str(uuid.uuid4()), name="bulk-vm", agent_id=agent.id, state="running")
    backup = Backup(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status=status,
        completed_at=datetime.utcnow() if status == "completed" else None,
        storage_path=storage_path,
        tags={},
    )
    db_session.add_all([agent, vm, backup])
    db_session.commit()
    return vm, backup


def _operator(db, vm):
    user = User(
        id=str(uuid.uuid4()),
        org_id=vm.org_id,
        username="bulk-operator",
        password_hash="fixture",
        role="admin",
        is_active=True,
    )
    db.add(user)
    db.commit()
    return user


def test_bulk_create_keeps_record_after_audit_commit(db_session, monkeypatch):
    vm, backup = _backup(db_session, "pending")
    user = _operator(db_session, vm)

    class Service:
        def __init__(self, db):
            assert db is db_session

        def _create_backup_flush(self, **kwargs):
            assert kwargs["vm_id"] == vm.id
            return SimpleNamespace(success=True, backup=backup)

        def get_vm_name(self, vm_id):
            assert vm_id == vm.id
            return vm.name

    monkeypatch.setattr(bulk_router, "BackupService", Service)
    commits = []
    original_commit = db_session.commit

    def commit():
        commits.append(True)
        return original_commit()

    monkeypatch.setattr(db_session, "commit", commit)
    background = BackgroundTasks()
    result = bulk_router.bulk_create_backups(
        BulkBackupCreate(vm_ids=[vm.id]),
        background,
        db=db_session,
        current_user=user,
        request_id=str(uuid.uuid4()),
    )

    result = json.loads(result.body)
    assert result["summary"]["created"] == 1
    assert background.tasks == []
    work = db_session.query(OperatorDispatch).one()
    assert work.resource_id == backup.id and work.state == "pending"
    assert db_session.query(ActivityLog).filter_by(action="backup_created").count() == 1
    assert len(commits) == 1
    assert db_session.get(Backup, backup.id) is not None


def test_bulk_create_audit_failure_rolls_back_row_and_task(db_session, monkeypatch):
    vm, _ = _backup(db_session, "completed")
    user = _operator(db_session, vm)

    class Service:
        def __init__(self, db):
            self.db = db

        def _create_backup_flush(self, **kwargs):
            row = Backup(
                id=str(uuid.uuid4()),
                vm_id=kwargs["vm_id"],
                status="pending",
                tags={},
            )
            self.db.add(row)
            self.db.flush()
            return SimpleNamespace(success=True, backup=row)

        def get_vm_name(self, vm_id):
            return vm.name

    monkeypatch.setattr(bulk_router, "BackupService", Service)

    def reject_audit(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(bulk_router, "log_activity", reject_audit)
    background = BackgroundTasks()
    result = bulk_router.bulk_create_backups(
        BulkBackupCreate(vm_ids=[vm.id]),
        background,
        db=db_session,
        current_user=user,
        request_id=str(uuid.uuid4()),
    )

    result = json.loads(result.body)
    assert result["summary"] == {"total": 1, "created": 0, "skipped": 0, "failed": 1}
    assert background.tasks == []
    assert db_session.query(Backup).filter(Backup.status == "pending").count() == 0
    assert db_session.query(OperatorDispatch).count() == 0
    receipt = db_session.query(OperatorRequest).one()
    assert receipt.response_body["summary"]["failed"] == 1


def test_bulk_delete_refuses_unowned_record(db_session, monkeypatch):
    _, backup = _backup(
        db_session, "completed", "file:///var/lib/vnbui/backups/bulk-seed"
    )
    backup_id = backup.id
    monkeypatch.setattr(bulk_router, "log_activity", lambda db, *a, **kw: db.commit())
    result = bulk_router.bulk_delete_backups(
        BulkBackupDelete(backup_ids=[backup_id]), db=db_session, current_user=object()
    )
    assert result["summary"]["deleted"] == 0 and result["summary"]["failed"] == 1
    assert "no accepted ownership receipts" in result["details"]["failed"][0]["reason"]
    assert db_session.get(Backup, backup_id).status == "completed"


def test_bulk_delete_preserves_transaction_tombstone(db_session, monkeypatch):
    _, backup = _backup(db_session, "completed")
    backup_id = backup.id

    async def delete_transaction(db, row):
        assert db is db_session
        assert row.id == backup_id
        row.status = "deleted"
        db.commit()
        return 123

    monkeypatch.setattr(
        bulk_router.backup_deletion_service, "delete_payload", delete_transaction
    )
    monkeypatch.setattr(bulk_router, "log_activity", lambda db, *a, **kw: db.commit())
    result = bulk_router.bulk_delete_backups(
        BulkBackupDelete(backup_ids=[backup_id]),
        db=db_session,
        current_user=object(),
    )

    assert result["summary"]["deleted"] == 1
    assert db_session.get(Backup, backup_id).status == "deleted"


def test_bulk_delete_refuses_success_without_tombstone(db_session):
    _, backup = _backup(db_session, "completed")
    with patch.object(
        bulk_router.backup_deletion_service,
        "delete_payload",
        AsyncMock(return_value=123),
    ):
        result = bulk_router.bulk_delete_backups(
            BulkBackupDelete(backup_ids=[backup.id]),
            db=db_session,
            current_user=object(),
        )
    assert result["summary"]["deleted"] == 0 and result["summary"]["failed"] == 1
    assert "tombstone" in result["details"]["failed"][0]["reason"]
    assert db_session.get(Backup, backup.id).status == "completed"


@pytest.mark.parametrize("custody", ["reserved", "legacy_held"])
def test_bulk_delete_keeps_held_producer_payload(db_session, custody):
    _, backup = _backup(
        db_session, "completed", "file:///var/lib/vnbui/backups/bulk-seed"
    )
    backup_id = backup.id
    backup.capacity_state = custody
    backup.capacity_id = str(uuid.uuid4())
    backup.capacity_reserved_at = datetime.utcnow()
    backup.capacity_policy_revision = 1 if custody == "reserved" else None
    db_session.commit()
    with patch.object(
        bulk_router.backup_deletion_service, "delete_payload", AsyncMock()
    ) as delete_payload:
        result = bulk_router.bulk_delete_backups(
            BulkBackupDelete(backup_ids=[backup_id]),
            db=db_session,
            current_user=object(),
        )

    delete_payload.assert_not_awaited()
    assert result["summary"]["skipped"] == 1
    assert db_session.get(Backup, backup_id) is not None


def test_bulk_delete_failure_retains_attribution(db_session):
    _, backup = _backup(
        db_session, "completed", "file:///var/lib/vnbui/backups/bulk-seed"
    )
    backup_id = backup.id
    with patch("core.storage_deletion.is_transaction_backup", return_value=True), patch(
        "core.storage_deletion.delete_transaction_payload",
        side_effect=RuntimeError("storage offline"),
    ):
        result = bulk_router.bulk_delete_backups(
            BulkBackupDelete(backup_ids=[backup_id]),
            db=db_session,
            current_user=object(),
        )

    db_session.expire_all()
    retained = db_session.get(Backup, backup_id)
    assert result["summary"]["failed"] == 1
    assert result["summary"]["deleted"] == 0
    assert retained is not None
    assert retained.tags["deletion_error"] == "storage offline"


def test_bulk_delete_rolls_back_failed_item_before_next(db_session, monkeypatch):
    vm, first = _backup(db_session, "completed")
    second = Backup(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="completed",
        completed_at=datetime.utcnow(),
        storage_path="file:///var/lib/vnbui/backups/second",
        tags={},
    )
    db_session.add(second)
    db_session.commit()
    first_id, second_id = first.id, second.id

    async def delete_payload(_db, _backup):
        _backup.status = "deleted"
        _db.commit()
        return 0

    def audit(db, _user, **kwargs):
        if kwargs["resource_id"] == first_id:
            raise RuntimeError("audit unavailable")
        db.commit()

    monkeypatch.setattr(
        bulk_router.backup_deletion_service, "delete_payload", delete_payload
    )
    monkeypatch.setattr(bulk_router, "log_activity", audit)
    result = bulk_router.bulk_delete_backups(
        BulkBackupDelete(backup_ids=[first_id, second_id]),
        db=db_session,
        current_user=object(),
    )

    db_session.expire_all()
    assert result["summary"] == {"total": 2, "deleted": 1, "skipped": 0, "failed": 1}
    # Provider completion is durable even if the later audit fails; neither
    # item may lose its catalog or resurrect an already deleted payload.
    assert db_session.get(Backup, first_id).status == "deleted"
    assert db_session.get(Backup, second_id).status == "deleted"


def test_bulk_tag_audit_failure_rolls_back_tags_and_continues(db_session, monkeypatch):
    vm, first = _backup(db_session, "completed")
    second = Backup(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="completed",
        completed_at=datetime.utcnow(),
        tags={},
    )
    db_session.add(second)
    db_session.commit()
    first_id, second_id = first.id, second.id

    def audit(db, _user, **kwargs):
        if kwargs["resource_id"] == first_id:
            raise RuntimeError("audit unavailable")
        db.commit()

    monkeypatch.setattr(bulk_router, "log_activity", audit)
    result = bulk_router.bulk_tag_backups(
        BulkBackupTag(backup_ids=[first_id, second_id], tags={"reviewed": "yes"}),
        db=db_session,
        current_user=object(),
    )

    db_session.expire_all()
    assert result["summary"] == {"total": 2, "updated": 1, "failed": 1}
    assert db_session.get(Backup, first_id).tags == {}
    assert db_session.get(Backup, second_id).tags == {"reviewed": "yes"}
