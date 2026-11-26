"""A failed retention item cannot poison or leak changes into the next item.

Deletion is doubled here to isolate batch transaction handling. Real accepted
receipt/provider/lineage behavior is covered by the storage deletion suites.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock
import uuid

import pytest

from core import retention
from models import Backup
from .conftest import make_agent, make_backup, make_vm


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["aborted-flush", "uncommitted-change"])
@pytest.mark.parametrize("by_vm", [False, True])
async def test_retention_rolls_back_failed_item_before_next(
    db_session, monkeypatch, failure, by_vm
):
    vm = make_vm(db_session, make_agent(db_session))
    options = {
        "status": "completed",
        "completed_at": datetime.utcnow() - timedelta(days=3),
        "retention_days": 1,
        "tags": {"preserved": "original"},
    }
    first = make_backup(db_session, vm, chain_position=1, **options)
    second = make_backup(db_session, vm, chain_position=0, **options)
    first_id, second_id = first.id, second.id
    calls = []

    async def delete_payload(db, backup):
        calls.append(backup.id)
        if backup.id == first_id:
            if failure == "aborted-flush":
                duplicate = str(uuid.uuid4())
                db.add_all(
                    [
                        Backup(
                            id=duplicate,
                            vm_id=backup.vm_id,
                            org_id=backup.org_id,
                            status="failed",
                        )
                        for _ in range(2)
                    ]
                )
                # A real constraint error leaves the Session unusable until rollback.
                db.flush()
                pytest.fail("Duplicate primary keys did not fail")
            backup.tags = {"uncommitted": "must not reach another item's commit"}
            raise RuntimeError("interrupted deletion")
        assert backup.id == second_id
        backup.status = "deleted"
        db.commit()
        return 7

    monkeypatch.setattr(retention, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(retention, "get_setting", lambda *args: True)
    monkeypatch.setattr(
        retention.backup_deletion_service, "delete_payload", delete_payload
    )
    enforcer = retention.RetentionPolicyEnforcer()
    monkeypatch.setattr(enforcer, "_cleanup_orphaned_manifests", AsyncMock())

    result = (
        await enforcer.enforce_for_vm(vm.id) if by_vm else await enforcer.enforce_all()
    )

    assert calls == [first_id, second_id]
    assert result["deleted_count"] == 1 and result["deleted_bytes"] == 7
    assert db_session.get(Backup, first_id).status == "completed"
    assert db_session.get(Backup, first_id).tags == {"preserved": "original"}
    assert db_session.get(Backup, second_id).status == "deleted"
