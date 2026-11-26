"""Queue positions follow the same ordering as both active queue readers."""

import asyncio
from datetime import datetime
import uuid

from core.backup_queue_processor import BackupQueueProcessor, get_queue_position
from models import Agent, Backup, BackupQueue, OrganizationDefault, User, VM
from routers import queue


def test_tied_positions_and_started_identity_agree_with_both_readers(
    db_session, monkeypatch
):
    org = db_session.get(OrganizationDefault, "oss").org_id
    user = User(
        id=str(uuid.uuid4()),
        org_id=org,
        username="queue-reader",
        password_hash="fixture",
        role="admin",
    )
    agent = Agent(id=str(uuid.uuid4()), org_id=org, hostname="queue-reader")
    vm = VM(id=str(uuid.uuid4()), org_id=org, agent_id=agent.id, name="queue-reader")
    backup = Backup(
        id=str(uuid.uuid4()),
        org_id=org,
        vm_id=vm.id,
        authority_kind="human",
        initiating_user_id=user.id,
        status="pending",
        retention_days=30,
        tags={},
    )
    db_session.add_all([user, agent, vm, backup])
    db_session.flush()
    at = datetime(2026, 1, 1)
    tied = [str(uuid.UUID(int=value)) for value in (1, 2, 3)]
    # Deliberately insert ties in reverse order; row insertion order is irrelevant.
    for identity in reversed(tied):
        db_session.add(
            BackupQueue(
                id=identity,
                vm_id=vm.id,
                authority_kind="human",
                initiating_user_id=user.id,
                created_by=user.id,
                priority=10,
                queued_at=at,
                status="queued",
                started_backup_id=backup.id if identity == tied[1] else None,
            )
        )
    earlier = str(uuid.UUID(int=4))
    db_session.add(
        BackupQueue(
            id=earlier,
            vm_id=vm.id,
            authority_kind="human",
            initiating_user_id=user.id,
            created_by=user.id,
            priority=20,
            queued_at=at,
            status="queued",
        )
    )
    held = BackupQueue(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        authority_kind="human",
        initiating_user_id=user.id,
        created_by=user.id,
        priority=100,
        queued_at=at,
        status="held",
    )
    db_session.add(held)
    db_session.commit()
    expected = [earlier, *tied]
    assert [get_queue_position(db_session, identity) for identity in expected] == [
        1,
        2,
        3,
        4,
    ]
    assert get_queue_position(db_session, held.id) is None
    assert get_queue_position(db_session, str(uuid.uuid4())) is None
    processor = BackupQueueProcessor(None, object())
    internal = processor.get_queue_status(db_session)
    monkeypatch.setattr(queue, "get_max_concurrent_backups", lambda db: 1)
    external = asyncio.run(queue.get_backup_queue(db_session, user))
    assert internal["total_queued"] == external["total_queued"] == 4
    assert (
        [row["id"] for row in internal["queue"]]
        == [row["id"] for row in external["queue"]]
        == expected
    )
    for internal_row, external_row in zip(internal["queue"], external["queue"]):
        for field in ("position", "status", "hold_reason", "started_backup_id"):
            assert internal_row[field] == external_row[field]
    linked = next(row for row in internal["queue"] if row["id"] == tied[1])
    assert linked["status"] == "queued" and linked["started_backup_id"] == backup.id
    held_wire = queue.get_backup_queue_item(held.id, db_session, user)
    assert held_wire["status"] == "held" and held_wire["hold_reason"] == "queue_held"
    assert held_wire["position"] is None and held_wire["started_backup_id"] is None
