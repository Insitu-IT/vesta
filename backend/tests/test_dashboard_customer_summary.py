"""Aggregate dashboard truth across tenant, inventory, queue and pagination boundaries."""

import asyncio
import pytest
from datetime import datetime, timedelta
from types import SimpleNamespace

from models import BackupQueue, Organization, Schedule
from routers.dashboard import get_dashboard_summary
from .conftest import make_agent, make_vm, make_backup


def summary(db, org_id):
    return asyncio.run(
        get_dashboard_summary(current_user=SimpleNamespace(org_id=org_id), db=db)
    )


def test_current_inventory_and_tenant_aggregates_exceed_list_page(db_session):
    db = db_session
    agent = make_agent(db, display_name="Friendly agent")
    other = Organization(name="Other tenant")
    db.add(other)
    db.commit()
    other_agent = make_agent(db, org_id=other.id)
    make_vm(db, other_agent, org_id=other.id)
    make_vm(db, agent, inventory_present=False)
    for _ in range(105):
        make_vm(db, agent, state="running")
    make_vm(db, agent, state="paused")
    data = summary(db, agent.org_id)
    assert data["vms"]["total"] == 106
    assert data["vms"]["by_status"] == {"running": 105, "paused": 1}
    assert data["vms"]["stopped"] == 0
    assert data["vms"]["by_agent"] == [
        {"agent_id": agent.id, "name": "Friendly agent", "count": 106}
    ]
    assert data["agents"]["total"] == 1


def test_empty_history_is_not_one_hundred_percent_success(db_session):
    agent = make_agent(db_session)
    data = summary(db_session, agent.org_id)
    assert data["backups"]["success_rate_24h"] is None
    assert data["backups"]["last_24h"] == 0
    assert data["recent_backups"] == []
    assert data["vms"]["by_status"] == {}


def test_period_statuses_are_exclusive_and_schedule_count_means_due_runs(db_session):
    db = db_session
    agent = make_agent(db)
    vm = make_vm(db, agent)
    now = datetime.utcnow()
    for status in [
        "completed",
        "running",
        "uploading",
        "pending",
        "failed",
        "upload_failed",
    ]:
        make_backup(db, vm, status=status)
    old = make_backup(db, vm, status="completed", created_at=now - timedelta(days=3))
    make_backup(db, vm, status="held", created_at=now - timedelta(days=2))
    make_backup(db, vm, status="completed", created_at=now + timedelta(hours=1))
    db.add(BackupQueue(vm_id=vm.id, status="queued", queued_at=now))
    db.add(
        BackupQueue(
            vm_id=vm.id,
            status="held_unclaimed",
            hold_reason="source_unavailable",
            queued_at=now,
        )
    )
    db.add(
        BackupQueue(
            vm_id=vm.id, status="claimed", started_backup_id=old.id, queued_at=now
        )
    )
    # A second tenant's queue never contributes to this tenant's aggregate.
    other = Organization(name="Other")
    db.add(other)
    db.flush()
    other_vm = make_vm(db, make_agent(db, org_id=other.id), org_id=other.id)
    db.add(BackupQueue(vm_id=other_vm.id, status="queued", queued_at=now))
    for name, enabled, next_run in [
        ("due", True, now + timedelta(hours=2)),
        ("late", True, now + timedelta(days=2)),
        ("disabled", False, now + timedelta(hours=1)),
    ]:
        db.add(
            Schedule(
                name=name,
                org_id=agent.org_id,
                cron_expression="0 0 * * *",
                enabled=enabled,
                next_run_at=next_run,
            )
        )
    db.commit()
    data = summary(db, agent.org_id)
    assert data["backups"]["by_status"] == {
        "completed": 1,
        "running": 2,
        "queued": 2,
        "failed": 2,
        "held": 1,
        "other": 0,
    }
    assert data["backups"]["last_24h"] == 8
    assert data["backups"]["total"] == 9
    assert data["schedules"] == {"active": 2, "upcoming": 1}
    assert data["attention"]["failed_backups"] == 2
    assert data["attention"]["held_backups"] == 1


def test_database_error_is_not_converted_to_empty_dashboard():
    class UnavailableDB:
        def query(self, *_args):
            raise RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        summary(UnavailableDB(), "tenant")


def test_literal_unknown_and_null_vm_state_counts_merge(db_session):
    from models import VM

    db = db_session
    agent = make_agent(db)
    vm = make_vm(db, agent)
    make_vm(db, agent, state="unknown")
    db.query(VM).filter(VM.id == vm.id).update({VM.state: None})
    db.commit()
    assert summary(db, agent.org_id)["vms"]["by_status"] == {"unknown": 2}
