"""Schedule configuration contract exercised by the automation UI."""

from unittest.mock import patch

import pytest

from core.tenant_context import TenantContext
from models import Agent, OrganizationDefault, Schedule, User, VM, VMGroup
from routers import schedules as schedules_router
from schemas import ScheduleCreate, ScheduleUpdate


def _make_vm(db_session, name="ctrl01-vm"):
    agent = Agent(hostname="ctrl01", status="online")
    db_session.add(agent)
    db_session.flush()
    vm = VM(name=name, agent_id=agent.id, state="running")
    db_session.add(vm)
    db_session.flush()
    return vm


def test_create_schedule_persists_target_and_backup_type(
    db_session,
):
    vm = _make_vm(db_session)
    group = VMGroup(name="ctrl01-estate", group_type="static")
    db_session.add(group)
    group.vms.append(vm)
    db_session.commit()

    request = ScheduleCreate(
        name="ctrl01 weekly",
        vm_group_id=group.id,
        cron_expression="0 2 * * 0",
        backup_type="incremental",
        exclude_disks=["boot"],
        retention_days=30,
    )

    with patch.object(
        schedules_router, "add_schedule_to_scheduler"
    ) as add_job, patch.object(schedules_router, "log_activity"):
        response = schedules_router.create_schedule(
            request, db_session, current_user=object()
        )

    stored = db_session.query(Schedule).filter(Schedule.id == response["id"]).one()
    assert stored.vm_group_id == group.id
    assert stored.vm_id is None
    assert stored.backup_type == "incremental"
    assert stored.exclude_disks == ["boot"]
    assert stored.workers is None
    assert response["backup_type"] == "incremental"
    assert response["exclude_disks"] == ["boot"]
    assert response["workers"] is None
    assert stored.enabled is False
    assert stored.authority_revision == 1
    add_job.assert_not_called()


def test_update_schedule_changes_backup_type(db_session):
    vm = _make_vm(db_session)
    schedule = Schedule(
        name="ctrl01 weekly",
        vm_id=vm.id,
        cron_expression="0 2 * * 0",
        backup_type="full",
        enabled=False,
    )
    db_session.add(schedule)
    db_session.commit()

    org_id = db_session.get(OrganizationDefault, "oss").org_id
    operator = User(
        org_id=org_id,
        username="schedule-operator",
        password_hash="test",
        role="operator",
        is_active=True,
    )
    db_session.add(operator)
    db_session.commit()
    with TenantContext(org_id, operator.id), patch.object(
        schedules_router, "log_activity"
    ):
        response = schedules_router.update_schedule(
            schedule.id,
            ScheduleUpdate(backup_type="incremental"),
            db_session,
            current_user=operator,
        )

    assert response["backup_type"] == "incremental"
    assert db_session.get(Schedule, schedule.id).backup_type == "incremental"
    assert db_session.get(Schedule, schedule.id).authority_revision == 2


def test_schedule_rejects_unknown_backup_type():
    with pytest.raises(ValueError):
        ScheduleCreate(
            name="bad",
            vm_id="vm-id",
            cron_expression="0 2 * * *",
            backup_type="copy",
        )


def test_create_automatic_schedule_persists_policy_but_never_enrolls(db_session):
    vm = _make_vm(db_session)
    db_session.commit()
    policy = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
    request = ScheduleCreate(
        name="automatic daily",
        vm_id=vm.id,
        cron_expression="0 2 * * *",
        backup_type="automatic",
        backup_policy=policy,
    )
    with patch.object(schedules_router, "log_activity"), patch.object(
        schedules_router, "add_schedule_to_scheduler"
    ) as add_job:
        result = schedules_router.create_schedule(request, db_session, object())
    stored = db_session.get(Schedule, result["id"])
    assert stored.backup_type == "automatic" and stored.backup_policy == policy
    assert result["backup_policy"] == policy and result["enabled"] is False
    assert stored.current_grant_id is None and stored.authority_revision == 1
    add_job.assert_not_called()


def test_policy_edit_detaches_revision_and_requires_reenrollment(db_session):
    vm = _make_vm(db_session)
    policy = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
    schedule = Schedule(
        name="automatic",
        vm_id=vm.id,
        cron_expression="0 2 * * *",
        backup_type="automatic",
        backup_policy=policy,
        enabled=False,
    )
    db_session.add(schedule)
    db_session.commit()
    org = db_session.get(OrganizationDefault, "oss").org_id
    operator = User(
        org_id=org,
        username="policy-operator",
        password_hash="test",
        role="operator",
        is_active=True,
    )
    db_session.add(operator)
    db_session.commit()
    changed = {**policy, "max_incrementals": 5}
    with TenantContext(org, operator.id), patch.object(
        schedules_router, "log_activity"
    ):
        result = schedules_router.update_schedule(
            schedule.id,
            ScheduleUpdate(backup_policy=changed, enabled=True),
            db_session,
            operator,
        )
    assert result["backup_policy"] == changed
    assert result["enabled"] is False and result["authority_revision"] == 2
    assert result["current_grant_id"] is None


def test_fixed_mode_transition_requires_explicit_policy_clear(db_session):
    from fastapi import HTTPException

    vm = _make_vm(db_session)
    policy = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
    schedule = Schedule(
        name="automatic",
        vm_id=vm.id,
        cron_expression="0 2 * * *",
        backup_type="automatic",
        backup_policy=policy,
        enabled=False,
    )
    db_session.add(schedule)
    db_session.commit()
    org = db_session.get(OrganizationDefault, "oss").org_id
    operator = User(
        org_id=org,
        username="policy-clear",
        password_hash="test",
        role="operator",
        is_active=True,
    )
    db_session.add(operator)
    db_session.commit()
    with TenantContext(org, operator.id), patch.object(
        schedules_router, "log_activity"
    ):
        with pytest.raises(HTTPException) as error:
            schedules_router.update_schedule(
                schedule.id,
                ScheduleUpdate(backup_type="full"),
                db_session,
                operator,
            )
        assert error.value.status_code == 422
        assert schedule.authority_revision == 1 and schedule.backup_policy == policy
        result = schedules_router.update_schedule(
            schedule.id,
            ScheduleUpdate(backup_type="full", backup_policy=None),
            db_session,
            operator,
        )
    assert result["backup_type"] == "full" and result["backup_policy"] is None
    assert result["authority_revision"] == 2 and result["enabled"] is False


@pytest.mark.parametrize("disks", [["boot", "boot"], ["bad disk"], ["/"]])
def test_schedule_rejects_invalid_exclusions(disks):
    with pytest.raises(ValueError):
        ScheduleCreate(
            name="bad",
            vm_id="vm-id",
            cron_expression="0 2 * * *",
            exclude_disks=disks,
        )


@pytest.mark.parametrize("worker_payload", [{}, {"workers": None}])
def test_unrelated_edit_preserves_legacy_workers_and_grant(db_session, worker_payload):
    vm = _make_vm(db_session)
    schedule = Schedule(
        name="legacy",
        vm_id=vm.id,
        cron_expression="0 2 * * *",
        workers=4,
        enabled=False,
    )
    db_session.add(schedule)
    org_id = db_session.get(OrganizationDefault, "oss").org_id
    operator = User(
        org_id=org_id,
        username="legacy-worker-operator",
        password_hash="test",
        role="operator",
        is_active=True,
    )
    db_session.add(operator)
    db_session.commit()
    revision, grant = schedule.authority_revision, schedule.current_grant_id
    with TenantContext(org_id, operator.id), patch.object(
        schedules_router, "log_activity"
    ), patch.object(schedules_router, "revoke_grant_flush") as revoke:
        result = schedules_router.update_schedule(
            schedule.id,
            ScheduleUpdate(name="renamed", **worker_payload),
            db_session,
            operator,
        )
    assert result["workers"] == 4
    assert schedule.workers == 4 and schedule.name == "renamed"
    assert (
        schedule.authority_revision == revision and schedule.current_grant_id == grant
    )
    revoke.assert_not_called()
