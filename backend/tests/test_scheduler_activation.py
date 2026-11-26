"""Mounted grant/cron wiring; database authority also has PostgreSQL tests."""

from datetime import datetime, timezone
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import event

from core.scheduler_grants import enroll_grant, preview_grant, require_current_grant
from core.scheduler_scope import ScopeRefused
from core.tenant_context import TenantContext
from models import Organization, OrganizationDefault, Schedule, SchedulerGrant, User
from backend.tests.conftest import make_agent, make_vm


def uid():
    return str(uuid.uuid4())


@pytest.fixture
def setup(db_session, monkeypatch):
    @event.listens_for(db_session, "before_flush")
    def sqlite_revocation_fixture(session, *_):
        # Only this SQLite fixture emulates the database-assigned revoke order.
        for row in list(session.dirty):
            if (
                isinstance(row, SchedulerGrant)
                and row.state == "revoked"
                and row.revoke_order is None
            ):
                organization = session.get(Organization, row.org_id)
                organization.scheduler_order += 1
                row.revoke_order = organization.scheduler_order

    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    monkeypatch.setattr(
        "core.storage_dispatch.read_target",
        lambda _: dict(
            endpoint="https://storage.invalid",
            bucket="backup",
            region="us-east-1",
            prefix="",
            capability_profile="db-rooted-consumer-verified/1",
        ),
    )
    org = db_session.get(OrganizationDefault, "oss").org_id
    user = User(
        id=uid(),
        org_id=org,
        username=uid(),
        password_hash="test",
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    agent = make_agent(db_session, org_id=org)
    vm = make_vm(
        db_session,
        agent,
        org_id=org,
        provider="kubevirt",
        vm_uid=uid(),
        namespace="fixture",
        inventory_present=True,
        disks=[],
    )
    schedule = Schedule(
        id=uid(),
        org_id=org,
        name="nightly",
        vm_id=vm.id,
        cron_expression="0 2 * * *",
        enabled=False,
        backup_type="full",
        retention_days=30,
        exclude_disks=[],
        tags={},
    )
    db_session.add(schedule)
    db_session.commit()
    return SimpleNamespace(org=org, user=user, schedule=schedule)


def enroll(db, setup, **extra):
    preview = preview_grant(db, setup.schedule)
    return enroll_grant(
        db,
        setup.schedule.id,
        request_id=extra.pop("request_id", uid()),
        expected_revision=preview["revision"],
        scope_sha256=preview["scope_sha256"],
        **extra
    )


def test_admin_enrollment_is_idempotent_and_not_delegated_human(db_session, setup):
    with TenantContext(setup.org, setup.user.id):
        request_id = uid()
        grant = enroll(db_session, setup, request_id=request_id)
        assert setup.schedule.enabled and setup.schedule.current_grant_id == grant.id
        assert enroll(db_session, setup, request_id=request_id).id == grant.id
        setup.user.role = "viewer"
        setup.user.is_active = False
        db_session.commit()
    with TenantContext(setup.org):
        assert require_current_grant(db_session, setup.schedule).id == grant.id


def test_automatic_policy_is_explicitly_sealed_by_admin(db_session, setup):
    policy = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
    setup.schedule.backup_type = "automatic"
    setup.schedule.backup_policy = policy
    db_session.commit()
    with TenantContext(setup.org, setup.user.id):
        preview = preview_grant(db_session, setup.schedule)
        assert preview["scope"]["options"]["backup_policy"] == policy
        grant = enroll(db_session, setup)
        assert grant.scope_sha256 == preview["scope_sha256"]
        assert grant.scope["options"]["backup_type"] == "automatic"
        assert grant.scope["options"]["backup_policy"] == policy


def test_policy_edit_revokes_live_grant_and_operator_cannot_reenroll(
    db_session, setup, monkeypatch
):
    from routers.schedules import update_schedule
    from schemas import ScheduleUpdate

    monkeypatch.setattr("routers.schedules.log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "routers.schedules.remove_schedule_from_scheduler", lambda _: None
    )
    policy = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
    setup.schedule.backup_type = "automatic"
    setup.schedule.backup_policy = policy
    db_session.commit()
    with TenantContext(setup.org, setup.user.id):
        grant = enroll(db_session, setup)
        setup.user.role = "operator"
        db_session.commit()
        update_schedule(
            setup.schedule.id,
            ScheduleUpdate(
                backup_policy={**policy, "max_incrementals": 5}, enabled=True
            ),
            db_session,
            current_user=setup.user,
        )
        assert grant.state == "revoked" and grant.revoke_order
        assert setup.schedule.current_grant_id is None
        assert setup.schedule.enabled is False
        assert setup.schedule.authority_revision == 2
        assert grant.scope["options"]["backup_policy"] == policy
        with pytest.raises(ScopeRefused, match="administrator"):
            enroll(db_session, setup)


@pytest.mark.parametrize("ambient_org", [None, "default"])
def test_oss_admin_enrolls_using_persisted_default(db_session, setup, ambient_org):
    with TenantContext(ambient_org, setup.user.id):
        grant = enroll(db_session, setup)
    assert grant.org_id == setup.org
    assert setup.schedule.current_grant_id == grant.id


def test_admin_cannot_enroll_from_foreign_organization(db_session, setup):
    with TenantContext(uid(), setup.user.id), pytest.raises(
        ScopeRefused, match="foreign_organization"
    ):
        enroll(db_session, setup)
    assert db_session.query(SchedulerGrant).count() == 0


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_non_admin_cannot_enroll(db_session, setup, role):
    setup.user.role = role
    db_session.commit()
    with TenantContext(setup.org, setup.user.id), pytest.raises(
        ScopeRefused, match="administrator"
    ):
        enroll(db_session, setup)
    assert db_session.query(SchedulerGrant).count() == 0


def test_scope_change_requires_fresh_preview(db_session, setup):
    with TenantContext(setup.org, setup.user.id):
        preview = preview_grant(db_session, setup.schedule)
        setup.schedule.retention_days = 99
        db_session.commit()
        with pytest.raises(ScopeRefused, match="scope_changed"):
            enroll_grant(
                db_session,
                setup.schedule.id,
                request_id=uid(),
                expected_revision=1,
                scope_sha256=preview["scope_sha256"],
            )


def test_replacement_revokes_original_and_keeps_audit(db_session, setup):
    with TenantContext(setup.org, setup.user.id):
        old = enroll(db_session, setup)
        with pytest.raises(ScopeRefused, match="schedule_changed"):
            enroll(db_session, setup)
        new = enroll(db_session, setup, replace_grant_id=old.id)
        assert new.id != old.id and old.state == "revoked" and old.revoke_order
        assert db_session.query(SchedulerGrant).count() == 2


@pytest.mark.parametrize(
    "edit",
    [
        {"retention_days": 8},
        {"exclude_disks": ["boot"]},
    ],
)
def test_operator_edit_pauses_and_detaches_scope(db_session, setup, monkeypatch, edit):
    from routers.schedules import update_schedule
    from schemas import ScheduleUpdate

    monkeypatch.setattr(
        "routers.schedules.remove_schedule_from_scheduler", lambda _: None
    )
    with TenantContext(setup.org, setup.user.id):
        grant = enroll(db_session, setup)
        setup.user.role = "operator"
        db_session.commit()
        result = update_schedule(
            setup.schedule.id,
            ScheduleUpdate(**edit, enabled=True),
            db_session,
            setup.user,
        )
    assert result["enabled"] is False and result["current_grant_id"] is None
    assert result["authority_revision"] == 2 and grant.state == "revoked"


def test_pause_resume_keeps_original_grant(db_session, setup, monkeypatch):
    from routers.schedules import update_schedule
    from schemas import ScheduleUpdate

    monkeypatch.setattr(
        "routers.schedules.remove_schedule_from_scheduler", lambda _: None
    )
    monkeypatch.setattr("routers.schedules.add_schedule_to_scheduler", lambda *a: None)
    with TenantContext(setup.org, setup.user.id):
        grant = enroll(db_session, setup)
        update_schedule(
            setup.schedule.id, ScheduleUpdate(enabled=False), db_session, setup.user
        )
        result = update_schedule(
            setup.schedule.id, ScheduleUpdate(enabled=True), db_session, setup.user
        )
    assert (
        result["enabled"]
        and result["current_grant_id"] == grant.id
        and grant.state == "active"
    )


def test_due_occurrence_uses_utc_cron_and_does_not_repeat_future_slot(
    db_session, session_factory, setup, monkeypatch
):
    from core.scheduler_runtime import create_due_occurrence

    setup.schedule.cron_expression = "0 2 * * 0"  # Sunday, not APScheduler Monday=0.
    db_session.commit()
    with TenantContext(setup.org, setup.user.id):
        enroll(db_session, setup)
    calls = []
    monkeypatch.setattr(
        "core.scheduler_runtime.create_occurrence",
        lambda factory, key: calls.append(key) or {"queues": []},
    )
    now = datetime(2026, 10, 4, 2, 0, 15, tzinfo=timezone.utc)
    assert create_due_occurrence(
        session_factory, setup.schedule.id, setup.org, now=now
    ) == {"queues": []}
    assert calls[0].scheduled_at == now.replace(second=0)
    assert (
        create_due_occurrence(session_factory, setup.schedule.id, setup.org, now=now)
        is None
    )
    assert len(calls) == 1


def test_grant_mutation_routes_require_admin():
    from routers import schedules as schedule_routes

    routes = [
        r
        for r in schedule_routes.router.routes
        if r.path.endswith("/grant") and r.methods & {"POST", "DELETE"}
    ]
    assert len(routes) == 2
    assert all(
        schedule_routes.get_admin_user in {d.call for d in r.dependant.dependencies}
        for r in routes
    )


@pytest.mark.parametrize("worker_payload", [{}, {"workers": None}])
@pytest.mark.parametrize("pause", [False, True])
def test_null_or_omitted_worker_edit_keeps_enrolled_grant(
    db_session, setup, monkeypatch, worker_payload, pause
):
    from routers.schedules import update_schedule
    from schemas import ScheduleUpdate

    monkeypatch.setattr(
        "routers.schedules.remove_schedule_from_scheduler", lambda _: None
    )
    with TenantContext(setup.org, setup.user.id):
        setup.schedule.workers = 3
        db_session.commit()
        grant = enroll(db_session, setup)
        revision = setup.schedule.authority_revision
        result = update_schedule(
            setup.schedule.id,
            ScheduleUpdate(
                name="renamed",
                **worker_payload,
                **({"enabled": False} if pause else {})
            ),
            db_session,
            setup.user,
        )
    assert result["workers"] == 3
    assert result["current_grant_id"] == grant.id
    assert result["authority_revision"] == revision and grant.state == "active"
    assert result["enabled"] is (not pause)
