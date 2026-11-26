"""Retained transaction reports bind exact custody and cannot publish/release."""

from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from core.storage_hold_observation import observe_storage_hold
from models import S3Publication
from .conftest import make_agent, make_backup, make_vm


def test_public_diagnostic_preserves_zero_counts_and_rejects_extra_provider_text():
    import jsonschema
    from core.storage_hold_observation import public_safety_diagnostic
    from operator_contracts import safety_diagnostic_schema

    diagnostic = dict(
        stage="export_admission",
        reason="native_volume_count_mismatch",
        disposition="refused",
        expected_native_volumes=2,
        observed_native_volumes=0,
        observed_export_links=0,
        read_observation_reason="export_native_observation_unavailable",
        read_observation_uncertain_since="2026-11-10T16:00:00Z",
        read_observation_deadline="2026-11-10T16:03:00Z",
    )
    row = SimpleNamespace(
        status="cleanup_required",
        tags={"storage_hold": {"schema": 2, "diagnostic": diagnostic}},
    )
    result = public_safety_diagnostic(row)
    assert result == diagnostic and result is not diagnostic
    jsonschema.validate(result, safety_diagnostic_schema())
    diagnostic["provider_body"] = "https://user:password@example/token"
    assert public_safety_diagnostic(row) is None
    del diagnostic["provider_body"]
    row.status = "completed"
    assert public_safety_diagnostic(row) is None


@pytest.fixture
def held(db_session):
    agent = make_agent(db_session)
    vm = make_vm(db_session, agent)
    row = make_backup(
        db_session,
        vm,
        status="running",
        capacity_state="reserved",
        capacity_id=str(uuid4()),
        capacity_reserved_at=datetime.utcnow(),
        capacity_policy_revision=1,
        tags={"preserve": "existing"},
    )
    reservation = str(uuid4())
    request = {
        "backup_id": row.id,
        "org_id": row.org_id,
        "agent_id": agent.id,
        "reservation_id": reservation,
        "plan_sha256": "a" * 64,
        "plan": {"provider": "kubevirt"},
    }
    claim = S3Publication(
        id=reservation,
        backup_id=row.id,
        org_id=row.org_id,
        kind="payload",
        state="reserved",
        endpoint="https://s3.example",
        bucket="fixture",
        object_key=reservation,
        expected_plan={"schema": 3, "transaction": request},
    )
    db_session.add(claim)
    db_session.commit()
    event = dict(
        type="storage_transaction_held",
        schema=1,
        backup_id=row.id,
        reservation_id=reservation,
        plan_sha256="a" * 64,
        reason="storage_transaction_retained",
    )
    return agent, row, claim, event


def test_exact_hold_repeats_without_custody_mutation(db_session, held):
    agent, row, claim, event = held
    storage = row.completed_at, row.storage_path, row.size_bytes
    custody = (
        row.capacity_id,
        row.capacity_state,
        row.capacity_release,
        deepcopy(claim.expected_plan),
        claim.state,
        claim.prepared_receipt,
    )
    assert observe_storage_hold(db_session, agent, event)
    db_session.commit()
    assert row.status == "cleanup_required" and row.tags["cleanup_required"]
    assert row.tags["preserve"] == "existing"
    assert not observe_storage_hold(db_session, agent, event)
    assert not db_session.dirty
    assert (
        row.capacity_id,
        row.capacity_state,
        row.capacity_release,
        claim.expected_plan,
        claim.state,
        claim.prepared_receipt,
    ) == custody
    assert (row.completed_at, row.storage_path, row.size_bytes) == storage


@pytest.mark.parametrize(
    "field,value",
    [
        ("disposition", []),
        ("disposition", {}),
        ("schema", True),
        ("schema", 2),
        ("backup_id", "other"),
        ("reservation_id", "other"),
        ("plan_sha256", "0" * 64),
        ("reason", "https://secret:credential@invalid"),
        ("extra", "unexpected"),
        ("reservation_id", None),
    ],
)
def test_invalid_or_unbound_report_ignored(db_session, held, field, value):
    agent, row, claim, event = held
    event[field] = value
    assert not observe_storage_hold(db_session, agent, event)
    assert row.status == "running" and row.tags == {"preserve": "existing"}
    assert not db_session.dirty


@pytest.mark.parametrize("field", ["id", "org_id"])
def test_foreign_agent_or_tenant_ignored(db_session, held, field):
    agent, row, claim, event = held
    foreign = SimpleNamespace(id=agent.id, org_id=agent.org_id)
    setattr(foreign, field, str(uuid4()))
    assert not observe_storage_hold(db_session, foreign, event)
    assert row.status == "running"


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "foreign"),
        ("org_id", "foreign"),
        ("backup_id", "foreign"),
        ("reservation_id", "foreign"),
        ("plan_sha256", "0" * 64),
        ("plan", {"provider": "libvirt"}),
        ("plan", "invalid"),
    ],
)
def test_recorded_transaction_must_match(db_session, held, field, value):
    agent, row, claim, event = held
    plan = deepcopy(claim.expected_plan)
    plan["transaction"][field] = value
    claim.expected_plan = plan
    db_session.commit()
    assert not observe_storage_hold(db_session, agent, event)
    assert row.status == "running" and row.tags == {"preserve": "existing"}


def test_published_payload_cannot_be_regressed(db_session, held):
    agent, row, claim, event = held
    claim.state = "published"
    db_session.commit()
    assert not observe_storage_hold(db_session, agent, event)
    assert row.status == "running" and claim.state == "published"


@pytest.mark.asyncio
async def test_heartbeat_routes_exact_storage_hold(db_session, held, monkeypatch):
    from routers.health import _process_agent_events

    agent, row, claim, event = held
    observed = []
    monkeypatch.setattr(
        "routers.health.observe_storage_hold", lambda *args: observed.append(args)
    )
    await _process_agent_events(agent, [event], db_session)
    assert observed == [(db_session, agent, event)]


@pytest.mark.parametrize(
    "status,capacity",
    [("completed", "reserved"), ("deleted", "reserved"), ("running", "released")],
)
def test_terminal_or_released_custody_not_regressed(db_session, held, status, capacity):
    agent, row, claim, event = held
    row.status, row.capacity_state = status, capacity
    if capacity == "released":
        row.capacity_release = {"reason": "fixture"}
    db_session.commit()
    assert not observe_storage_hold(db_session, agent, event)
    assert row.status == status and row.tags == {"preserve": "existing"}


def test_safety_diagnostic_is_visible_without_releasing_custody(db_session, held):
    from core.storage_hold_observation import public_safety_diagnostic

    agent, row, claim, event = held
    event.update(
        schema=2,
        diagnostic={
            "stage": "mapping",
            "reason": "map_stored_range_limit",
            "disposition": "refused",
            "page": 39,
            "offset": 81788928,
            "raw_ranges": 19968,
            "stored_ranges": 10000,
            "acknowledged_bytes": 0,
            "native_stop_phase": "native_absent_unproven",
            "last_progress_at": "2026-11-07T00:00:00Z",
        },
    )
    assert observe_storage_hold(db_session, agent, event)
    db_session.commit()
    db_session.expire(row)
    db_session.refresh(row)
    assert public_safety_diagnostic(row) == event["diagnostic"]
    assert row.status == "cleanup_required"
    assert "map_stored_range_limit" in row.tags["error"]
    assert row.tags["storage_hold"]["diagnostic"] == event["diagnostic"]
    assert row.capacity_state == "reserved" and claim.state == "reserved"
    assert row.completed_at is None and claim.prepared_receipt is None
    assert not observe_storage_hold(db_session, agent, event)


def test_public_diagnostic_survives_a_mutable_json_database_roundtrip():
    from sqlalchemy import Column, Integer, JSON, String, create_engine
    from sqlalchemy.ext.mutable import MutableDict
    from sqlalchemy.orm import Session, declarative_base
    from core.storage_hold_observation import public_safety_diagnostic

    # The general SQLite fixture replaces JSONB with plain JSON before mapper
    # setup, losing the production column's MutableDict instrumentation. Exercise
    # the real mutable JSON mapping separately, including loading a new instance.
    base = declarative_base()

    class PersistedBackup(base):
        __tablename__ = "diagnostic_backup"
        id = Column(Integer, primary_key=True)
        status = Column(String, nullable=False)
        tags = Column(MutableDict.as_mutable(JSON), nullable=False)

    diagnostic = {
        "stage": "queued",
        "reason": "admission_wait_exhausted",
        "disposition": "refused",
        "native_stop_phase": "no_native_started",
        "acknowledged_bytes": 0,
    }
    engine = create_engine("sqlite:///:memory:")
    try:
        base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(
                PersistedBackup(
                    id=1,
                    status="cleanup_required",
                    tags={"storage_hold": {"schema": 2, "diagnostic": diagnostic}},
                )
            )
            session.commit()
            session.expunge_all()
            row = session.get(PersistedBackup, 1)
            assert isinstance(row.tags, MutableDict)
            assert public_safety_diagnostic(row) == diagnostic
            row.tags = {
                "storage_hold": {
                    "schema": 2,
                    "diagnostic": {
                        **diagnostic,
                        "provider_body": "private provider response",
                    },
                }
            }
            session.commit()
            session.expire_all()
            assert public_safety_diagnostic(row) is None
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "field,value",
    [
        ("reason", "https://private:credential@host/path"),
        ("page", True),
        ("offset", 2**63),
        ("acknowledged_bytes", -1),
        ("first_byte_at", "not-a-timestamp"),
        ("http_status", 999),
        ("response_body", "private response"),
        ("disposition", "publish"),
    ],
)
def test_unsafe_safety_diagnostics_are_rejected(db_session, held, field, value):
    agent, row, claim, event = held
    diagnostic = {
        "stage": "mapping",
        "reason": "map_schema_invalid",
        "disposition": "refused",
    }
    diagnostic[field] = value
    event.update(schema=2, diagnostic=diagnostic)
    assert not observe_storage_hold(db_session, agent, event)
    assert row.status == "running" and row.capacity_state == "reserved"
