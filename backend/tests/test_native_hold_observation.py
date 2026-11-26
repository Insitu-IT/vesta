"""Only the original native agent/attempt can annotate a retained hold."""

from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
import uuid

import pytest

from core.native_hold_observation import observe_native_hold
from core.native_inventory import digest
from .conftest import make_agent, make_backup, make_vm


@pytest.fixture
def held(db_session):
    agent = make_agent(db_session)
    vm = make_vm(db_session, agent)
    row = make_backup(
        db_session,
        vm,
        status="running",
        capacity_state="reserved",
        capacity_id=str(uuid.uuid4()),
        capacity_reserved_at=datetime.utcnow(),
        capacity_policy_revision=1,
        tags={"preserve": "existing"},
    )
    intent = dict(
        producer="libvirt-push-qcow2/1",
        backup_id=row.id,
        org_id=row.org_id,
        agent_id=agent.id,
        attempt_id=str(uuid.uuid4()),
    )
    row.native_job_intent = intent
    db_session.commit()
    event = dict(
        type="native_attempt_held",
        schema=1,
        backup_id=row.id,
        attempt_id=intent["attempt_id"],
        intent_sha256=digest(intent),
        reason="native_upload_held",
    )
    return agent, row, event


def test_exact_hold_is_idempotent_display_only(db_session, held):
    agent, row, event = held
    original = (
        row.status,
        row.capacity_state,
        row.capacity_id,
        deepcopy(row.native_job_intent),
        row.native_inventory,
    )
    assert observe_native_hold(db_session, agent, event)
    db_session.commit()
    assert row.tags == dict(
        preserve="existing",
        native_hold={
            k: event[k] for k in ("schema", "attempt_id", "intent_sha256", "reason")
        },
    )
    assert not observe_native_hold(db_session, agent, event)
    assert not db_session.dirty
    assert (
        row.status,
        row.capacity_state,
        row.capacity_id,
        row.native_job_intent,
        row.native_inventory,
    ) == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("backup_id", "other"),
        ("attempt_id", "other"),
        ("intent_sha256", "0" * 64),
        ("reason", "https://secret:credential@provider.invalid"),
        ("reason", "x" * 129),
        ("extra", "unexpected"),
        ("attempt_id", None),
    ],
)
def test_invalid_or_unbound_observation_is_ignored(db_session, held, field, value):
    agent, row, event = held
    event[field] = value
    assert not observe_native_hold(db_session, agent, event)
    assert row.tags == {"preserve": "existing"}
    assert not db_session.dirty


@pytest.mark.parametrize("foreign", ["agent", "organization"])
def test_other_agent_or_tenant_cannot_report(db_session, held, foreign):
    agent, row, event = held
    observer = SimpleNamespace(id=agent.id, org_id=agent.org_id)
    setattr(observer, "id" if foreign == "agent" else "org_id", str(uuid.uuid4()))
    assert not observe_native_hold(db_session, observer, event)
    assert row.tags == {"preserve": "existing"}


def test_missing_native_intent_cannot_adopt_job(db_session, held):
    agent, row, event = held
    row.native_job_intent = None
    db_session.commit()
    assert not observe_native_hold(db_session, agent, event)
    assert row.tags == {"preserve": "existing"}
