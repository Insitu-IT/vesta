"""Generic heartbeat observations are never modern transaction authority."""

from datetime import datetime
import uuid

import pytest
from sqlalchemy.dialects import postgresql

from core.backup_event_custody import generic_event_backups
from .conftest import make_agent, make_backup, make_vm


def candidate(db, **fields):
    agent = make_agent(db)
    vm = make_vm(db, agent)
    return make_backup(db, vm, status="running", **fields)


def test_existing_nontransaction_event_row_remains_addressable(db_session):
    row = candidate(db_session)
    assert generic_event_backups(db_session).filter_by(id=row.id).one() is row


@pytest.mark.parametrize("authority", ["human", "scheduler", "unknown"])
def test_modern_authority_excluded_before_admission(db_session, authority):
    row = candidate(db_session, authority_kind=authority)
    assert row.capacity_state == "unreserved"
    assert generic_event_backups(db_session).filter_by(id=row.id).first() is None


@pytest.mark.parametrize("state", ["reserved", "legacy_held", "released"])
def test_capacity_custody_excluded_even_without_native_intent(db_session, state):
    fields = dict(
        capacity_state=state,
        capacity_id=str(uuid.uuid4()),
        capacity_reserved_at=datetime.utcnow(),
    )
    if state != "legacy_held":
        fields["capacity_policy_revision"] = 1
    if state == "released":
        fields["capacity_release"] = {"reason": "test"}
    row = candidate(db_session, **fields)
    assert generic_event_backups(db_session).filter_by(id=row.id).first() is None


@pytest.mark.parametrize("field", ["native_job_intent", "native_inventory"])
def test_native_identity_excluded_even_without_capacity(db_session, field):
    row = candidate(db_session, **{field: {"attempt_id": str(uuid.uuid4())}})
    assert generic_event_backups(db_session).filter_by(id=row.id).first() is None


def test_predicate_and_nonblocking_lock_are_one_postgres_statement(db_session):
    statement = str(
        generic_event_backups(db_session).statement.compile(
            dialect=postgresql.dialect()
        )
    )
    assert "FOR UPDATE SKIP LOCKED" in statement
    assert "backups.authority_kind IS NULL" in statement
    assert "backups.capacity_state =" in statement
    assert "backups.native_job_intent IS NULL" in statement
    assert "backups.native_inventory IS NULL" in statement
