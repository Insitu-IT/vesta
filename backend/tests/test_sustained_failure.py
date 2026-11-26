"""Sustained backup-failure alerting: backup_failing_sustained SystemEvent (#41).

Follow-up to #38. Once a VM accumulates `threshold` consecutive `failed` backups with no
`completed` in between, notify_backup_failure emits a single distinct
`backup_failing_sustained` SystemEvent (once per streak) so a sustained outage — the Mesh
case, a VM failing for weeks — is distinguishable in-product from a one-off blip. The
per-failure `backup_failed` event (#38) and the no-success-in-X-days staleness metric are
unchanged; this only adds the streak signal.
"""

import uuid
from datetime import datetime, timedelta

import pytest

from models import Backup, SystemEvent

BASE = datetime(2026, 7, 1, 12, 0, 0)


def _add_backup(db, status, when, vm_id="vm-1"):
    b = Backup(
        id=str(uuid.uuid4()),
        vm_id=vm_id,
        status=status,
        backup_type="full",
        tags={},
        created_at=when,
    )
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


def _sustained_events(db, vm_id=None):
    q = db.query(SystemEvent).filter(
        SystemEvent.event_type == "backup_failing_sustained"
    )
    if vm_id is not None:
        q = q.filter(SystemEvent.resource_id == vm_id)
    return q.all()


@pytest.fixture
def notifications(session_factory, monkeypatch):
    """Bind the module's isolated SessionLocal to the test DB; default threshold = 3.

    notify_backup_failure's helpers open their own SessionLocal() (imported into the
    module at import time), so it must be patched on the module — see #38's test. The
    threshold is monkeypatched to keep the streak logic hermetic from the settings cache.
    """
    import core.notifications as notifications

    monkeypatch.setattr(notifications, "SessionLocal", session_factory)
    monkeypatch.setattr(
        notifications, "get_sustained_failure_threshold", lambda db=None: 3
    )
    return notifications


async def _fail(notifications, db, when, vm_id="vm-1", error="boom"):
    """Simulate a hard backup failure: persist a failed row, then notify (as callers do)."""
    b = _add_backup(db, "failed", when, vm_id=vm_id)
    await notifications.notify_backup_failure(b, vm_name=vm_id, error=error, db=db)
    return b


@pytest.mark.asyncio
async def test_below_threshold_no_event(notifications, session_factory):
    """threshold-1 consecutive failures must NOT emit a sustained event."""
    db = session_factory()
    await _fail(notifications, db, BASE + timedelta(seconds=1))
    await _fail(notifications, db, BASE + timedelta(seconds=2))
    assert _sustained_events(db) == []
    db.close()


@pytest.mark.asyncio
async def test_at_threshold_fires_once(notifications, session_factory):
    """The Nth consecutive failure emits exactly one sustained event with useful detail."""
    db = session_factory()
    await _fail(notifications, db, BASE + timedelta(seconds=1))
    await _fail(notifications, db, BASE + timedelta(seconds=2))
    await _fail(notifications, db, BASE + timedelta(seconds=3), error="agent 403")

    events = _sustained_events(db)
    assert len(events) == 1
    ev = events[0]
    assert ev.source == "backup"
    assert ev.resource_type == "vm"
    assert ev.resource_id == "vm-1"
    assert ev.details["threshold"] == 3
    assert ev.details["consecutive_failures"] >= 3
    assert ev.details["last_success_at"] is None
    assert "403" in ev.details["latest_error"]
    db.close()


@pytest.mark.asyncio
async def test_dedup_no_refire_on_continued_failures(notifications, session_factory):
    """A long streak yields ONE alert, not one per failed attempt."""
    db = session_factory()
    for i in range(1, 6):  # 5 consecutive failures
        await _fail(notifications, db, BASE + timedelta(seconds=i))
    assert len(_sustained_events(db)) == 1
    db.close()


@pytest.mark.asyncio
async def test_reset_after_success_then_new_streak_refires(
    notifications, session_factory
):
    """A `completed` breaks the streak; a fresh N-failure run alerts again."""
    db = session_factory()
    # First streak -> event 1. Timestamps are slightly in the past so the event's
    # (real-now) created_at precedes the success timestamp used by the dedup boundary.
    now = datetime.utcnow()
    await _fail(notifications, db, now - timedelta(seconds=30))
    await _fail(notifications, db, now - timedelta(seconds=20))
    await _fail(notifications, db, now - timedelta(seconds=10))
    assert len(_sustained_events(db)) == 1

    # A success (after the first event) resets the streak, then a new run fails.
    _add_backup(db, "completed", now + timedelta(hours=1))
    await _fail(notifications, db, now + timedelta(hours=1, seconds=10))
    await _fail(notifications, db, now + timedelta(hours=1, seconds=20))
    assert len(_sustained_events(db)) == 1, "reset not crossed yet"
    await _fail(notifications, db, now + timedelta(hours=1, seconds=30))

    events = _sustained_events(db)
    assert len(events) == 2, "second streak must emit a distinct alert"
    assert events[-1].details["last_success_at"] is not None
    db.close()


@pytest.mark.asyncio
async def test_upload_failed_current_is_not_a_hard_failure(
    notifications, session_factory
):
    """notify_backup_failure fires for exhausted S3 uploads too, but upload_failed
    produced a local backup and must NOT count toward the streak."""
    db = session_factory()
    _add_backup(db, "failed", BASE + timedelta(seconds=1))
    _add_backup(db, "failed", BASE + timedelta(seconds=2))
    current = _add_backup(db, "upload_failed", BASE + timedelta(seconds=3))
    await notifications.notify_backup_failure(
        current, vm_name="vm-1", error="S3 upload failed", db=db
    )
    assert _sustained_events(db) == []
    db.close()


@pytest.mark.asyncio
async def test_upload_failed_interspersed_does_not_break_streak(
    notifications, session_factory
):
    """Only `completed` breaks a streak; an interspersed upload_failed is ignored."""
    db = session_factory()
    await _fail(notifications, db, BASE + timedelta(seconds=1))
    await _fail(notifications, db, BASE + timedelta(seconds=2))
    _add_backup(
        db, "upload_failed", BASE + timedelta(seconds=3)
    )  # ignored, not a success
    await _fail(notifications, db, BASE + timedelta(seconds=4))
    assert len(_sustained_events(db)) == 1
    db.close()


@pytest.mark.asyncio
async def test_threshold_le_one_disables(notifications, session_factory, monkeypatch):
    """threshold <= 1 disables the distinct event (backup_failed already covers singles)."""
    monkeypatch.setattr(
        notifications, "get_sustained_failure_threshold", lambda db=None: 1
    )
    db = session_factory()
    for i in range(1, 5):
        await _fail(notifications, db, BASE + timedelta(seconds=i))
    assert _sustained_events(db) == []
    db.close()


@pytest.mark.asyncio
async def test_per_vm_isolation(notifications, session_factory):
    """A streak on one VM must not trigger an alert for another."""
    db = session_factory()
    for i in range(1, 4):
        await _fail(notifications, db, BASE + timedelta(seconds=i), vm_id="vm-A")
    await _fail(notifications, db, BASE + timedelta(seconds=10), vm_id="vm-B")

    assert len(_sustained_events(db, vm_id="vm-A")) == 1
    assert _sustained_events(db, vm_id="vm-B") == []
    db.close()


def test_setting_default_is_three(db_session):
    """The threshold setting is registered with a sensible on-by-default value."""
    from core.settings_reader import DEFAULTS, get_sustained_failure_threshold

    assert DEFAULTS[("backup", "sustained_failure_threshold")] == 3
    assert get_sustained_failure_threshold(db_session) == 3
