"""Tests for configurable retention schedule + safe-default enable-toggle (#29).

Two guarantees:
  1. SAFETY — with no `backup.auto_cleanup` setting, retention must NOT prune. The
     default is OFF (destructive op → opt-in). A regression that flips the default
     back to ON must fail this test.
  2. SCHEDULE — `reschedule_retention_job(hour)` (re)installs the daily job at the
     chosen server-local hour, clamping bad/out-of-range input to 3.
"""

from unittest.mock import MagicMock

import pytest
from apscheduler.schedulers.background import BackgroundScheduler


@pytest.fixture
def retention_clock(monkeypatch):
    """Own a live job registry without starting a background clock thread."""
    import app

    monkeypatch.setattr("apscheduler.schedulers.background.Thread", MagicMock())
    clock = BackgroundScheduler()
    monkeypatch.setattr(app, "scheduler", clock)
    clock.start(paused=True)
    try:
        yield clock
    finally:
        clock.shutdown(wait=True)


@pytest.mark.asyncio
async def test_retention_defaults_off_when_unset(session_factory, monkeypatch):
    """No auto_cleanup setting → enforce_all() skips, deletes nothing (#29 default OFF)."""
    import core.retention as retention_mod
    from core import settings_reader

    # enforce_all() opens its own SessionLocal() — point it at the empty test DB.
    monkeypatch.setattr(retention_mod, "SessionLocal", session_factory)
    # No env override, fresh cache → resolution falls through to the default.
    monkeypatch.delenv("AUTO_CLEANUP", raising=False)
    settings_reader.invalidate_cache()

    result = await retention_mod.retention_enforcer.enforce_all()

    assert result.get("skipped") is True, "unset auto_cleanup must NOT prune"
    assert result.get("reason") == "auto_cleanup disabled"
    assert result.get("deleted_count") == 0
    assert result.get("deleted_bytes") == 0


def test_reschedule_retention_job_sets_hour(retention_clock):
    """reschedule_retention_job installs the daily job at the given hour."""
    import app

    used = app.reschedule_retention_job(7)
    assert used == 7

    job = app.scheduler.get_job("retention_enforcement")
    assert job is not None, "retention_enforcement job must exist after reschedule"
    hour_field = next(f for f in job.trigger.fields if f.name == "hour")
    assert str(hour_field) == "7"
    minute_field = next(f for f in job.trigger.fields if f.name == "minute")
    assert str(minute_field) == "0"


def test_reschedule_retention_job_clamps_bad_input(retention_clock):
    """Out-of-range / non-numeric hours fall back to 3; a valid 0 (midnight) is kept."""
    import app

    assert app.reschedule_retention_job(99) == 3
    assert app.reschedule_retention_job(-1) == 3
    assert app.reschedule_retention_job("nonsense") == 3
    assert app.reschedule_retention_job(None) == 3
    # 0 is a valid hour (midnight) and must NOT be coerced to the fallback.
    assert app.reschedule_retention_job(0) == 0
    job = app.scheduler.get_job("retention_enforcement")
    hour_field = next(f for f in job.trigger.fields if f.name == "hour")
    assert str(hour_field) == "0"
