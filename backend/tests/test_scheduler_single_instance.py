"""Single scheduler instance — regression for the split-brain (#42).

app.py used to run a SECOND BackgroundScheduler. Startup-loaded schedules landed on
app.py's instance, while the schedules router registered runtime create/update/delete on
scheduler.py's instance. That split caused:
  - double-execution on edit — a startup-loaded schedule re-added via the router ended up
    on BOTH instances and fired twice;
  - ghost-execution on delete-after-restart — a delete hit the router's instance while the
    reloaded job survived on app.py's instance and kept firing.

The invariant test below is the guard: with a single shared instance the split-brain
cannot occur. The functional tests confirm edit (replace-in-place) and delete work on the
consolidated instance, exercising both the startup-load and router entry points.
"""

import pytest

import scheduler as scheduler_mod
from models import Schedule
from apscheduler.schedulers.base import STATE_RUNNING
from unittest.mock import MagicMock
from scheduler import (
    scheduler,
    add_schedule_to_scheduler,
    remove_schedule_from_scheduler,
)

# Daily 03:00 UTC. The registry uses a minute wakeup; these tests pause its
# clock because they inspect registration, not execution/admission.
FUTURE_CRON = "0 3 * * *"


def _jobs_for(job_id):
    return [j for j in scheduler.get_jobs() if j.id == job_id]


@pytest.fixture
def cleanup_jobs(monkeypatch):
    """Remove any 'sched-*' jobs the test registered from the shared scheduler."""
    prior_state = scheduler.state
    started_here = not scheduler.running
    if started_here:
        # Exercise the real job registry while keeping its clock inert.
        monkeypatch.setattr("apscheduler.schedulers.background.Thread", MagicMock())
        scheduler.start(paused=True)
    else:
        scheduler.pause()
    yield
    for job in list(scheduler.get_jobs()):
        if job.id.startswith("sched-"):
            scheduler.remove_job(job.id)
    if started_here:
        scheduler.shutdown(wait=True)
    elif prior_state == STATE_RUNNING:
        scheduler.resume()


def test_app_and_scheduler_share_one_instance():
    """The invariant: ONE BackgroundScheduler, shared by app.py and scheduler.py.

    If a second instance is ever reintroduced this fails immediately — and with it the
    split-brain (double-exec on edit, ghost-delete after restart) would return.
    """
    import app

    assert app.scheduler is scheduler_mod.scheduler
    assert app.add_schedule_to_scheduler is scheduler_mod.add_schedule_to_scheduler
    assert (
        app.remove_schedule_from_scheduler
        is scheduler_mod.remove_schedule_from_scheduler
    )
    assert app.load_schedules is scheduler_mod.load_schedules


def test_edit_reregisters_in_place_no_double(cleanup_jobs):
    """Editing/toggling a schedule re-registers it in place — one job, no double-exec."""
    add_schedule_to_scheduler("sched-edit", FUTURE_CRON)
    assert len(_jobs_for("sched-edit")) == 1
    # An edit/toggle re-adds (possibly with a new cron) — it must replace, not duplicate.
    add_schedule_to_scheduler("sched-edit", "0 4 * * *")
    assert (
        len(_jobs_for("sched-edit")) == 1
    ), "edit must not leave a duplicate job (double-execution)"


@pytest.mark.asyncio
async def test_delete_after_startup_load_removes_job(
    session_factory, monkeypatch, cleanup_jobs
):
    """Ghost-delete regression: a schedule registered by the STARTUP path (load_schedules)
    and then deleted via the ROUTER path (remove_schedule_from_scheduler) must actually be
    gone — both now target the one shared instance."""
    import app  # noqa: F401 — ensure the app-side wiring is imported/live
    import database

    monkeypatch.setattr(database, "SessionLocal", session_factory)

    db = session_factory()
    db.add(
        Schedule(
            id="sched-restart",
            name="estate",
            cron_expression=FUTURE_CRON,
            enabled=True,
            current_grant_id="fixture-grant",
        )
    )
    db.commit()
    db.close()

    # Startup-load path (previously → app.py's instance).
    await scheduler_mod.load_schedules()
    assert len(_jobs_for("sched-restart")) == 1

    # Router delete path (previously → scheduler.py's instance, leaving a ghost).
    remove_schedule_from_scheduler("sched-restart")
    assert (
        _jobs_for("sched-restart") == []
    ), "startup-loaded schedule must be removable via the router path (no ghost)"
