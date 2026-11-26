"""Regression tests for the retention scheduler fix (#37).

The daily retention job is fired by APScheduler's BackgroundScheduler on a
worker thread that has NO running event loop. The old code did
`asyncio.create_task(retention_enforcer.enforce_all())`, which raises
"no running event loop" — so retention silently never ran (broken 2026-07-06).
The fix drives the coroutine with `asyncio.run()`. These tests exercise the job
function from a plain sync context (same no-loop condition as the scheduler
thread) to prove the coroutine is actually driven to completion.
"""

import asyncio

import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [False, True])
async def test_orphan_manifest_scan_cannot_delete_on_database_absence(
    db_session, dry_run
):
    from unittest.mock import MagicMock, patch
    from core.retention import RetentionPolicyEnforcer

    client = MagicMock()
    keys = [
        "backups/manifests/other-tenant/live.json",
        "backups/manifests/absent/unknown.json",
    ]
    client.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": key} for key in keys]}
    ]
    enforcer = RetentionPolicyEnforcer()
    enforcer.dry_run = dry_run
    with patch(
        "core.settings_service.SettingsService.get_s3_config",
        return_value={"bucket": "shared"},
    ), patch("boto3.client", return_value=client):
        await enforcer._cleanup_orphaned_manifests(db_session, set())
    client.get_paginator.assert_called_once_with("list_objects_v2")
    client.delete_object.assert_not_called()
    client.delete_objects.assert_not_called()
    client.put_object.assert_not_called()


def test_create_task_fails_without_running_loop():
    """Document the bug: asyncio.create_task from a no-loop thread raises."""

    async def noop():
        return None

    with pytest.raises(RuntimeError):
        # This is what the old scheduler job did; it raised every run.
        asyncio.create_task(noop())


def test_run_retention_enforcement_drives_coroutine(monkeypatch):
    import app
    import core.retention

    ran = []

    async def fake_enforce_all():
        ran.append(True)

    monkeypatch.setattr(
        core.retention.retention_enforcer, "enforce_all", fake_enforce_all
    )
    monkeypatch.setattr(
        "core.tenant_work.organization_work_ids", lambda factory: ("default",)
    )
    # Called from this sync thread (no running loop) — same as the scheduler.
    app.run_retention_enforcement()
    assert ran == [True], "enforce_all() coroutine was not driven to completion"


def test_run_retention_enforcement_swallows_errors(monkeypatch):
    """A failing enforce_all is logged, not propagated (won't kill the thread)."""
    import app
    import core.retention

    async def boom():
        raise RuntimeError("simulated retention failure")

    monkeypatch.setattr(core.retention.retention_enforcer, "enforce_all", boom)
    monkeypatch.setattr(
        "core.tenant_work.organization_work_ids", lambda factory: ("default",)
    )
    app.run_retention_enforcement()  # must not raise


def test_retention_org_failure_does_not_skip_later_organization(monkeypatch):
    import app
    import core.retention
    from core.tenant_context import current_org, is_superuser

    observed = []

    async def work():
        observed.append((current_org.get(), is_superuser.get()))
        if current_org.get() == "first":
            raise RuntimeError("first organization failed")

    monkeypatch.setattr(
        "core.tenant_work.organization_work_ids", lambda factory: ("first", "second")
    )
    monkeypatch.setattr(core.retention.retention_enforcer, "enforce_all", work)
    app.run_retention_enforcement()
    assert observed == [("first", False), ("second", False)]
