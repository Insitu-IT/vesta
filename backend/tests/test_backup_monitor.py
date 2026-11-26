"""Finite polling lifetime controls; persisted admission is exercised in PG."""

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from core import backup_executor as module
from core.backup_monitor import MonitorBinding, MonitorRefused, progress_observation
from core.tenant_context import identity


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_terminal_observation_is_not_publication(status):
    row = SimpleNamespace(id="backup", progress=10)
    assert (
        progress_observation(
            row,
            {
                "backup_id": "backup",
                "status": status,
                "checkpoint_committed": True,
                "s3_location": "s3://untrusted",
                "size_bytes": 999,
            },
        )
        is None
    )
    assert vars(row) == {"id": "backup", "progress": 10}


def test_held_observation_is_visible_without_publishing_or_releasing():
    row = SimpleNamespace(
        id="backup",
        status="running",
        progress=10,
        capacity_state="reserved",
        capacity_release=None,
        storage_path=None,
        size_bytes=None,
        completed_at=None,
        tags={"checkpoint_required": True, "checkpoint_committed": False},
    )
    event = progress_observation(
        row,
        {
            "backup_id": "backup",
            "status": "cleanup_required",
            "checkpoint_committed": True,
            "s3_location": "s3://untrusted",
            "size_bytes": 999,
            "progress_percent": 100,
        },
    )
    assert event == {
        "backup_id": "backup",
        "status": "cleanup_required",
        "progress": 10,
    }
    assert row.status == "cleanup_required" and row.tags["cleanup_required"]
    assert row.tags["checkpoint_committed"] is False
    assert row.capacity_state == "reserved" and row.capacity_release is None
    assert row.storage_path is row.size_bytes is row.completed_at is None
    assert row.progress == 10


def test_held_observation_preserves_existing_error():
    row = SimpleNamespace(id="backup", progress=0, tags={"error": "original"})
    progress_observation(row, {"backup_id": "backup", "status": "cleanup_required"})
    assert row.tags["error"] == "original"


@pytest.mark.parametrize("value", [-1, 101, True, None, "50", 0.5])
def test_progress_bounds(value):
    row = SimpleNamespace(id="backup", progress=10)
    with pytest.raises(MonitorRefused):
        progress_observation(
            row, {"backup_id": "backup", "status": "running", "progress_percent": value}
        )
    assert row.progress == 10


@pytest.mark.parametrize("response_id", [None, "another-backup"])
def test_status_response_must_bind_exact_backup(response_id):
    row = SimpleNamespace(id="backup", progress=10)
    with pytest.raises(MonitorRefused):
        progress_observation(
            row, {"backup_id": response_id, "status": "running", "progress_percent": 37}
        )
    assert row.progress == 10


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "progress",
        "held",
        "pre_refused",
        "post_refused",
        "commit_failure",
        "network",
        "cancel",
    ],
)
async def test_poll_lifetime_no_session_across_await(monkeypatch, case):
    executor = module.BackupExecutor()
    binding = MonitorBinding(
        "backup", str(uuid4()), str(uuid4()), "agent", "source", "https://agent.invalid"
    )
    active, events = [], []
    row = SimpleNamespace(id="backup", progress=0, status="running", tags={})

    class Session:
        def __enter__(self):
            active.append(self)
            events.append("open")
            return self

        def __exit__(self, *_):
            active.remove(self)
            events.append("close")

        def rollback(self):
            events.append("rollback")

        def commit(self):
            events.append("commit")
            if case == "commit_failure":
                raise RuntimeError("private-db-detail")

    admissions = []

    def admit(*_):
        admissions.append(True)
        assert active
        if (case == "pre_refused" and len(admissions) == 1) or (
            case == "post_refused" and len(admissions) == 2
        ):
            raise MonitorRefused("private-identity-detail")
        return row

    sleeps = []

    async def sleep(_):
        assert not active
        sleeps.append(True)
        if len(sleeps) > 1:
            executor.close_admission()

    async def get(*_, **__):
        assert not active
        events.append("get")
        if case == "cancel":
            raise asyncio.CancelledError()
        if case == "network":
            raise RuntimeError("private-provider-detail")
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "backup_id": "backup",
                "status": "cleanup_required" if case == "held" else "running",
                "progress_percent": 37,
            },
        )

    async def emit(**event):
        assert not active
        assert identity() == (binding.org_id, binding.actor_id, False)
        assert event == {
            "backup_id": "backup",
            "status": "cleanup_required" if case == "held" else "progress",
            "progress": 0 if case == "held" else 37,
        }
        assert events[-1] == "close" and "commit" in events
        events.append("event")

    monkeypatch.setattr(module, "SessionLocal", Session)
    monkeypatch.setattr("core.backup_monitor.admit", admit)
    monkeypatch.setattr(module.asyncio, "sleep", sleep)
    monkeypatch.setattr(executor.http_client, "get", get)
    headers = Mock(return_value={})
    monkeypatch.setattr(executor, "_get_agent_headers", headers)
    monkeypatch.setattr(module, "emit_backup_event", emit)
    before = identity()
    task = asyncio.create_task(executor.monitor_backup(binding))
    executor.monitoring_tasks[binding.backup_id] = task
    if case == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task
    assert not active and not executor.monitoring_tasks
    assert identity() == before
    assert headers.call_count == (0 if case == "pre_refused" else 1)
    assert ("event" in events) == (case in {"progress", "held"})
    if case == "held":
        assert row.status == "cleanup_required" and len(sleeps) == 1
    assert len(admissions) == (
        2 if case in {"progress", "held", "post_refused", "commit_failure"} else 1
    )
    await executor.http_client.aclose()


def test_no_path_only_upload_monitor_reachable():
    assert not hasattr(module.BackupExecutor, "monitor_upload")


def test_stale_sweep_excludes_durable_transaction_custody(db_session):
    from datetime import datetime
    from core.backup_monitor import stale_backup_candidates
    from models import Backup

    for state in ("unreserved", "released", "reserved", "legacy_held"):
        custody = {}
        if state != "unreserved":
            custody = dict(
                capacity_id=str(uuid4()), capacity_reserved_at=datetime.utcnow()
            )
            if state != "legacy_held":
                custody["capacity_policy_revision"] = 1
            if state == "released":
                custody["capacity_release"] = {"reason": "fixture"}
        db_session.add(
            Backup(
                id="stale-" + state,
                vm_id="fixture-vm",
                status="running",
                capacity_state=state,
                **custody,
            )
        )
    db_session.add(Backup(id="done", vm_id="fixture-vm", status="completed"))
    db_session.commit()
    assert {row.id for row in stale_backup_candidates(db_session)} == {
        "stale-unreserved",
        "stale-released",
    }
