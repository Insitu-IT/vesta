"""Same-attempt admission holds cannot starve the API liveness loop."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core import backup_recovery
from core.task_lifetime import DispatchLifetime


@pytest.mark.asyncio
async def test_contended_resume_requester_keeps_health_live(monkeypatch):
    from routers.public import health_check

    entered = threading.Event()
    release = threading.Event()

    def requester(db, backup_id, org_id, caller_id):
        entered.set()
        assert release.wait(2), "test did not release requester wait"
        return SimpleNamespace(status="completed")

    monkeypatch.setattr(backup_recovery, "_requester", requester)
    session = MagicMock()
    executor = SimpleNamespace(dispatch_lifetime=DispatchLifetime())
    task = asyncio.create_task(
        backup_recovery.resume_backup_attempt(
            lambda: session,
            executor,
            "backup",
            "00000000-0000-0000-0000-000000000001",
            "caller",
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert await asyncio.wait_for(health_check(), 0.2) == {
            "status": "ok",
            "service": "vesta-api",
        }
        assert not task.done()
    finally:
        release.set()
    assert await task == {
        "status": "completed",
        "backup_id": "backup",
        "resumed": False,
    }
    session.__enter__.return_value.rollback.assert_called_once()
