"""A contended scheduler admission cannot starve API health or outlive fencing."""

import asyncio
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from core.scheduler_scope import ScopeRefused
from core.scheduler_transactions import ClaimBinding
from core.storage_dispatch import ConnectedKubevirtDispatch


@pytest.mark.asyncio
async def test_contended_capacity_keeps_health_live_and_fence_prevents_send(
    monkeypatch,
):
    from routers.public import health_check

    entered = threading.Event()
    release = threading.Event()

    def claim(*args, **kwargs):
        return ClaimBinding(
            queue_id="queue",
            claim_id="claim",
            claimed_at=datetime.now(timezone.utc),
            backup_id="backup",
            state="claimed",
        )

    def blocked_capacity(*args, **kwargs):
        entered.set()
        assert release.wait(2), "test did not release capacity wait"
        return {"capacity_id": "capacity"}

    monkeypatch.setattr("core.scheduler_transactions.claim_queue", claim)
    monkeypatch.setattr("core.backup_capacity.reserve_capacity", blocked_capacity)
    sender = AsyncMock()
    dispatcher = ConnectedKubevirtDispatch(lambda: None, sender)
    task = asyncio.create_task(dispatcher.dispatch(object(), "queue"))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert await asyncio.wait_for(health_check(), 0.2) == {
            "status": "ok",
            "service": "vesta-api",
        }
        assert not task.done()
        dispatcher.dispatch_lifetime.close_admission()
    finally:
        release.set()
    with pytest.raises(ScopeRefused, match="dispatch_continuation_unavailable"):
        await task
    sender.assert_not_awaited()
