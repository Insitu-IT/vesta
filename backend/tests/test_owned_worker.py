"""Worker cancellation cannot release dispatch lifetime before work exits."""

import asyncio
import threading

import pytest

from core.task_lifetime import run_owned_worker


@pytest.mark.asyncio
async def test_cancel_waits_for_worker_and_fences_unsent_continuation():
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    cancelled = threading.Event()

    def work():
        entered.set()
        assert release.wait(2), "test did not release worker"
        finished.set()

    task = asyncio.create_task(run_owned_worker(work, on_cancel=cancelled.set))
    assert await asyncio.to_thread(entered.wait, 1)
    task.cancel()
    await asyncio.sleep(0.05)
    assert cancelled.is_set()
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finished.is_set()
