"""Await local monitor teardown without transferring foreign-loop ownership."""

import asyncio
from contextlib import contextmanager
from contextvars import copy_context
from functools import wraps
import threading

from starlette.concurrency import run_in_threadpool


async def run_owned_worker(function, *args, on_cancel=None, **kwargs):
    """Keep the owning task alive until a synchronous worker actually exits.

    Cancelling an ordinary threadpool await abandons its still-running function.
    Dispatch admission and shutdown must instead retain that worker until its
    transaction/transport resolves. `on_cancel` fences an unsent continuation;
    work already sent remains under its original durable attempt custody.
    """
    worker = asyncio.create_task(run_in_threadpool(function, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        if on_cancel is not None:
            on_cancel()
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        # Retrieve a worker exception without allowing it to replace the
        # caller's cancellation. The original attempt remains inspectable.
        try:
            worker.result()
        except BaseException:
            pass
        raise


class DispatchLifetime:
    """One loop owns each executor's transport and admitted dispatch calls."""

    def __init__(self):
        self.closed = False
        self.loop = None
        self.tasks = {}
        self.lock = threading.Lock()

    def close_admission(self):
        with self.lock:
            self.closed = True

    @contextmanager
    def admission(self):
        loop = asyncio.get_running_loop()
        with self.lock:
            if self.closed:
                raise RuntimeError("Dispatch admission is closed")
            if self.loop is not None and self.loop is not loop:
                raise RuntimeError("Dispatch requires its owning event loop")
            self.loop = loop
            task = asyncio.current_task()
            self.tasks[task] = self.tasks.get(task, 0) + 1
        try:
            yield
        finally:
            with self.lock:
                self.tasks[task] -= 1
                if not self.tasks[task]:
                    del self.tasks[task]

    async def drain(self):
        self.close_admission()
        if self.loop is not None and self.loop is not asyncio.get_running_loop():
            raise RuntimeError("Dispatch shutdown requires its owning event loop")
        tasks = {id(task): task for task in self.tasks}
        await drain_monitors(tasks)


def owned_dispatch(method):
    @wraps(method)
    async def call(self, *args, **kwargs):
        with self.dispatch_lifetime.admission():
            return await method(self, *args, **kwargs)

    return call


class SchedulerWork:
    """Fence sync callbacks and submit their async work to the application loop.

    No transport is used from an APScheduler/Starlette worker thread. Registration
    and close share a condition lock; shutdown waits for admitted callbacks before
    draining the loop's submissions. Refused submissions leave DB custody intact.
    """

    def __init__(self):
        self.condition = threading.Condition()
        self.closed = False
        self.callbacks = 0
        self.loop = None
        self.tasks = {}
        self.pending = 0
        self.errors = []

    def start(self):
        with self.condition:
            if self.callbacks or self.tasks or self.pending or self.errors:
                raise RuntimeError(
                    "Scheduler work still requires shutdown reconciliation"
                )
            self.loop = asyncio.get_running_loop()
            self.closed = False

    def close_admission(self):
        with self.condition:
            self.closed = True

    @contextmanager
    def callback(self):
        with self.condition:
            if self.closed:
                raise RuntimeError("Scheduler admission is closed")
            self.callbacks += 1
        try:
            yield
        finally:
            with self.condition:
                self.callbacks -= 1
                self.condition.notify_all()

    def submit(self, function, *args):
        with self.condition:
            if self.closed or self.loop is None or self.loop.is_closed():
                raise RuntimeError("Scheduler dispatch admission is closed")
            context = copy_context()
            self.pending += 1

            def launch():
                with self.condition:
                    self.pending -= 1
                    if self.closed:
                        return
                    coroutine = None
                    try:
                        coroutine = function(*args)
                        task = asyncio.create_task(coroutine)
                    except Exception as error:
                        if asyncio.iscoroutine(coroutine):
                            coroutine.close()
                        self.closed = True
                        self.errors.append(error)
                        return
                    self.tasks[id(task)] = task
                    task.add_done_callback(self._finished)

            try:
                self.loop.call_soon_threadsafe(launch, context=context)
            except BaseException:
                self.pending -= 1
                raise

    def _finished(self, task):
        self.tasks.pop(id(task), None)
        if not task.cancelled() and task.exception() is not None:
            self.close_admission()
            if not self.errors:
                self.errors.append(task.exception())

    def _wait_callbacks(self):
        with self.condition:
            self.condition.wait_for(lambda: self.callbacks == 0)

    async def drain(self):
        self.close_admission()
        if self.loop is not None and self.loop is not asyncio.get_running_loop():
            raise RuntimeError("Scheduler drain requires its owning event loop")
        await asyncio.to_thread(self._wait_callbacks)
        # All accepted call_soon_threadsafe registrations precede this barrier.
        await asyncio.sleep(0)
        await drain_monitors(self.tasks)
        if self.pending:
            raise RuntimeError("Scheduler submissions remain pending")
        if self.errors:
            raise self.errors[0]


async def drain_monitors(registry):
    """Cancel a stable local snapshot; follow any successor registered on teardown.

    A scheduler's separate loop must be drained by its own owner. Refuse before
    cancelling anything if foreign live tasks exist; never close their transport.
    No durable operation status is changed or remote cancellation inferred.
    """
    loop = asyncio.get_running_loop()
    while registry:
        snapshot = tuple(registry.items())
        if any(task.get_loop() is not loop for _, task in snapshot):
            raise RuntimeError("Monitor shutdown requires its owning event loop")
        for _, task in snapshot:
            task.cancel()
        await asyncio.gather(*(task for _, task in snapshot), return_exceptions=True)
        for key, task in snapshot:
            if registry.get(key) is task:
                del registry[key]
