"""Production scheduler/monitor lifetime; no provider or persistence claim."""

import asyncio
import threading
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from core import backup_executor as module
from core.tenant_context import TenantContext, identity
from scheduler import _run_backup_async
from core.task_lifetime import SchedulerWork


@pytest.fixture(autouse=True)
def isolated_lifetime_owners(monkeypatch):
    # Shutdown tests exercise real gates without retiring another test's singleton.
    import app as application
    import scheduler as jobs
    from core import (
        restore_executor,
        notifications,
        realtime,
        websocket,
        verification_executor,
        operator_dispatch,
    )

    dispatcher = operator_dispatch.OperatorDispatcher()
    monkeypatch.setattr(operator_dispatch, "operator_dispatcher", dispatcher)
    monkeypatch.setattr(application, "operator_dispatcher", dispatcher)
    work = SchedulerWork()
    monkeypatch.setattr(application, "scheduler_work", work)
    monkeypatch.setattr(jobs, "scheduler_work", work)
    monkeypatch.setattr(module, "backup_executor", module.BackupExecutor())
    monkeypatch.setattr(
        restore_executor, "restore_executor", restore_executor.RestoreExecutor()
    )
    monkeypatch.setattr(
        notifications, "notification_service", notifications.NotificationService()
    )
    monkeypatch.setattr(realtime, "realtime", realtime.RealtimeManager())
    monkeypatch.setattr(websocket, "websocket_manager", websocket.WebSocketManager())
    monkeypatch.setattr(
        verification_executor,
        "verification_executor",
        verification_executor.VerificationExecutor(),
    )
    monkeypatch.setattr(verification_executor, "_work_ids", lambda *args: ())


@pytest.mark.asyncio
async def test_stale_timer_notification_uses_application_owner_loop(monkeypatch):
    from types import SimpleNamespace
    import app as application
    import database
    from core import commercial, notifications, settings_reader, task_lifetime
    from core.backup_queue_processor import BackupQueueProcessor
    from core.notifications import notification_service

    monkeypatch.setattr(application.settings, "demo_mode", False)
    monkeypatch.setattr(
        application,
        "operator_dispatcher",
        MagicMock(start=MagicMock(), close_admission=MagicMock(), cleanup=AsyncMock()),
    )
    monkeypatch.setattr(application, "init_database", MagicMock())
    monkeypatch.setattr(application, "SessionLocal", MagicMock())
    monkeypatch.setattr(database, "SessionLocal", MagicMock())
    monkeypatch.setattr(application.metrics, "collect_gauge_metrics", MagicMock())
    monkeypatch.setattr(application, "scheduler", MagicMock(running=False))
    monkeypatch.setattr(application, "queue_processor", None)
    monkeypatch.setattr(application, "load_schedules", AsyncMock())
    monkeypatch.setattr(application, "_recover_orphaned_uploads", AsyncMock())
    monkeypatch.setattr(settings_reader, "get_setting_with_db", lambda *args: 3)
    monkeypatch.setattr(BackupQueueProcessor, "start", AsyncMock())
    monkeypatch.setattr(BackupQueueProcessor, "stop", AsyncMock())
    monkeypatch.setattr(commercial, "load_commercial_modules", lambda *args: [])
    before = identity()
    orgs = (
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    )
    loop = asyncio.get_running_loop()
    scopes, workers = [], []
    hold = False
    suspended = asyncio.Event()

    monkeypatch.setattr(notification_service, "_send_smtp", lambda *args: None)

    async def notify(backup, vm_name, error):
        scopes.append(identity()[0])
        assert asyncio.get_running_loop() is loop
        assert await notification_service._send_email(
            "subject",
            "body",
            ["recipient"],
            {"server": "smtp.invalid", "from_email": "sender"},
        )
        if hold:
            suspended.set()
            await asyncio.Future()

    async def controlled_work(function):
        # Replace database mutation only; the scheduler callback, tenant
        # notification scope and loop-owned SMTP path remain real.
        assert asyncio.get_running_loop() is loop
        assert function.__name__ == "_cleanup_stale_operations_worker"
        workers.append(function.__name__)
        return tuple(
            (org_id, SimpleNamespace(id=org_id), "vm", "stale") for org_id in orgs
        )

    monkeypatch.setattr(task_lifetime, "run_owned_worker", controlled_work)
    monkeypatch.setattr(notifications, "notify_stale_backup_failure", notify)
    await application.startup_event()
    callback = next(
        c.args[0]
        for c in application.scheduler.add_job.call_args_list
        if c.kwargs.get("id") == "cleanup_stale_operations"
    )
    for _ in range(2):
        await asyncio.to_thread(callback)
        async with asyncio.timeout(2):
            while (
                application.scheduler_work.pending or application.scheduler_work.tasks
            ):
                await asyncio.sleep(0.001)
    assert scopes == list(orgs) * 2
    assert workers == ["_cleanup_stale_operations_worker"] * 2
    assert identity() == before
    hold = True
    await asyncio.to_thread(callback)
    await asyncio.wait_for(suspended.wait(), 1)
    await application.shutdown_event()
    assert workers == ["_cleanup_stale_operations_worker"] * 3
    assert scopes == list(orgs) * 2 + [orgs[0]]
    assert not application.scheduler_work.tasks
    assert identity() == before
    with pytest.raises(RuntimeError, match="closed"):
        await asyncio.to_thread(callback)


@pytest.mark.asyncio
async def test_stale_timer_blocked_inventory_does_not_block_application_loop(
    monkeypatch,
):
    from contextlib import contextmanager
    import app as application
    import database
    from core import commercial, settings_reader, singleton, tenant_work
    from core.backup_queue_processor import BackupQueueProcessor

    monkeypatch.setattr(application.settings, "demo_mode", False)
    monkeypatch.setattr(
        application,
        "operator_dispatcher",
        MagicMock(start=MagicMock(), close_admission=MagicMock(), cleanup=AsyncMock()),
    )
    monkeypatch.setattr(application, "init_database", MagicMock())
    monkeypatch.setattr(application, "SessionLocal", MagicMock())
    monkeypatch.setattr(database, "SessionLocal", MagicMock())
    monkeypatch.setattr(application.metrics, "collect_gauge_metrics", MagicMock())
    monkeypatch.setattr(application, "scheduler", MagicMock(running=False))
    monkeypatch.setattr(application, "queue_processor", None)
    monkeypatch.setattr(application, "load_schedules", AsyncMock())
    monkeypatch.setattr(application, "_recover_orphaned_uploads", AsyncMock())
    monkeypatch.setattr(settings_reader, "get_setting_with_db", lambda *args: 3)
    monkeypatch.setattr(BackupQueueProcessor, "start", AsyncMock())
    monkeypatch.setattr(BackupQueueProcessor, "stop", AsyncMock())
    monkeypatch.setattr(commercial, "load_commercial_modules", lambda *args: [])

    loop_thread = threading.get_ident()
    entered, release = threading.Event(), threading.Event()

    @contextmanager
    def guard(name):
        assert name == "cleanup_stale_operations"
        assert threading.get_ident() != loop_thread
        yield True

    def blocked_inventory(_factory):
        assert threading.get_ident() != loop_thread
        entered.set()
        assert release.wait(5), "test failed to release blocked inventory"
        return ()

    monkeypatch.setattr(singleton, "cluster_singleton", guard)
    monkeypatch.setattr(tenant_work, "organization_work_ids", blocked_inventory)
    await application.startup_event()
    callback = next(
        call.args[0]
        for call in application.scheduler.add_job.call_args_list
        if call.kwargs.get("id") == "cleanup_stale_operations"
    )
    try:
        await asyncio.to_thread(callback)
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), 2)
        tick = asyncio.Event()
        asyncio.get_running_loop().call_soon(tick.set)
        await asyncio.wait_for(tick.wait(), 0.2)
    finally:
        release.set()
        await application.shutdown_event()


@pytest.mark.asyncio
@pytest.mark.parametrize("handoff", [False, True])
async def test_scheduler_owns_monitor_until_final_phase(monkeypatch, handoff):
    executor = module.BackupExecutor()
    monkeypatch.setattr(module, "backup_executor", executor)
    events = []
    before = identity()
    org = "00000000-0000-0000-0000-000000000001"

    async def upload():
        await asyncio.sleep(0)
        assert identity()[0] == org
        events.append("upload-finished")

    async def monitor():
        await asyncio.sleep(0)
        assert identity()[0] == org
        events.append("backup-finished")
        if handoff:
            executor.monitoring_tasks["backup"] = asyncio.create_task(upload())

    async def dispatch(backup_id):
        assert backup_id == "backup"
        executor.monitoring_tasks[backup_id] = asyncio.create_task(monitor())

    monkeypatch.setattr(executor, "execute_backup", dispatch)
    for _ in range(2):
        with TenantContext(org):
            await _run_backup_async("backup", True)
        assert executor.monitoring_tasks == {}
        assert identity() == before
    assert (
        events
        == (["backup-finished", "upload-finished"] if handoff else ["backup-finished"])
        * 2
    )


@pytest.mark.asyncio
async def test_old_monitor_cleanup_cannot_remove_successor(monkeypatch):
    from core.backup_monitor import MonitorBinding

    executor = module.BackupExecutor()
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    monkeypatch.setattr(module.asyncio, "sleep", AsyncMock())
    replacement = object()
    executor.monitoring_tasks["backup"] = replacement
    executor.close_admission()
    await executor.monitor_backup(
        MonitorBinding(
            "backup", "org", "actor", "agent", "source", "https://agent.invalid"
        )
    )
    assert executor.monitoring_tasks["backup"] is replacement
    db.close.assert_not_called()
    await executor.http_client.aclose()


@pytest.mark.asyncio
async def test_monitor_cancellation_closes_session_and_own_registry(monkeypatch):
    from core.backup_monitor import MonitorBinding

    executor = module.BackupExecutor()
    db = MagicMock()
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    started = asyncio.Event()

    async def sleep(_):
        started.set()
        await asyncio.Future()

    monkeypatch.setattr(module.asyncio, "sleep", sleep)
    task = asyncio.create_task(
        executor.monitor_backup(
            MonitorBinding(
                "backup", "org", "actor", "agent", "source", "https://agent.invalid"
            )
        )
    )
    executor.monitoring_tasks["backup"] = task
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert executor.monitoring_tasks == {}
    db.close.assert_not_called()  # Sleeping owns no session at all.
    await executor.http_client.aclose()


@pytest.mark.asyncio
async def test_scheduler_owner_cancellation_reaches_monitor(monkeypatch):
    executor = module.BackupExecutor()
    entered = asyncio.Event()
    finalized = []

    async def monitor():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            finalized.append(True)
            executor.monitoring_tasks.pop("backup")

    async def dispatch(_):
        executor.monitoring_tasks["backup"] = asyncio.create_task(monitor())

    monkeypatch.setattr(executor, "execute_backup", dispatch)
    task = asyncio.create_task(executor.execute_backup_and_wait("backup"))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finalized == [True]
    assert executor.monitoring_tasks == {}


@pytest.mark.asyncio
async def test_foreign_loop_monitor_refuses_without_cancelling_it(monkeypatch):
    executor = module.BackupExecutor()
    foreign_loop = asyncio.new_event_loop()
    future = foreign_loop.create_future()
    executor.monitoring_tasks["backup"] = future
    monkeypatch.setattr(executor, "execute_backup", AsyncMock())
    try:
        with pytest.raises(RuntimeError, match="another event loop"):
            await executor.execute_backup_and_wait("backup")
        assert not future.cancelled()
        assert executor.monitoring_tasks["backup"] is future
    finally:
        future.cancel()
        foreign_loop.close()


@pytest.mark.asyncio
async def test_drain_follows_successor_created_during_cancellation():
    from core.task_lifetime import drain_monitors

    registry, events = {}, []
    entered = asyncio.Event()

    async def successor():
        try:
            events.append("successor-start")
            await asyncio.Future()
        finally:
            events.append("successor-closed")

    async def parent():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            registry["backup"] = asyncio.create_task(successor())
            events.append("parent-closed")

    registry["backup"] = asyncio.create_task(parent())
    await entered.wait()
    await drain_monitors(registry)
    assert registry == {}
    assert events == ["parent-closed", "successor-start", "successor-closed"]


@pytest.mark.asyncio
async def test_queue_stop_drains_live_child_without_remote_cancellation():
    from core.backup_queue_processor import BackupQueueProcessor

    executor = MagicMock()
    entered, closed = asyncio.Event(), asyncio.Event()

    async def dispatch(_):
        try:
            entered.set()
            await asyncio.Future()
        finally:
            closed.set()

    executor.execute_backup_and_wait = dispatch
    processor = BackupQueueProcessor(MagicMock(), executor)
    child = asyncio.create_task(processor._execute_backup_async("backup"))
    processor._children.add(child)
    await entered.wait()
    await processor.stop()
    assert closed.is_set() and child.cancelled()
    assert not processor._children
    executor.stop_backup.assert_not_called()
    await processor.stop()


@pytest.mark.asyncio
async def test_cleanup_refuses_foreign_loop_before_closing_transport():
    executor = module.BackupExecutor()
    executor.http_client = MagicMock(aclose=AsyncMock())
    other = asyncio.new_event_loop()
    task = other.create_future()
    executor.monitoring_tasks["backup"] = task
    try:
        with pytest.raises(RuntimeError, match="owning event loop"):
            await executor.cleanup()
        executor.http_client.aclose.assert_not_awaited()
        assert not task.cancelled()
    finally:
        task.cancel()
        other.close()


@pytest.mark.asyncio
async def test_queue_poller_failure_still_drains_children_and_surfaces_error():
    from core.backup_queue_processor import BackupQueueProcessor

    processor = BackupQueueProcessor(MagicMock(), MagicMock())
    entered, closed = asyncio.Event(), asyncio.Event()

    async def child_work():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            closed.set()

    child = asyncio.create_task(child_work())
    processor._children.add(child)
    await entered.wait()
    failure = RuntimeError("poller failed")
    poller = asyncio.get_running_loop().create_future()
    poller.set_exception(failure)
    processor._task = poller
    with pytest.raises(RuntimeError) as raised:
        await processor.stop()
    assert raised.value is failure
    assert closed.is_set() and child.cancelled()
    assert not processor._children and processor._task is None
    await processor.stop()


@pytest.mark.asyncio
async def test_application_shutdown_orders_owned_drain_before_transport_close(
    monkeypatch,
):
    import app as application
    from core.restore_executor import restore_executor
    from core.notifications import notification_service
    from core.realtime import realtime
    from core.websocket import websocket_manager

    events = []

    async def queue_stop():
        assert application.scheduler_work.closed
        assert module.backup_executor.dispatch_lifetime.closed
        assert restore_executor.dispatch_lifetime.closed
        assert notification_service.dispatch_lifetime.closed
        assert realtime.dispatch_lifetime.closed
        assert websocket_manager.dispatch_lifetime.closed
        events.append("queue-drained")

    async def backup_cleanup():
        events.append("backup-drained-and-closed")

    async def restore_cleanup():
        events.append("restore-drained-and-closed")

    async def smtp_cleanup():
        events.append("smtp-workers-drained")

    monkeypatch.setattr(application, "queue_processor", MagicMock(stop=queue_stop))
    scheduler = MagicMock(running=True)
    scheduler.shutdown.side_effect = lambda **_: events.append("scheduler-stopped")
    monkeypatch.setattr(application, "scheduler", scheduler)
    monkeypatch.setattr(module.backup_executor, "cleanup", backup_cleanup)
    monkeypatch.setattr(restore_executor, "cleanup", restore_cleanup)
    monkeypatch.setattr(notification_service, "cleanup", smtp_cleanup)
    await application.shutdown_event()
    assert events == [
        "queue-drained",
        "scheduler-stopped",
        "backup-drained-and-closed",
        "restore-drained-and-closed",
        "smtp-workers-drained",
    ]


@pytest.mark.asyncio
async def test_realtime_shutdown_failure_preserves_independent_owners(monkeypatch):
    import app as application
    from core.realtime import realtime
    from core.websocket import websocket_manager
    from core.restore_executor import restore_executor
    from core.notifications import notification_service

    socket = MagicMock()
    socket.accept = AsyncMock()
    socket.send_json = AsyncMock()
    socket.close = AsyncMock(side_effect=RuntimeError("peer close failed"))
    await websocket_manager.connect(
        socket, "user", {"org_id": "00000000-0000-0000-0000-000000000001"}
    )
    entered, settled = asyncio.Event(), asyncio.Event()

    async def listener(event):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            settled.set()

    realtime.add_listener(listener)
    monkeypatch.setattr(realtime, "_broadcast_websocket", AsyncMock())
    with TenantContext("00000000-0000-0000-0000-000000000001"):
        task = asyncio.create_task(realtime.emit_event("shutdown", {}))
    await asyncio.wait_for(entered.wait(), 1)
    monkeypatch.setattr(application, "queue_processor", None)
    monkeypatch.setattr(application, "scheduler", MagicMock(running=False))
    cleanups = [AsyncMock() for _ in range(3)]
    for owner, cleanup in zip(
        (module.backup_executor, restore_executor, notification_service), cleanups
    ):
        monkeypatch.setattr(owner, "cleanup", cleanup)
    with pytest.raises(RuntimeError, match="socket close remains unresolved"):
        await application.shutdown_event()
    assert settled.is_set() and task.cancelled()
    for cleanup in cleanups:
        cleanup.assert_awaited_once()
    assert socket in websocket_manager._closing
    with pytest.raises(RuntimeError, match="unresolved"):
        websocket_manager.start()
    socket.close.side_effect = None
    await application.shutdown_event()
    assert not websocket_manager._closing


@pytest.mark.asyncio
async def test_scheduler_thread_dispatch_uses_application_loop_and_actor(monkeypatch):
    work = SchedulerWork()
    work.start()
    loop = asyncio.get_running_loop()
    entered, stopped = asyncio.Event(), asyncio.Event()
    org = "00000000-0000-0000-0000-000000000001"
    actor = "00000000-0000-0000-0000-000000000002"

    async def execute(backup_id):
        assert backup_id == "backup"
        assert asyncio.get_running_loop() is loop
        assert identity()[:2] == (org, actor)
        try:
            entered.set()
            await asyncio.Future()
        finally:
            stopped.set()

    monkeypatch.setattr(module.backup_executor, "execute_backup_and_wait", execute)

    def callback():
        with work.callback(), TenantContext(org, actor):
            work.submit(_run_backup_async, "backup", True)

    await asyncio.to_thread(callback)
    await asyncio.wait_for(entered.wait(), 2)
    await work.drain()
    assert stopped.is_set() and not work.tasks and not work.pending
    await work.drain()
    work.start()
    assert not work.closed and work.loop is loop
    await work.drain()


@pytest.mark.asyncio
async def test_scheduler_close_fences_pending_registration_and_late_callbacks():
    work = SchedulerWork()
    work.start()
    body = AsyncMock()
    # call_soon is queued but has not run: closing must prevent task creation.
    work.submit(body)
    assert work.pending == 1
    work.close_admission()
    with pytest.raises(RuntimeError, match="admission is closed"):
        work.submit(body)
    with pytest.raises(RuntimeError, match="admission is closed"):
        with work.callback():
            pytest.fail("late callback admitted")
    await work.drain()
    body.assert_not_called()
    assert not work.tasks and not work.pending


@pytest.mark.asyncio
async def test_scheduler_drain_waits_admitted_thread_but_refuses_its_late_submit():
    import threading

    work = SchedulerWork()
    work.start()
    entered, release = threading.Event(), threading.Event()
    body = AsyncMock()

    def callback():
        with work.callback():
            entered.set()
            assert release.wait(3)
            with pytest.raises(RuntimeError, match="admission is closed"):
                work.submit(body)

    thread = asyncio.create_task(asyncio.to_thread(callback))
    assert await asyncio.to_thread(entered.wait, 2)
    work.close_admission()
    drain = asyncio.create_task(work.drain())
    await asyncio.sleep(0)
    assert not drain.done() and work.callbacks == 1
    release.set()
    await asyncio.wait_for(asyncio.gather(thread, drain), 3)
    body.assert_not_called()
    assert work.callbacks == 0


@pytest.mark.asyncio
async def test_scheduler_failure_retains_closed_restart_hold():
    work = SchedulerWork()
    work.start()
    done = asyncio.Event()

    async def failure():
        done.set()
        raise RuntimeError("dispatch uncertain")

    work.submit(failure)
    await asyncio.wait_for(done.wait(), 2)
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError, match="dispatch uncertain"):
        await work.drain()
    with pytest.raises(RuntimeError, match="reconciliation"):
        work.start()
    assert work.closed and not work.tasks


@pytest.mark.asyncio
async def test_scheduler_task_creation_failure_preserves_closed_hold(monkeypatch):
    work = SchedulerWork()
    work.start()
    body = AsyncMock()
    with monkeypatch.context() as patch:
        patch.setattr(
            asyncio,
            "create_task",
            MagicMock(side_effect=RuntimeError("task allocation failed")),
        )
        work.submit(body)
        await asyncio.sleep(0)
    assert work.closed and not work.pending and not work.tasks
    body.assert_not_awaited()
    with pytest.raises(RuntimeError, match="task allocation failed"):
        await work.drain()
    with pytest.raises(RuntimeError, match="reconciliation"):
        work.start()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method", ["execute_backup", "execute_upload", "stop_backup", "execute_restore"]
)
async def test_closed_executor_refuses_before_database_or_transport(
    monkeypatch, method
):
    from core import restore_executor

    owner_module = restore_executor if method == "execute_restore" else module
    owner = (
        owner_module.RestoreExecutor()
        if method == "execute_restore"
        else module.BackupExecutor()
    )
    database = MagicMock(side_effect=AssertionError("database reached"))
    monkeypatch.setattr(owner_module, "SessionLocal", database)
    owner.close_admission()
    with pytest.raises(RuntimeError, match="admission is closed"):
        await getattr(owner, method)("operation")
    database.assert_not_called()
    with pytest.raises(RuntimeError, match="shutdown remains unresolved"):
        owner.start()
    await owner.cleanup()


@pytest.mark.asyncio
async def test_executor_drains_active_dispatch_before_transport_close_and_restarts():
    from core.task_lifetime import owned_dispatch

    owner = module.BackupExecutor()
    entered = asyncio.Event()
    order = []
    owner.http_client = MagicMock(
        aclose=AsyncMock(side_effect=lambda: order.append("transport"))
    )

    @owned_dispatch
    async def dispatch(self):
        try:
            entered.set()
            await asyncio.Future()
        finally:
            order.append("dispatch-drained")

    task = asyncio.create_task(dispatch(owner))
    await entered.wait()
    old_client = owner.http_client
    await owner.cleanup()
    assert task.cancelled() and order == ["dispatch-drained", "transport"]
    assert not owner.dispatch_lifetime.tasks
    owner.start()
    assert owner.http_client is not old_client and not owner.dispatch_lifetime.closed
    await owner.cleanup()


@pytest.mark.asyncio
async def test_executor_foreign_loop_entry_refuses_before_database(monkeypatch):
    owner = module.BackupExecutor()
    with owner.dispatch_lifetime.admission():
        pass
    database = MagicMock(side_effect=AssertionError("foreign loop reached database"))
    monkeypatch.setattr(module, "SessionLocal", database)

    def foreign():
        with pytest.raises(RuntimeError, match="owning event loop"):
            asyncio.run(owner.execute_backup("backup"))

    await asyncio.to_thread(foreign)
    database.assert_not_called()
    await owner.cleanup()


@pytest.mark.asyncio
async def test_queue_stop_caller_cancellation_drains_child_then_propagates():
    from core.backup_queue_processor import BackupQueueProcessor

    processor = BackupQueueProcessor(MagicMock(), MagicMock())
    poller_entered, poller_stopping = asyncio.Event(), asyncio.Event()
    child_entered, child_closed = asyncio.Event(), asyncio.Event()

    async def poller_work():
        try:
            poller_entered.set()
            await asyncio.Future()
        finally:
            poller_stopping.set()
            await asyncio.Future()

    async def child_work():
        try:
            child_entered.set()
            await asyncio.Future()
        finally:
            child_closed.set()

    processor._task = asyncio.create_task(poller_work())
    child = asyncio.create_task(child_work())
    processor._children.add(child)
    await poller_entered.wait()
    await child_entered.wait()
    stop = asyncio.create_task(processor.stop())
    await poller_stopping.wait()
    stop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stop
    assert child_closed.is_set() and child.cancelled()
    assert not processor._children and processor._task is None
    await processor.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("queue_failure", [None, RuntimeError, asyncio.CancelledError])
async def test_shutdown_isolates_foreign_backup_and_drains_local_restore(
    monkeypatch, queue_failure
):
    import app as application
    from core import restore_executor as restore_module
    from core.notifications import notification_service

    backup = module.BackupExecutor()
    restore = restore_module.RestoreExecutor()
    backup.http_client = MagicMock(aclose=AsyncMock())
    restore.http_client = MagicMock(aclose=AsyncMock())
    foreign_loop = asyncio.new_event_loop()
    foreign = foreign_loop.create_future()
    backup.monitoring_tasks["foreign"] = foreign
    entered, closed = asyncio.Event(), asyncio.Event()

    async def local_monitor():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            closed.set()

    local = asyncio.create_task(local_monitor())
    restore.monitoring_tasks["local"] = local
    await entered.wait()
    failure = queue_failure("queue shutdown refused") if queue_failure else None
    queue = MagicMock(stop=AsyncMock(side_effect=failure))
    monkeypatch.setattr(application, "queue_processor", queue)
    monkeypatch.setattr(application, "scheduler", MagicMock(running=True))
    monkeypatch.setattr(module, "backup_executor", backup)
    monkeypatch.setattr(restore_module, "restore_executor", restore)
    try:
        for _ in range(2):
            with pytest.raises(BaseException) as raised:
                await application.shutdown_event()
            errors = getattr(raised.value, "exceptions", (raised.value,))
            assert any("owning event loop" in str(error) for error in errors)
            if failure:
                assert failure in errors
            assert closed.is_set() and local.cancelled()
            assert not restore.monitoring_tasks
            assert backup.monitoring_tasks == {"foreign": foreign}
            assert not foreign.cancelled()
            backup.http_client.aclose.assert_not_awaited()
            assert notification_service.dispatch_lifetime.closed
            assert notification_service._shutdown_complete
        assert restore.http_client.aclose.await_count == 2
        assert application.scheduler.shutdown.call_count == 2
    finally:
        foreign.cancel()
        foreign_loop.close()


def test_metrics_installs_and_restores_platform_scope(monkeypatch):
    from core import metrics

    before = identity()
    seen = []
    monkeypatch.setattr(
        metrics, "_collect_gauge_metrics", lambda: seen.append(identity())
    )
    metrics.collect_gauge_metrics()
    assert seen == [(None, None, True)]
    assert identity() == before


@pytest.mark.asyncio
async def test_manual_run_now_transfers_actor_into_actual_worker(monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from fastapi import BackgroundTasks
    from routers import schedules
    import scheduler as jobs

    org = "00000000-0000-0000-0000-000000000011"
    actor = "00000000-0000-0000-0000-000000000012"
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(
        name="manual"
    )
    seen = []

    @contextmanager
    def singleton(_):
        seen.append(identity())
        yield True

    monkeypatch.setattr("core.singleton.cluster_singleton", singleton)
    monkeypatch.setattr(
        jobs, "_execute_scheduled_backup_locked", lambda *args: seen.append(identity())
    )
    monkeypatch.setattr(schedules, "log_activity", MagicMock())
    tasks = BackgroundTasks()
    schedules.run_schedule_now(
        "schedule", tasks, db, SimpleNamespace(id=actor, org_id=org)
    )
    assert tasks.tasks[0].args == ("schedule", org, actor)
    before = identity()
    await tasks()
    assert seen == [(org, actor, False), (org, actor, False)]
    assert identity() == before


@pytest.mark.parametrize(
    "case",
    [
        "allowed",
        "missing_org",
        "disabled_org",
        "missing_actor",
        "disabled_actor",
        "revoked",
    ],
)
def test_manual_worker_admission_refuses_before_schedule_or_service(case):
    from types import SimpleNamespace
    import scheduler as jobs

    org = (
        SimpleNamespace(enabled=case != "disabled_org")
        if case != "missing_org"
        else None
    )
    actor = (
        SimpleNamespace(
            is_active=case != "disabled_actor",
            role="viewer" if case == "revoked" else "operator",
        )
        if case != "missing_actor"
        else None
    )
    db = MagicMock()
    query = (
        db.query.return_value.filter.return_value.populate_existing.return_value.with_for_update.return_value
    )
    query.first.side_effect = [org, actor]
    with TenantContext(
        "00000000-0000-0000-0000-000000000011", "00000000-0000-0000-0000-000000000012"
    ):
        if case == "allowed":
            jobs._admit_manual_schedule_actor(db)
        else:
            with pytest.raises(
                PermissionError, match="Manual schedule authority refused"
            ):
                jobs._admit_manual_schedule_actor(db)
    assert db.query.call_count == 2
    db.add.assert_not_called()
    db.commit.assert_not_called()
    if case != "allowed":
        query.first.side_effect = [org, actor]
        service = MagicMock()
        with TenantContext(
            "00000000-0000-0000-0000-000000000011",
            "00000000-0000-0000-0000-000000000012",
        ):
            jobs._execute_scheduled_backup_locked(
                "schedule", lambda: db, MagicMock(), MagicMock(), MagicMock(), service
            )
        service.assert_not_called()
        assert db.query.call_count == 4  # Only org/actor, never the schedule/VM.
        db.rollback.assert_called_once()
        db.close.assert_called_once()
        db.commit.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("commit_failure", [False, True])
async def test_queue_child_starts_only_after_durable_started_commit(
    monkeypatch, commit_failure
):
    from types import SimpleNamespace
    from core.backup_queue_processor import BackupQueueProcessor

    db = MagicMock()
    row = SimpleNamespace(
        id="queue",
        authority_kind="human",
        tags={},
        vm_id="vm",
        retention_days=1,
        backup_type="full",
        exclude_disks=[],
        workers=1,
        schedule_id=None,
        status="queued",
    )
    service = MagicMock()
    service.create_backup.return_value = SimpleNamespace(
        success=True, backup=SimpleNamespace(id="backup")
    )
    monkeypatch.setattr("core.backup_service.BackupService", lambda _: service)
    events = []
    commits = 0

    def commit():
        nonlocal commits
        commits += 1
        events.append(row.status)
        if commit_failure and commits == 2:
            raise RuntimeError("injected commit failure")

    db.commit.side_effect = commit
    executor = MagicMock()

    async def execute(_):
        assert events[:2] == ["processing", "started"]
        assert not commit_failure
        events.append("dispatch")

    executor.execute_backup_and_wait = execute
    processor = BackupQueueProcessor(MagicMock(), executor)
    await processor._start_backup_from_queue(db, row)
    await asyncio.gather(*tuple(processor._children))
    await asyncio.sleep(0)  # done callbacks remove completed children
    assert not processor._children
    assert ("dispatch" in events) is not commit_failure
    if commit_failure:
        db.rollback.assert_called_once()


@pytest.mark.asyncio
async def test_queue_poll_db_wait_does_not_block_api_loop():
    from core.backup_queue_processor import BackupQueueProcessor

    entered = threading.Event()
    release = threading.Event()
    seen_identities = []
    db = MagicMock()
    db.__enter__.return_value = db

    def blocked_first():
        seen_identities.append(identity())
        entered.set()
        release.wait(3)
        return None

    db.query.return_value.filter.return_value.order_by.return_value.first.side_effect = (
        blocked_first
    )
    processor = BackupQueueProcessor(lambda: db, MagicMock())
    safety_release = threading.Timer(2, release.set)
    safety_release.start()
    started = time.monotonic()
    with TenantContext("default"):
        task = asyncio.create_task(processor._process_tenant_queue(1, "queue"))
    try:
        if not await asyncio.to_thread(entered.wait, 1):
            release.set()
            await task
            pytest.fail("queue poll never reached the database read")
        assert time.monotonic() - started < 1.5
        assert not task.done()
    finally:
        release.set()
        safety_release.cancel()
    assert await task == 0
    assert seen_identities[0][0] == "default"


@pytest.mark.asyncio
async def test_scheduled_queue_inventory_wait_keeps_api_loop_live(monkeypatch):
    from core import scheduler_runtime
    from routers.public import health_check

    entered = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(
        scheduler_runtime, "_scheduler_work_ids", lambda _: ("default",)
    )

    def blocked_rows(_factory, _limit):
        assert identity()[0] == "default"
        entered.set()
        assert release.wait(2), "test did not release scheduled inventory"
        return ()

    monkeypatch.setattr(scheduler_runtime, "_queued_schedule_rows", blocked_rows)
    task = asyncio.create_task(
        scheduler_runtime.dispatch_queued_schedules(lambda: None, AsyncMock())
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
    assert await task == 0


@pytest.mark.asyncio
async def test_native_scheduler_claim_wait_keeps_api_loop_live(monkeypatch):
    from types import SimpleNamespace
    from core import native_dispatch
    from core.scheduler_scope import ScopeRefused
    from routers.public import health_check

    entered = threading.Event()
    release = threading.Event()

    def blocked_claim(*_args, **_kwargs):
        assert identity()[0] == "default"
        entered.set()
        assert release.wait(2), "test did not release native claim"
        return SimpleNamespace(state="not_claimed", claim_id=None, backup_id=None)

    monkeypatch.setattr(native_dispatch, "claim_queue", blocked_claim)
    dispatch = native_dispatch.ConnectedNativeDispatch(lambda: None, AsyncMock())
    with TenantContext("default"):
        task = asyncio.create_task(dispatch.dispatch(object(), "queue"))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert await asyncio.wait_for(health_check(), 0.2) == {
            "status": "ok",
            "service": "vesta-api",
        }
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(ScopeRefused, match="original_claim_unavailable"):
        await task
    await dispatch.close()
