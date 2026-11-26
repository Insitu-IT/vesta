"""Real route/registry lifetime with socket doubles, not persisted admission."""

import asyncio

import pytest
from starlette.websockets import WebSocketDisconnect

from core.websocket import WebSocketManager
from core.realtime import RealtimeManager
from routers import realtime

ORG = "d321cd87-74d5-4a1d-9a34-e2d8e0e6af80"
OTHER = "b0d78398-5c7d-477d-ace0-58b7fce87827"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["async", "wrapper", "object", "awaitable", "future", "task", "sync"]
)
async def test_listener_result_is_awaited_once_in_emitting_context(monkeypatch, kind):
    from core.tenant_context import TenantContext, resolved_organization

    manager = RealtimeManager()
    seen = []

    async def finish(event):
        await asyncio.sleep(0)
        seen.append((event.org_id, resolved_organization()))

    class Callable:
        async def __call__(self, event):
            await finish(event)

    class Awaitable:
        def __init__(self, event):
            self.event = event

        def __await__(self):
            return finish(self.event).__await__()

    calls = []

    def listener(event):
        calls.append(event)
        if kind == "object":
            return Callable()(event)
        if kind == "awaitable":
            return Awaitable(event)
        if kind == "future":
            result = asyncio.get_running_loop().create_future()

            def settle():
                seen.append((event.org_id, resolved_organization()))
                result.set_result(None)

            asyncio.get_running_loop().call_soon(settle)
            return result
        if kind == "task":
            return asyncio.create_task(finish(event))
        if kind == "sync":
            seen.append((event.org_id, resolved_organization()))
            return None
        return finish(event)

    async def async_listener(event):
        await listener(event)

    async def broadcast(event):
        assert not calls

    monkeypatch.setattr(manager, "_broadcast_websocket", broadcast)
    manager.add_listener(async_listener if kind == "async" else listener)
    with TenantContext(ORG):
        await manager.emit_event("test", {})
    assert len(calls) == 1
    assert seen == [(ORG, ORG)]
    assert list(manager.event_history) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["invoke", "await"])
async def test_listener_failure_is_redacted_and_next_listener_runs(caplog, phase):
    manager = RealtimeManager()
    seen = []

    async def fail():
        raise ValueError("PRIVATE_LISTENER_BODY")

    def listener(event):
        if phase == "invoke":
            raise ValueError("PRIVATE_LISTENER_BODY")
        return fail()

    manager.add_listener(listener)
    manager.add_listener(seen.append)
    await manager._notify_listeners("event")
    assert seen == ["event"]
    assert "Realtime listener failed" in caplog.text
    assert "PRIVATE_LISTENER_BODY" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["coroutine", "future"])
async def test_listener_cancellation_propagates_without_replay(kind):
    manager = RealtimeManager()
    entered = asyncio.Event()
    settled = []
    calls = []
    future = asyncio.get_running_loop().create_future()

    async def block():
        try:
            entered.set()
            await future
        finally:
            settled.append(True)

    def listener(event):
        calls.append(event)
        if kind == "future":
            entered.set()
            return future
        return block()

    manager.add_listener(listener)
    manager.add_listener(
        lambda event: pytest.fail("delivery continued after cancellation")
    )
    task = asyncio.create_task(manager._notify_listeners("event"))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert calls == ["event"]
    assert future.cancelled()
    assert settled == ([True] if kind == "coroutine" else [])


@pytest.mark.asyncio
async def test_listener_registry_changes_apply_to_next_snapshot():
    manager = RealtimeManager()
    seen = []

    def second(event):
        seen.append("second")

    def added(event):
        seen.append("added")

    async def first(event):
        manager.remove_listener(first)
        manager.remove_listener(second)
        manager.add_listener(added)
        await asyncio.sleep(0)
        seen.append("first")

    manager.add_listener(first)
    manager.add_listener(second)
    await manager._notify_listeners(None)
    assert seen == ["first", "second"]
    await manager._notify_listeners(None)
    assert seen == ["first", "second", "added"]


@pytest.mark.asyncio
async def test_foreign_listener_future_remains_with_owner(caplog):
    owner = asyncio.new_event_loop()
    foreign = owner.create_future()
    manager = RealtimeManager()
    seen = []
    manager.add_listener(lambda event: foreign)
    manager.add_listener(seen.append)
    try:
        await manager._notify_listeners("event")
        assert seen == ["event"]
        assert not foreign.done()
        assert foreign.get_loop() is owner
        assert "Realtime listener failed" in caplog.text
        foreign.set_result("owner settled")
        assert foreign.result() == "owner settled"
    finally:
        owner.close()


class Socket:
    def __init__(self):
        self.messages = []
        self.receiving = asyncio.Event()
        self.confirmation = asyncio.Event()
        self.block_confirmation = False
        self.failure = None
        self.closes = []

    async def close(self, **kwargs):
        self.closes.append(kwargs)

    async def accept(self):
        pass

    async def send_json(self, message):
        self.confirmation.set()
        if self.failure:
            raise self.failure
        if self.block_confirmation:
            await asyncio.Future()
        self.messages.append(message)

    async def receive_text(self):
        self.receiving.set()
        await asyncio.Future()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint", ["websocket_endpoint", "backup_progress_websocket"]
)
async def test_server_drain_owns_route_and_refuses_new_registration(
    monkeypatch, endpoint
):
    manager = WebSocketManager()
    manager.start()
    monkeypatch.setattr(realtime, "websocket_manager", manager)
    admissions = []

    async def admit(socket, backup_id=None):
        admissions.append(socket)
        return await manager.connect(socket, "user", {"org_id": ORG})

    monkeypatch.setattr(realtime, "connect_authenticated", admit)
    socket = Socket()
    handler = getattr(realtime, endpoint)
    args = (socket, "backup") if endpoint == "backup_progress_websocket" else (socket,)
    task = asyncio.create_task(handler(*args))
    await asyncio.wait_for(socket.receiving.wait(), 1)
    manager.close_admission()
    with pytest.raises(RuntimeError, match="closed"):
        await handler(*args)
    with pytest.raises(RuntimeError, match="closed"):
        await manager.send_scoped({}, ORG)
    assert admissions == [socket]
    await manager.cleanup()
    assert task.cancelled()
    assert socket.closes == [{"code": 1001, "reason": "Server shutdown"}]
    assert not manager.connection_meta and not manager.dispatch_lifetime.tasks
    await manager.cleanup()
    assert len(socket.closes) == 1
    manager.start()
    assert await manager.connect(Socket(), "new", {"org_id": ORG})
    await manager.cleanup()


@pytest.mark.asyncio
async def test_shutdown_during_accept_retains_exact_socket_custody():
    manager, socket = WebSocketManager(), Socket()
    entered = asyncio.Event()

    async def accept():
        entered.set()
        await asyncio.Future()

    socket.accept = accept
    task = asyncio.create_task(manager.connect(socket, "user", {"org_id": ORG}))
    await asyncio.wait_for(entered.wait(), 1)
    await manager.cleanup()
    assert task.cancelled()
    assert len(socket.closes) == 1
    assert not manager._closing and not manager.connection_meta


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["error", "cancel"])
async def test_failed_peer_close_does_not_starve_other_socket(failure):
    manager = WebSocketManager()
    broken, survivor = Socket(), Socket()
    for socket, org in ((broken, ORG), (survivor, OTHER)):
        await manager.connect(socket, "user", {"org_id": org})

    async def close(**kwargs):
        raise (
            asyncio.CancelledError() if failure == "cancel" else RuntimeError("private")
        )

    broken.close = close
    with pytest.raises(RuntimeError, match="unresolved"):
        await manager.cleanup()
    assert len(survivor.closes) == 1
    assert set(manager._closing) == {broken}
    with pytest.raises(RuntimeError, match="unresolved"):
        manager.start()
    broken.close = Socket.close.__get__(broken)
    await manager.cleanup()
    assert not manager._closing and not manager.connection_meta
    manager.start()


@pytest.mark.asyncio
async def test_socket_timeout_keeps_custody_closed_until_owner_settles():
    manager, socket = WebSocketManager(), Socket()
    manager.DRAIN_TIMEOUT = 0.01
    release = asyncio.Event()

    async def close(**kwargs):
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()

    socket.close = close
    await manager.connect(socket, "user", {"org_id": ORG})
    with pytest.raises(RuntimeError, match="unresolved"):
        await manager.cleanup()
    assert socket in manager._close_tasks
    with pytest.raises(RuntimeError, match="unresolved"):
        manager.start()
    release.set()
    await manager._close_tasks[socket]
    await manager.cleanup()
    assert not manager.connection_meta and not manager._closing


@pytest.mark.asyncio
async def test_foreign_socket_loop_refuses_without_touching_transport():
    manager, socket = WebSocketManager(), Socket()
    await manager.connect(socket, "user", {"org_id": ORG})
    before = list(socket.messages)

    async def foreign():
        for operation in (
            lambda: manager.connect(Socket(), "new", {"org_id": ORG}),
            lambda: manager.send_scoped({}, ORG),
            lambda: manager.disconnect(socket),
            manager.cleanup,
        ):
            with pytest.raises(RuntimeError, match="owning event loop"):
                await operation()

    await asyncio.to_thread(lambda: asyncio.run(foreign()))
    assert socket.messages == before and not socket.closes
    assert socket in manager.connection_meta
    await manager.cleanup()
    assert len(socket.closes) == 1


@pytest.mark.asyncio
async def test_foreign_event_loop_refuses_before_history_or_delivery(monkeypatch):
    from unittest.mock import AsyncMock

    manager = RealtimeManager()
    manager.start()
    broadcast = AsyncMock()
    monkeypatch.setattr(manager, "_broadcast_websocket", broadcast)

    async def foreign():
        with pytest.raises(RuntimeError, match="owning event loop"):
            await manager.emit_event("foreign", {})
        with pytest.raises(RuntimeError, match="owning event loop"):
            manager.get_events_since()
        with pytest.raises(RuntimeError, match="owning event loop"):
            await manager.cleanup()

    await asyncio.to_thread(lambda: asyncio.run(foreign()))
    broadcast.assert_not_called()
    assert not manager.event_history
    await manager.cleanup()


@pytest.mark.asyncio
async def test_realtime_cleanup_drains_listener_and_blocks_emit_and_poll(monkeypatch):
    from core.tenant_context import TenantContext

    manager = RealtimeManager()
    manager.start()
    entered, settled = asyncio.Event(), asyncio.Event()

    async def broadcast(event):
        pass

    async def listener(event):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            settled.set()

    monkeypatch.setattr(manager, "_broadcast_websocket", broadcast)
    manager.add_listener(listener)
    with TenantContext(ORG):
        task = asyncio.create_task(manager.emit_event("test", {}))
    await asyncio.wait_for(entered.wait(), 1)
    manager.close_admission()
    with pytest.raises(RuntimeError, match="closed"):
        await manager.emit_event("late", {})
    with pytest.raises(RuntimeError, match="closed"):
        manager.get_events_since()
    await manager.cleanup()
    assert task.cancelled() and settled.is_set()
    assert not manager.event_history and not manager.dispatch_lifetime.tasks
    manager.start()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["cancel", "error"])
async def test_confirmation_failure_retains_custody_until_cleanup(failure):
    manager = WebSocketManager()
    socket = Socket()
    socket.block_confirmation = failure == "cancel"
    socket.failure = RuntimeError("transport failed") if failure == "error" else None
    task = asyncio.create_task(manager.connect(socket, "user", {"org_id": ORG}))
    await asyncio.wait_for(socket.confirmation.wait(), 1)
    if failure == "cancel":
        assert manager.get_connection_count() == 1
        task.cancel()
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else RuntimeError):
        await asyncio.wait_for(task, 1)
    assert manager.active_connections == manager.connection_meta == {}
    assert socket in manager._closing
    with pytest.raises(RuntimeError, match="unresolved"):
        manager.start()
    socket.block_confirmation = False
    socket.failure = None
    with pytest.raises(RuntimeError, match="already owned"):
        await manager.connect(socket, "user", {"org_id": ORG})
    await manager.disconnect(socket)
    await manager.disconnect(socket)
    assert manager.get_connection_count() == manager.get_user_count() == 0
    assert socket in manager._closing
    await manager.cleanup()
    assert len(socket.closes) == 1
    await manager.disconnect(socket)
    await manager.cleanup()
    assert len(socket.closes) == 1
    manager.start()
    assert await manager.connect(Socket(), "user", {"org_id": ORG})
    await manager.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["error", "cancel"])
async def test_scoped_send_failure_retains_live_route_until_drain(monkeypatch, failure):
    manager = WebSocketManager()
    monkeypatch.setattr(realtime, "websocket_manager", manager)

    async def admit(socket, backup_id=None):
        return await manager.connect(socket, "user", {"org_id": ORG})

    monkeypatch.setattr(realtime, "connect_authenticated", admit)
    socket = Socket()
    route = asyncio.create_task(realtime.websocket_endpoint(socket))
    await asyncio.wait_for(socket.receiving.wait(), 1)
    before = list(socket.messages)
    socket.failure = asyncio.CancelledError() if failure == "cancel" else RuntimeError()
    if failure == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await manager.send_scoped({"type": "event"}, ORG)
    else:
        await manager.send_scoped({"type": "event"}, ORG)
    assert not route.done()
    assert socket not in manager.connection_meta and socket in manager._closing
    await manager.send_scoped({"type": "not-replayed"}, ORG)
    assert socket.messages == before
    await manager.cleanup()
    assert route.cancelled() and len(socket.closes) == 1
    await manager.cleanup()
    assert len(socket.closes) == 1
    manager.start()


@pytest.mark.asyncio
async def test_observed_peer_disconnect_retires_custody_without_double_close():
    from starlette.websockets import WebSocketState

    manager, socket = WebSocketManager(), Socket()
    await manager.connect(socket, "user", {"org_id": ORG})
    await manager.disconnect(socket)
    assert socket in manager._closing
    socket.client_state = WebSocketState.DISCONNECTED
    await manager.disconnect(socket)
    await manager.disconnect(socket)
    await manager.cleanup()
    assert not socket.closes and not manager._closing
    manager.start()


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["MAX_CONNECTIONS_PER_USER", "MAX_TOTAL_CONNECTIONS"])
async def test_failed_delivery_close_failure_blocks_restart_and_capacity(limit):
    manager, socket = WebSocketManager(), Socket()
    setattr(manager, limit, 1)
    socket.failure = RuntimeError()
    with pytest.raises(RuntimeError):
        await manager.connect(socket, "user", {"org_id": ORG})
    assert not await manager.connect(Socket(), "user", {"org_id": ORG})

    async def failed_close(**kwargs):
        raise RuntimeError("private")

    socket.close = failed_close
    with pytest.raises(RuntimeError, match="unresolved"):
        await manager.cleanup()
    with pytest.raises(RuntimeError, match="unresolved"):
        manager.start()
    assert socket in manager._closing
    socket.close = Socket.close.__get__(socket)
    await manager.cleanup()
    assert len(socket.closes) == 1
    manager.start()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint", ["websocket_endpoint", "backup_progress_websocket"]
)
@pytest.mark.parametrize("failure", ["cancel", "disconnect", "error"])
async def test_route_exit_releases_only_owned_socket(monkeypatch, endpoint, failure):
    manager = WebSocketManager()
    monkeypatch.setattr(realtime, "websocket_manager", manager)
    socket, survivor = Socket(), Socket()
    # Same user name is deliberately insufficient to remove another org/socket.
    await manager.connect(survivor, "user", {"org_id": OTHER})

    async def admit(ws, backup_id=None):
        return await manager.connect(
            ws, "user", {"org_id": ORG, "backup_id": backup_id}
        )

    monkeypatch.setattr(realtime, "connect_authenticated", admit)
    if failure != "cancel":

        async def refused_receive():
            raise (
                WebSocketDisconnect()
                if failure == "disconnect"
                else RuntimeError("transport failed")
            )

        socket.receive_text = refused_receive
    handler = getattr(realtime, endpoint)
    args = (socket, "backup") if endpoint == "backup_progress_websocket" else (socket,)
    task = asyncio.create_task(handler(*args))
    if failure == "cancel":
        await asyncio.wait_for(socket.receiving.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
    else:
        await asyncio.wait_for(task, 1)
    assert set(manager.connection_meta) == {survivor}
    assert manager.active_connections == {"user": {survivor}}
    before = len(socket.messages)
    await manager.send_scoped({"type": "after-exit"}, ORG)
    assert len(socket.messages) == before
    await manager.send_scoped({"type": "survivor"}, OTHER)
    assert survivor.messages[-1] == {"type": "survivor"}
    await manager.disconnect(survivor)
    assert manager.get_connection_count() == 0


@pytest.mark.asyncio
async def test_failed_socket_does_not_starve_next_scoped_recipient():
    manager = WebSocketManager()
    broken, healthy, foreign = Socket(), Socket(), Socket()
    for socket, org in ((broken, ORG), (healthy, ORG), (foreign, OTHER)):
        await manager.connect(socket, "user", {"org_id": org})
        socket.messages.clear()
    broken.failure = RuntimeError("transport failed")
    await manager.send_scoped({"type": "event"}, ORG)
    assert broken not in manager.connection_meta
    assert healthy.messages == [{"type": "event"}]
    assert foreign.messages == []
    for socket in (healthy, foreign):
        await manager.disconnect(socket)
    assert manager.active_connections == manager.connection_meta == {}
    assert set(manager._closing) == {broken, healthy, foreign}
    await manager.cleanup()
    assert all(len(socket.closes) == 1 for socket in (broken, healthy, foreign))
    manager.start()
