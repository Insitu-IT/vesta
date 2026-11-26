"""Owned callback sessions, detached arguments and worker cancellation lifetime."""

import asyncio
from dataclasses import FrozenInstanceError
import threading
from types import SimpleNamespace

import pytest

from core.callback_identity import (
    CallbackIdentity,
    authenticate_callback,
    callback_worker,
)
from core.tenant_context import identity as current_identity


def test_descriptor_is_immutable_and_contains_no_orm():
    value = CallbackIdentity(
        "00000000-0000-4000-8000-000000000001", "agent", "api-key", "hash"
    )
    assert value.proof == ("api-key", "hash")
    assert all(type(v) is str for v in vars(value).values())
    with pytest.raises(FrozenInstanceError):
        value.agent_id = "replacement"


def test_authentication_finishes_both_owned_sessions(monkeypatch):
    from core import callback_identity as module

    events = []

    class DB:
        def __enter__(self):
            events.append(("enter", current_identity()))
            return self

        def __exit__(self, *exc):
            events.append(("close", current_identity()))

        def commit(self):
            events.append(("commit", current_identity()))

    agent = SimpleNamespace(org_id="00000000-0000-4000-8000-000000000001", id="agent")
    monkeypatch.setattr("database.SessionLocal", DB)
    monkeypatch.setattr("deps.REQUIRE_MTLS", False)

    def authenticate(key, fingerprint, db):
        assert fingerprint is None and key == "raw-key"
        return agent

    monkeypatch.setattr("deps._authenticate_agent", authenticate)
    monkeypatch.setattr(module, "validate_identity", lambda db, descriptor: agent)
    before = current_identity()
    descriptor = asyncio.run(authenticate_callback("raw-key"))
    assert (
        descriptor.org_id == "00000000-0000-4000-8000-000000000001"
        and descriptor.credential_kind == "api-key"
    )
    assert descriptor.credential_id != "raw-key"
    assert [e[0] for e in events] == ["enter", "close", "enter", "commit", "close"]
    assert events[0][1][2] is True
    assert events[2][1] == ("00000000-0000-4000-8000-000000000001", None, False)
    assert current_identity() == before


@pytest.mark.parametrize("failure", [False, True])
def test_worker_owns_session_and_context_through_exception(monkeypatch, failure):
    from core import callback_identity as module

    events = []
    main_thread = threading.get_ident()

    class DB:
        def __init__(self):
            self.thread = threading.get_ident()
            assert self.thread != main_thread

        def __enter__(self):
            events.append("open")
            return self

        def __exit__(self, *exc):
            assert threading.get_ident() == self.thread
            events.append("close")

        def commit(self):
            events.append("commit")

    monkeypatch.setattr("database.SessionLocal", DB)
    monkeypatch.setattr(module, "validate_identity", lambda *a: None)
    descriptor = CallbackIdentity(
        "00000000-0000-4000-8000-000000000001", "agent", "api-key", "hash"
    )

    def operation(db, backup, agent, body, proof):
        assert current_identity() == (
            "00000000-0000-4000-8000-000000000001",
            None,
            False,
        )
        assert proof == descriptor.proof
        events.append("operation")
        if failure:
            raise RuntimeError("worker failed")
        return "result"

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(callback_worker, descriptor, operation, "backup", {})
        if failure:
            with pytest.raises(RuntimeError, match="worker failed"):
                future.result()
        else:
            assert future.result() == "result"
        assert pool.submit(current_identity).result() == (None, None, False)
    assert events == ["open", "commit", "operation", "close"]


def test_cancelled_request_does_not_close_running_worker(monkeypatch):
    import anyio
    from starlette.concurrency import run_in_threadpool
    from core import callback_identity as module

    started, release, closed = threading.Event(), threading.Event(), threading.Event()

    class DB:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            closed.set()

        def commit(self):
            pass

    monkeypatch.setattr("database.SessionLocal", DB)
    monkeypatch.setattr(module, "validate_identity", lambda *a: None)

    def operation(*args):
        started.set()
        assert release.wait(5)
        assert not closed.is_set()

    async def scenario():
        async with anyio.create_task_group() as group:
            group.start_soon(
                run_in_threadpool,
                callback_worker,
                CallbackIdentity(
                    "00000000-0000-4000-8000-000000000001", "agent", "api-key", "hash"
                ),
                operation,
                "backup",
                {},
            )
            try:
                while not started.is_set():
                    await anyio.sleep(0.01)
                group.cancel_scope.cancel()
                assert not closed.is_set()
            finally:
                release.set()
        assert closed.is_set()

    anyio.run(scenario)


def test_auth_exception_restores_context_and_closes_pool_owner(monkeypatch):
    from core import callback_identity as module

    closed = []

    class DB:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            closed.append(current_identity())

    agent = SimpleNamespace(org_id="00000000-0000-4000-8000-000000000001", id="agent")
    monkeypatch.setattr("database.SessionLocal", DB)
    monkeypatch.setattr("deps.REQUIRE_MTLS", False)
    monkeypatch.setattr("deps._authenticate_agent", lambda *args: agent)

    def fail(*args):
        raise RuntimeError("credential changed")

    monkeypatch.setattr(module, "validate_identity", fail)
    before = current_identity()
    with pytest.raises(RuntimeError, match="credential changed"):
        asyncio.run(authenticate_callback("key"))
    assert current_identity() == before
    assert len(closed) == 2 and closed[0][2] is True
    assert closed[1] == (agent.org_id, None, False)
