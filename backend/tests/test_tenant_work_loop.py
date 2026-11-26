"""Real HTTP transport control across organization fan-out boundaries."""

import asyncio
from builtins import ExceptionGroup

import httpx
import pytest

from core import tenant_work
from core.tenant_context import identity

FIRST = "00000000-0000-0000-0000-000000000001"
SECOND = "00000000-0000-0000-0000-000000000002"


def test_fanout_reuses_one_loop_and_http_connection(monkeypatch):
    monkeypatch.setattr(tenant_work, "organization_work_ids", lambda _: (FIRST, SECOND))
    loops, organizations, connections = [], [], []
    client = server = None

    async def serve(reader, writer):
        connections.append(writer)
        try:
            while True:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def work():
        nonlocal client, server
        loops.append(asyncio.get_running_loop())
        organizations.append(identity()[0])
        if client is None:
            server = await asyncio.start_server(serve, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            client = httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{port}", trust_env=False
            )
        try:
            response = await client.get("/")
            assert response.text == "ok"
        finally:
            if identity()[0] == SECOND:
                await client.aclose()
                server.close()
                await server.wait_closed()

    before = identity()
    tenant_work.run_organization_coroutines(None, work)
    assert identity() == before
    assert organizations == [FIRST, SECOND]
    assert loops[0] is loops[1]
    assert len(connections) == 1


def test_fanout_failure_restores_context(monkeypatch):
    monkeypatch.setattr(tenant_work, "organization_work_ids", lambda _: (FIRST,))
    before = identity()

    async def work():
        assert identity()[0] == FIRST
        raise RuntimeError("work failed")

    with pytest.raises(RuntimeError, match="work failed"):
        tenant_work.run_organization_coroutines(None, work)
    assert identity() == before


def test_failed_tenant_does_not_starve_next_tenant(monkeypatch):
    monkeypatch.setattr(tenant_work, "organization_work_ids", lambda _: (FIRST, SECOND))
    before, seen = identity(), []

    async def work():
        seen.append(identity()[0])
        if identity()[0] == FIRST:
            raise RuntimeError("first failed")

    with pytest.raises(RuntimeError, match="first failed"):
        tenant_work.run_organization_coroutines(None, work)
    assert seen == [FIRST, SECOND]
    assert identity() == before


def test_fanout_cancel_stops_and_restores_scope(monkeypatch):
    monkeypatch.setattr(tenant_work, "organization_work_ids", lambda _: (FIRST, SECOND))
    before, seen = identity(), []

    async def work():
        seen.append(identity()[0])
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        tenant_work.run_organization_coroutines(None, work)
    assert seen == [FIRST]
    assert identity() == before


def test_multiple_tenant_failures_are_retained(monkeypatch):
    monkeypatch.setattr(tenant_work, "organization_work_ids", lambda _: (FIRST, SECOND))
    before = identity()

    async def work():
        raise RuntimeError(identity()[0])

    with pytest.raises(ExceptionGroup) as caught:
        tenant_work.run_organization_coroutines(None, work)
    assert [str(error) for error in caught.value.exceptions] == [FIRST, SECOND]
    assert identity() == before
