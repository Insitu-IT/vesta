"""Source/transport controls for the coordinated release; no live deployment claim."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from starlette.requests import Request

from core.agent_http import AgentHTTP
from routers.public import get_compatibility
from version import check_compatibility, __version__


@pytest.mark.parametrize(
    "frontend,agent,status",
    [
        (__version__, __version__, "aligned"),
        ("6.0.0", __version__, "degraded"),
        ("5.0.24", __version__, "incompatible"),
        (__version__, "5.0.48", "incompatible"),
        (None, __version__, "degraded"),
    ],
)
def test_six_compatibility_report(frontend, agent, status):
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [
        SimpleNamespace(hostname="scoped-agent", version=agent)
    ]
    headers = [] if frontend is None else [(b"x-frontend-version", frontend.encode())]
    result = asyncio.run(
        get_compatibility(
            Request({"type": "http", "headers": headers}),
            SimpleNamespace(org_id="persisted-org-double"),
            db,
        )
    )
    assert (
        __version__
        == Path(__file__)
        .resolve()
        .parents[2]
        .joinpath(".release-version")
        .read_text()
        .strip()
    )
    assert result["status"] == status
    assert result["degraded_mode"] == (status != "aligned")
    assert result["contract_version"] == 6
    assert result["scope"] == "organization-online-agents"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "agent",
    [
        "5.0.48",
        "6.0.0",
        None,
        "unknown",
        "",
        "6",
        "6.0",
        6,
        "06.0.0",
        "6.0.0-extra",
        "6.0.0.1",
    ],
)
def test_mutation_probes_selected_agent_before_dispatch(agent, method):
    seen = []

    def respond(request):
        seen.append((request.method, request.url.path))
        if request.method == "GET":
            assert "X-Orchestrator-Key" not in request.headers
        else:
            assert request.headers["X-Orchestrator-Key"] == "test-only"
        return httpx.Response(200, json={"version": agent})

    transport = AgentHTTP(transport=httpx.MockTransport(respond))
    call = transport.request(
        method,
        "https://agent.invalid/api/backups",
        json={"backup_id": "b"},
        headers={"X-Orchestrator-Key": "test-only"},
    )
    if agent == "6.0.0":
        assert asyncio.run(call).status_code == 200
        assert seen == [("GET", "/health"), (method, "/api/backups")]
    else:
        with pytest.raises(RuntimeError, match="major version mismatch"):
            asyncio.run(call)
        assert seen == [("GET", "/health")]


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_read_only_transport_does_not_require_version(method):
    seen = []

    def respond(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(200)

    transport = AgentHTTP(transport=httpx.MockTransport(respond))
    assert (
        asyncio.run(
            transport.request(method, "https://agent.invalid/api/backups")
        ).status_code
        == 200
    )
    assert seen == [(method, "/api/backups")]


@pytest.mark.parametrize(
    "agent,delete_status",
    [(agent, 200) for agent in [None, "6", "6.0", "invalid", "5.0.48", "6.0.0"]]
    + [("6.0.0", 403), ("6.0.0", 503)],
)
def test_cancellation_refusal_does_not_claim_cancelled(
    monkeypatch, agent, delete_status
):
    from core import backup_executor

    db = MagicMock()
    backup = SimpleNamespace(id="b", vm_id="v", status="running")
    db.query.return_value.filter.return_value.first.side_effect = [
        backup,
        SimpleNamespace(agent_id="a"),
        SimpleNamespace(id="a"),
    ]
    monkeypatch.setattr(backup_executor, "SessionLocal", lambda: db)
    seen = []

    def respond(request):
        seen.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(200, json={"version": agent})
        return httpx.Response(delete_status)

    executor = backup_executor.BackupExecutor()
    executor.http_client = AgentHTTP(transport=httpx.MockTransport(respond))
    monkeypatch.setattr(executor, "_get_agent_url", lambda _: "https://agent.invalid")
    monkeypatch.setattr(executor, "_get_agent_headers", lambda: {})
    if agent == "6.0.0":
        if delete_status == 200:
            asyncio.run(executor.stop_backup("b"))
            assert backup.status == "cancelled"
            db.commit.assert_called_once()
        else:
            with pytest.raises(httpx.HTTPStatusError) as error:
                asyncio.run(executor.stop_backup("b"))
            assert error.value.response.status_code == delete_status
            assert error.value.request.method == "DELETE"
            assert error.value.request.url.path == "/api/backups/b"
            assert backup.status == "running"
            db.commit.assert_not_called()
        assert seen == [("GET", "/health"), ("DELETE", "/api/backups/b")]
    else:
        with pytest.raises(RuntimeError):
            asyncio.run(executor.stop_backup("b"))
        assert backup.status == "running"
        db.commit.assert_not_called()
        assert seen == [("GET", "/health")]


def test_five_backend_skew_fixture(monkeypatch):
    # Pure old algorithm fixture, not an execution of a deployed 5.x backend.
    import version

    monkeypatch.setattr(version, "__version__", "5.0.60")
    assert check_compatibility("6.0.0")["status"] == "incompatible"


def test_nginx_metrics_not_served_or_proxied():
    root = Path(__file__).resolve().parents[2]
    config = (root / "frontend/nginx.conf").read_text()
    assert "location = /metrics { return 404; }" in config
    assert "location ^~ /metrics/ { return 404; }" in config
    assert "$http_x_forwarded_for" not in config
    assert "allow 10." not in config  # Address enforcement belongs to OPS topology.
