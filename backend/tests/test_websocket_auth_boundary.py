"""Manual WebSocket admission, using real JWT verification and connection manager.

The query double observes scope predicates; it is not PostgreSQL RLS evidence.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call

import pytest
import jwt

from core import tenant_context
from core.websocket import WebSocketManager
from deps import JWT_ALGORITHM, jwt_secret
from models import Backup, Organization
from routers import realtime

ORG = "d321cd87-74d5-4a1d-9a34-e2d8e0e6af80"
USER = "36e61768-334e-4470-a987-a94c4a3926a5"
OUTER = "b0d78398-5c7d-477d-ace0-58b7fce87827"


@pytest.fixture
def boundary(monkeypatch):
    monkeypatch.setattr(tenant_context, "commercial_mode", lambda: True)
    monkeypatch.setattr(realtime, "commercial_mode", lambda: True)
    db = MagicMock()
    db.__enter__.return_value = db
    query = db.query.return_value
    query.filter.return_value = query
    query.first.return_value = SimpleNamespace(
        id=USER, username="viewer", org_id=ORG, role="viewer", is_active=True
    )

    def lookup(model, key):
        if model is Organization:
            assert key == ORG
            return SimpleNamespace(id=ORG, enabled=True)
        assert model is Backup
        return SimpleNamespace(id=key)

    db.get.side_effect = lookup
    manager = WebSocketManager()
    monkeypatch.setattr(realtime, "SessionLocal", lambda: db)
    monkeypatch.setattr(realtime, "websocket_manager", manager)
    return db, query, manager


def token(**changes):
    claims = {
        "sub": "viewer",
        "user_id": USER,
        "org_id": ORG,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(changes)
    return jwt.encode(claims, jwt_secret(), algorithm=JWT_ALGORITHM)


def socket(value):
    return SimpleNamespace(
        query_params={},
        headers={"sec-websocket-protocol": "vnbui, bearer." + value},
        close=AsyncMock(),
        accept=AsyncMock(),
        send_json=AsyncMock(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["query", "duplicate"])
async def test_url_or_ambiguous_socket_credentials_refused(boundary, kind):
    db, _, _ = boundary
    ws = socket(token())
    if kind == "query":
        ws.query_params = {"token": token()}
    else:
        ws.headers["sec-websocket-protocol"] += ", bearer." + token()
    assert not await realtime.connect_authenticated(ws)
    ws.accept.assert_not_awaited()
    db.query.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_id", [None, "backup-in-scope"])
@pytest.mark.parametrize(
    "failure",
    ["missing", "invalid", "expired", "no-org", "no-user", "absent", "disabled"],
)
async def test_manual_admission_denies_invalid_identity(boundary, backup_id, failure):
    db, query, manager = boundary
    value = token()
    if failure == "missing":
        value = ""
    elif failure == "invalid":
        value = "untrusted-token"
    elif failure == "expired":
        value = token(exp=datetime.now(timezone.utc) - timedelta(minutes=5))
    elif failure == "no-org":
        value = token(org_id=None)
    elif failure == "no-user":
        value = token(user_id=None)
    elif failure == "absent":
        query.first.return_value = None
    elif failure == "disabled":
        query.first.return_value.is_active = False
    ws = socket(value)
    with tenant_context.TenantContext(OUTER):
        assert not await realtime.connect_authenticated(ws, backup_id)
        assert tenant_context.get_current_org() == OUTER
    ws.accept.assert_not_awaited()
    ws.close.assert_awaited_once_with(
        code=1008, reason="Invalid credentials or subscription"
    )
    assert manager.get_connection_count() == 0
    db.get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_id", [None, "backup-in-scope"])
@pytest.mark.parametrize("missing", [True, False], ids=["missing-org", "disabled-org"])
async def test_manual_admission_denies_unavailable_organization(
    boundary, backup_id, missing
):
    db, _, manager = boundary
    db.get.side_effect = lambda model, key: (
        None if missing else SimpleNamespace(id=ORG, enabled=False)
    )
    ws = socket(token())
    with tenant_context.TenantContext(OUTER):
        assert not await realtime.connect_authenticated(ws, backup_id)
        assert tenant_context.identity() == (OUTER, None, False)
    db.get.assert_called_once_with(Organization, ORG)
    ws.accept.assert_not_awaited()
    ws.close.assert_awaited_once_with(
        code=1008, reason="Invalid credentials or subscription"
    )
    assert manager.get_connection_count() == 0


@pytest.mark.asyncio
async def test_backup_subscription_miss_is_denied_without_revealing_existence(boundary):
    db, _, manager = boundary
    organization_lookup = db.get.side_effect
    db.get.side_effect = lambda model, key: (
        None if model is Backup else organization_lookup(model, key)
    )
    ws = socket(token())
    assert not await realtime.connect_authenticated(ws, "other-tenant-backup")
    ws.accept.assert_not_awaited()
    ws.close.assert_awaited_once_with(
        code=1008, reason="Invalid credentials or subscription"
    )
    assert manager.get_connection_count() == 0
    assert db.get.call_args_list == [
        call(Organization, ORG),
        call(Backup, "other-tenant-backup"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint", ["websocket_endpoint", "backup_progress_websocket"]
)
async def test_each_route_runs_manual_admission_before_message_loop(boundary, endpoint):
    ws = socket("invalid-token")
    ws.receive_text = AsyncMock(side_effect=AssertionError("Unauthenticated read"))
    handler = getattr(realtime, endpoint)
    if endpoint == "backup_progress_websocket":
        await handler(ws, "backup-in-scope")
    else:
        await handler(ws)
    ws.close.assert_awaited_once_with(
        code=1008, reason="Invalid credentials or subscription"
    )
    ws.accept.assert_not_awaited()
    ws.receive_text.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_id", [None, "backup-in-scope"])
async def test_manual_admission_uses_persisted_scoped_identity(boundary, backup_id):
    db, query, manager = boundary
    # MagicMock is hashable, as a real WebSocket must be for the manager's set.
    ws = MagicMock()
    ws.query_params = {}
    ws.headers = {
        "sec-websocket-protocol": "vnbui, bearer."
        + token(role="admin", is_platform_admin=True)
    }
    ws.accept = AsyncMock()
    ws.close = AsyncMock()
    ws.send_json = AsyncMock()
    observed = []

    def lookup():
        observed.append(tenant_context.identity())
        return SimpleNamespace(id=USER, org_id=ORG, role="viewer", is_active=True)

    query.first.side_effect = lookup
    with tenant_context.PlatformContext():
        assert await realtime.connect_authenticated(ws, backup_id)
        assert tenant_context.identity() == (None, None, True)
    assert observed == [(ORG, None, False)]
    predicates = [
        str(arg.compile(compile_kwargs={"literal_binds": True}))
        for call in query.filter.call_args_list
        for arg in call.args
    ]
    assert any(
        USER in predicate and "users.id" in predicate for predicate in predicates
    )
    assert any(
        ORG in predicate and "users.org_id" in predicate for predicate in predicates
    )
    assert manager.connection_meta[ws]["metadata"] == {
        "org_id": ORG,
        "role": "viewer",
        "backup_id": backup_id,
    }
    ws.accept.assert_awaited_once()
    ws.close.assert_not_awaited()
    expected = [call(Organization, ORG)]
    if backup_id is not None:
        expected.append(call(Backup, backup_id))
    assert db.get.call_args_list == expected
    await manager.disconnect(ws)
    assert manager.get_connection_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_id", [None, "backup-in-scope"])
@pytest.mark.parametrize("public", ["vnbui", "", "other", "VNBUI"])
async def test_authenticated_socket_selects_only_requested_public_protocol(
    boundary, backup_id, public
):
    _, _, manager = boundary
    ws = MagicMock()
    ws.query_params = {}
    ws.headers = {
        "sec-websocket-protocol": ", ".join(
            value for value in (public, "bearer." + token()) if value
        )
    }
    ws.accept, ws.close, ws.send_json = AsyncMock(), AsyncMock(), AsyncMock()
    assert await realtime.connect_authenticated(ws, backup_id)
    if public == "vnbui":
        ws.accept.assert_awaited_once_with(subprotocol="vnbui")
    else:
        # Existing bearer-only clients remain supported; never echo credentials
        # or select an unoffered/unknown public protocol.
        ws.accept.assert_awaited_once_with()
    await manager.disconnect(ws)


def test_real_asgi_handshake_selects_public_protocol_after_admission(boundary):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    app = FastAPI()
    app.include_router(realtime.router)
    with TestClient(app) as client:
        for endpoint in ("/ws", "/ws/backups/backup-in-scope"):
            with client.websocket_connect(
                endpoint, subprotocols=["vnbui", "bearer." + token()]
            ) as ws:
                assert ws.accepted_subprotocol == "vnbui"
                assert ws.receive_json()["type"] == "connection"
                if endpoint != "/ws":
                    assert ws.receive_json()["type"] == "connected"
                ws.send_text("ping")
                assert ws.receive_text() == "pong"
            with pytest.raises(WebSocketDisconnect) as failure:
                with client.websocket_connect(
                    endpoint, subprotocols=["vnbui", "bearer.invalid-token"]
                ):
                    pytest.fail("Invalid credentials passed the handshake")
            assert failure.value.code == 1008
