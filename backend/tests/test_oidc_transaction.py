"""Callback transaction ownership; real persistence controls run in PostgreSQL CI."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.requests import Request

from routers import auth


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "jit", "audit", "token", "commit"])
async def test_callback_publishes_only_after_user_and_audit_commit(
    monkeypatch, failure
):
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/callback",
            "query_string": b"",
            "server": ("app.invalid", 443),
            "headers": [(b"cookie", b"oidc_state=fixture; oidc_pkce=verifier")],
        }
    )
    user = SimpleNamespace(id="user", org_id="org", username="same", role="viewer")
    service = SimpleNamespace(
        handle_callback=AsyncMock(return_value=({"sub": "subject"}, None)),
        get_or_create_user=AsyncMock(return_value=(user, True)),
    )
    request.state.oidc_service = service
    request.state.oidc_config = {"enabled": True}
    db = MagicMock()
    audit = MagicMock()
    token = MagicMock(return_value="synthetic-application-token")
    monkeypatch.setattr(auth, "log_activity", audit)
    monkeypatch.setattr(auth, "create_access_token", token)
    if failure:
        target = {
            "jit": service.get_or_create_user,
            "audit": audit,
            "token": token,
            "commit": db.commit,
        }[failure]
        target.side_effect = RuntimeError("private-provider-detail")
    response = await auth.oidc_callback(request, code="code", state="fixture", db=db)
    service.get_or_create_user.assert_awaited_once_with(
        {"sub": "subject"}, db, commit=False
    )
    if failure:
        assert response.status_code == 500
        assert "location" not in response.headers
        assert b"private-provider-detail" not in response.body
        db.rollback.assert_called_once()
        if failure != "commit":
            db.commit.assert_not_called()
    else:
        assert response.status_code == 302
        db.commit.assert_called_once()
        db.rollback.assert_not_called()
        audit.assert_called_once_with(
            db,
            user,
            action="oidc_login",
            resource_type="auth",
            resource_id="user",
            details={"new_user": True},
            commit=False,
        )
