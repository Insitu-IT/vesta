"""Pre-persistence admission and callback cookie custody, no provider or DB I/O."""

import time
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import jwt
from starlette.requests import Request

from core import oidc_state
from database import get_db
from deps import JWT_ALGORITHM, jwt_secret
from routers import auth


@pytest.mark.parametrize("limit", [0, -1, 129, True, 1.5, None])
def test_cleanup_rejects_unbounded_input_before_database(monkeypatch, limit):
    database = MagicMock(side_effect=AssertionError("No unbounded cleanup"))
    monkeypatch.setattr(oidc_state, "SessionLocal", database)
    with pytest.raises(ValueError, match="between 1 and 128"):
        oidc_state.reclaim_expired(limit=limit)
    database.assert_not_called()


def test_replay_migration_matches_metadata_fk_and_ordered_expiry_indexes(monkeypatch):
    import importlib.util
    from pathlib import Path
    from models import OIDCLoginState

    indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in OIDCLoginState.__table__.indexes
    }
    assert indexes == {
        "idx_oidc_login_states_org_id": ("org_id",),
        "ix_oidc_login_states_expiry_batch": ("org_id", "expires_at", "digest"),
    }
    path = Path(__file__).parents[1] / "alembic/versions/20260913_oidc_login_states.py"
    spec = importlib.util.spec_from_file_location("oidc_replay_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    operations = MagicMock()
    monkeypatch.setattr(migration, "op", operations)
    migration.upgrade()
    created = {
        call.args[0]: tuple(call.args[2])
        for call in operations.create_index.call_args_list
    }
    assert created == indexes


def test_retention_successor_preserves_helper_cutoff_and_repairs_early_indexes(
    monkeypatch,
):
    import importlib.util
    from pathlib import Path
    from datetime import timedelta

    path = (
        Path(__file__).parents[1] / "alembic/versions/20260913_oidc_state_retention.py"
    )
    spec = importlib.util.spec_from_file_location("oidc_retention_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    operations = MagicMock()
    monkeypatch.setattr(migration, "op", operations)
    migration.upgrade()
    statements = [call.args[0] for call in operations.execute.call_args_list]
    assert migration.down_revision == "oidc_login_states"
    assert "CREATE INDEX IF NOT EXISTS idx_oidc_login_states_org_id" in statements[0]
    assert (
        "CREATE INDEX IF NOT EXISTS ix_oidc_login_states_expiry_batch" in statements[1]
    )
    assert "CREATE OR REPLACE FUNCTION vnbui_oidc_state_transition()" in statements[2]
    assert "OLD.expires_at > now() - interval '24 hours'" in statements[2]
    assert oidc_state.EXPIRY_RETENTION == timedelta(hours=24)
    assert (
        "app.platform_admin" in statements[2]
    )  # Separate organization retirement authority.


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "cookie",
        "duplicate",
        "duplicate-cookie",
        "malformed",
        "mismatch",
        "expired",
        "missing-exp",
        "aud",
        "purpose",
        "org_id",
        "default",
        "issuer",
        "client_id",
        "nonce",
    ],
)
def test_untrusted_state_cannot_open_tenant_database(monkeypatch, bad):
    claims = {
        "aud": "vnbui-oidc-state",
        "purpose": "oidc-login",
        "org_id": str(uuid.uuid4()),
        "issuer": "https://issuer.invalid",
        "client_id": "client",
        "nonce": "random-test-nonce",
        "exp": int(time.time()) + 300,
    }
    if bad == "expired":
        claims["exp"] = 1
    elif bad == "missing-exp":
        del claims["exp"]
    elif bad == "default":
        claims["org_id"] = "default"
    elif bad in claims:
        claims[bad] = "" if bad not in ("aud", "purpose") else "wrong"
    state = jwt.encode(claims, jwt_secret(), algorithm=JWT_ALGORITHM)
    if bad == "malformed":
        state = "invalid"
    query = "state=" + state
    cookie = "oidc_state=" + state
    if bad == "missing":
        query = ""
    elif bad == "cookie":
        cookie = ""
    elif bad == "duplicate":
        query += "&" + query
    elif bad == "duplicate-cookie":
        cookie += "; " + cookie
    elif bad == "mismatch":
        cookie += "x"
    request = Request(
        {
            "type": "http",
            "query_string": query.encode(),
            "headers": [(b"cookie", cookie.encode())],
        }
    )
    database = MagicMock(
        side_effect=AssertionError("No database before signed identity")
    )
    monkeypatch.setattr(oidc_state, "SessionLocal", database)
    with pytest.raises(HTTPException) as exc:
        oidc_state.consume(request)
    assert exc.value.status_code == 400
    database.assert_not_called()


@pytest.mark.parametrize(
    "failure", [HTTPException(400, "private-detail"), RuntimeError("private-detail")]
)
def test_terminal_callback_dependency_failure_clears_both_cookies(monkeypatch, failure):
    application = FastAPI()
    application.include_router(auth.router)
    application.dependency_overrides[get_db] = lambda: MagicMock()
    consume = MagicMock(side_effect=failure)
    monkeypatch.setattr(oidc_state, "consume", consume)
    response = TestClient(application).get(
        "/api/v1/auth/oidc/callback?state=test&code=test"
    )
    assert response.status_code == (400 if isinstance(failure, HTTPException) else 500)
    assert "private-detail" not in response.text and "location" not in response.headers
    cookies = response.headers.get_list("set-cookie")
    for key in ("oidc_state", "oidc_pkce"):
        assert any(row.startswith(key + "=") and "Max-Age=0" in row for row in cookies)
