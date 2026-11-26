"""Persisted profile projection controls; database acceptance is separate."""

from datetime import datetime
from types import SimpleNamespace

import pytest

from core import tenant_context
from routers.auth import get_current_user_info


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,role_source",
    [("local", "local"), ("oidc", "local"), ("oidc", "oidc"), (None, None)],
)
@pytest.mark.parametrize(
    "commercial,role,platform,allowed",
    [
        (True, "admin", False, False),
        (True, "viewer", True, True),
        (False, "admin", False, True),
        (False, "viewer", True, False),
    ],
)
async def test_profile_is_explicit_persisted_allowlist(
    monkeypatch, source, role_source, commercial, role, platform, allowed
):
    from unittest.mock import MagicMock

    monkeypatch.setattr(tenant_context, "commercial_mode", lambda: commercial)
    session = MagicMock()
    session.return_value.__enter__.return_value.get.return_value = SimpleNamespace(
        org_id="organization"
    )
    monkeypatch.setattr("database.SessionLocal", session)
    user = SimpleNamespace(
        id="user",
        username="same",
        org_id="organization",
        role=role,
        is_platform_admin=platform,
        is_active=True,
        auth_source=source,
        role_source=role_source,
        full_name=None,
        email=None,
        oidc_issuer="https://issuer.invalid",
        oidc_subject="not-public",
        password_hash="never-public",
        raw_claims={"private": "never-public"},
        created_at=datetime(2026, 1, 1),
        last_login=None,
    )
    result = await get_current_user_info(user)
    assert set(result) == {
        "id",
        "username",
        "org_id",
        "role",
        "is_platform_admin",
        "can_manage_installation",
        "is_active",
        "auth_source",
        "role_source",
        "full_name",
        "email",
        "oidc_issuer",
        "created_at",
        "last_login",
    }
    assert result["can_manage_installation"] is allowed
    assert result["is_platform_admin"] is platform
    assert result["org_id"] == "organization"
    assert result["auth_source"] == source
    assert result["role_source"] == role_source
    assert result["email"] is None and result["full_name"] is None
    assert result["oidc_issuer"] == (user.oidc_issuer if source == "oidc" else None)
