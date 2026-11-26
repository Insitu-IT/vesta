"""Identity decision controls with query doubles, never persistence/RLS evidence."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import deps
from core import tenant_context as tc
from routers import auth

ORG = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"


def test_ambiguous_login_has_same_public_refusal():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.exc import MultipleResultsFound

    db = MagicMock()
    db.query.return_value.filter.return_value.one_or_none.side_effect = (
        MultipleResultsFound()
    )
    app = FastAPI()
    app.include_router(auth.router)
    app.dependency_overrides[auth.login_database] = lambda: db
    response = TestClient(app).post(
        "/api/v1/auth/login", data={"username": "same", "password": "fixture"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    db.commit.assert_not_called()


@pytest.mark.parametrize("context", [tc.PlatformContext, lambda: tc.TenantContext(ORG)])
def test_context_and_token_claims_do_not_grant_installation_authority(
    monkeypatch, context
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    user = SimpleNamespace(
        id=USER,
        org_id=ORG,
        username="same",
        role="admin",
        is_active=True,
        is_platform_admin=False,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = (
        user
    )
    db.get.return_value = SimpleNamespace(enabled=True)
    token = deps.create_access_token(
        {
            "sub": "same",
            "user_id": USER,
            "org_id": ORG,
            "role": "platform-admin",
            "is_platform_admin": True,
        }
    )
    with context():
        # The request tenant context is explicit; ambient platform flags do not
        # supply the persisted bit read by the installation dependency.
        marker = tc.current_org.set(ORG)
        try:
            persisted = deps.get_current_user(token, db)
            assert persisted is user
            with pytest.raises(HTTPException) as denied:
                deps.get_installation_admin(persisted)
            assert denied.value.status_code == 403
        finally:
            tc.current_org.reset(marker)


@pytest.mark.parametrize(
    "commercial,role,platform,allowed",
    [
        (True, "viewer", True, True),
        (True, "admin", False, False),
        (False, "admin", False, True),
        (False, "viewer", True, False),
    ],
)
def test_installation_authority_mode_split(
    monkeypatch, commercial, role, platform, allowed
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: commercial)
    user = SimpleNamespace(role=role, is_platform_admin=platform, org_id=ORG)
    session = MagicMock()
    session.return_value.__enter__.return_value.get.return_value = SimpleNamespace(
        org_id=ORG
    )
    monkeypatch.setattr("database.SessionLocal", session)
    if allowed:
        assert deps.get_installation_admin(user) is user
    else:
        with pytest.raises(HTTPException) as denied:
            deps.get_installation_admin(user)
        assert denied.value.status_code == 403


@pytest.mark.parametrize("assignment", [None, SimpleNamespace(org_id="other")])
def test_oss_installation_authority_requires_persisted_default(monkeypatch, assignment):
    monkeypatch.setattr(tc, "commercial_mode", lambda: False)
    session = MagicMock()
    session.return_value.__enter__.return_value.get.return_value = assignment
    monkeypatch.setattr("database.SessionLocal", session)
    user = SimpleNamespace(role="admin", is_platform_admin=True, org_id=ORG)
    with pytest.raises(HTTPException) as refused:
        deps.get_installation_admin(user)
    assert refused.value.status_code == 403


@pytest.mark.parametrize("organization", [None, SimpleNamespace(enabled=False)])
def test_bearer_lookup_refuses_unavailable_persisted_organization(
    monkeypatch, organization
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    db = MagicMock()
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = (
        SimpleNamespace(
            id=USER,
            org_id=ORG,
            is_active=True,
            is_platform_admin=True,
        )
    )
    db.get.return_value = organization
    token = deps.create_access_token({"sub": "same", "user_id": USER, "org_id": ORG})
    with tc.TenantContext(ORG), pytest.raises(HTTPException) as denied:
        deps.get_current_user(token, db)
    assert denied.value.status_code == 401


def test_oss_bearer_refuses_reassigned_username(monkeypatch):
    """A signed actor ID cannot be attributed to a newer same-name account."""
    monkeypatch.setattr(tc, "commercial_mode", lambda: False)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(
        id="33333333-3333-4333-8333-333333333333",
        username="same",
        org_id=ORG,
        is_active=True,
    )
    token = deps.create_access_token({"sub": "same", "user_id": USER, "org_id": ORG})
    with pytest.raises(HTTPException) as denied:
        deps.get_current_user(token, db)
    assert denied.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("selection", [None, "default", "same-visible-name", "invalid"])
async def test_login_namespace_refuses_missing_or_display_selection(
    monkeypatch, selection
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    db = MagicMock()
    with pytest.raises(HTTPException) as denied:
        await anext(auth.login_database(selection, db))
    assert denied.value.status_code == 401
    db.query.assert_not_called()


@pytest.mark.asyncio
async def test_oss_login_uses_default_context_and_refuses_selection(monkeypatch):
    monkeypatch.setattr(tc, "commercial_mode", lambda: False)
    db = MagicMock()
    dependency = auth.login_database(None, db)
    with tc.TenantContext(ORG):
        assert await anext(dependency) is db
        assert tc.current_org.get() is None
        await dependency.aclose()
        assert tc.current_org.get() == ORG
    with pytest.raises(HTTPException) as denied:
        await anext(auth.login_database(ORG, db))
    assert denied.value.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("organization", [None, SimpleNamespace(enabled=False)])
async def test_login_unavailable_organization_never_commits_or_issues_token(
    monkeypatch, organization
):
    db = MagicMock()
    db.query.return_value.filter.return_value.one_or_none.return_value = (
        SimpleNamespace(
            password_hash="unused",
            is_active=True,
            org_id=ORG,
        )
    )
    db.get.return_value = organization
    monkeypatch.setattr(auth, "verify_password", lambda *args: True)
    token = MagicMock()
    monkeypatch.setattr(auth, "create_access_token", token)
    with pytest.raises(HTTPException) as denied:
        await auth.login(SimpleNamespace(username="same", password="unused"), db)
    assert denied.value.status_code == 401
    db.commit.assert_not_called()
    token.assert_not_called()
