"""Real ContextVars and scoped restoration; PostgreSQL RLS is a separate gate."""

import pytest
import asyncio
from fastapi import HTTPException
import jwt
from types import SimpleNamespace
from core import tenant_context as tc

ORG = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"


@pytest.mark.parametrize("outer", [tc.PlatformContext, tc.DemoContext])
def test_tenant_entry_removes_ambient_privilege_and_restores_on_error(
    outer, monkeypatch
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    with outer():
        before = (
            tc.current_org.get(),
            tc.current_user_id.get(),
            tc.is_superuser.get(),
            tc.is_demo.get(),
        )
        with pytest.raises(RuntimeError, match="interrupted"):
            with tc.TenantContext(ORG, USER):
                assert tc.identity() == (ORG, USER, False)
                assert tc.is_demo.get() is False
                assert tc.resolved_organization() == ORG
                raise RuntimeError("interrupted")
        assert (
            tc.current_org.get(),
            tc.current_user_id.get(),
            tc.is_superuser.get(),
            tc.is_demo.get(),
        ) == before


def test_tenant_role_cannot_request_platform_authority():
    with pytest.raises(ValueError, match="explicit PlatformContext"):
        tc.TenantContext(ORG, USER, superuser=True)


@pytest.mark.parametrize("org", [None, "default", "invalid"])
def test_commercial_missing_invalid_identity_refuses_cursor_io(org, monkeypatch):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)

    class NoIO:
        def execute(self, *args):
            pytest.fail("Rejected identity reached SQL")

    with tc.TenantContext(org):
        with pytest.raises((HTTPException, ValueError)):
            tc.install_cursor_context(NoIO())


@pytest.mark.parametrize(
    "context,expected",
    [
        (lambda: tc.TenantContext(ORG, USER), (ORG, USER, "false", "false")),
        (tc.PlatformContext, ("", "", "true", "false")),
        (tc.DemoContext, ("", "", "false", "true")),
    ],
)
def test_cursor_installs_exact_transaction_local_identity(
    context, expected, monkeypatch
):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    calls = []

    class Cursor:
        def execute(self, sql, parameters):
            calls.append((sql, parameters))

    with context():
        tc.install_cursor_context(Cursor())
    assert len(calls) == 1
    sql, parameters = calls[0]
    assert parameters == expected
    assert sql.count(", true)") == 4
    for setting in ("current_org", "user_id", "platform_admin", "demo"):
        assert f"app.{setting}" in sql


def test_platform_scope_cannot_produce_tenant_event_identity(monkeypatch):
    monkeypatch.setattr(tc, "commercial_mode", lambda: True)
    with tc.PlatformContext():
        with pytest.raises(RuntimeError, match="explicit organization"):
            tc.resolved_organization()


def test_oss_bearer_request_preserves_signed_human_identity(monkeypatch):
    """Manual backup writes need the actor even when OSS resolves org from DB."""
    monkeypatch.setattr(tc, "commercial_mode", lambda: False)
    from deps import JWT_ALGORITHM

    monkeypatch.setattr("deps.jwt_secret", lambda: "test-secret")
    token = jwt.encode(
        {"sub": "operator", "user_id": USER, "org_id": ORG},
        "test-secret",
        algorithm=JWT_ALGORITHM,
    )
    request = SimpleNamespace(headers={"Authorization": "Bearer " + token})
    observed = []

    async def next_app(_request):
        observed.append(tc.identity())
        return "ok"

    assert asyncio.run(tc.tenant_middleware(request, next_app)) == "ok"
    assert observed == [(None, USER, False)]
    assert tc.identity() == (None, None, False)
