"""HTTP boundary controls; PostgreSQL policy evidence lives in integration CI."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deps import get_current_user, get_installation_db
from database import get_db
from routers import auth, config
from core.oidc_service import OIDCService


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("VNBUI_COMMERCIAL", "true")
    monkeypatch.setattr("core.tenant_context.commercial_mode", lambda: True)
    app = FastAPI()
    app.include_router(auth.router)
    app.include_router(config.router)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_installation_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="test", role="admin", is_platform_admin=False
    )
    return TestClient(app)


@pytest.mark.parametrize(
    "body",
    [
        "{broken",
        "null",
        "[]",
        '"text"',
        '{"unknown":1}',
        '{"oidc.enabled":[]}',
        '{"oidc.client_secret":{}}',
        '{"is_platform_admin":true}',
    ],
)
def test_settings_body_consumer_rejects_before_write(client, monkeypatch, body):
    client.app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="platform", role="viewer", is_platform_admin=True
    )
    db = MagicMock()
    client.app.dependency_overrides[get_installation_db] = lambda: db
    response = client.put(
        "/api/v1/settings/v3",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    db.add.assert_not_called()
    db.flush.assert_not_called()
    db.commit.assert_not_called()


def test_tenant_admin_cannot_test_installation_oidc(client, monkeypatch):
    outbound = MagicMock()
    monkeypatch.setattr(httpx, "AsyncClient", outbound)
    response = client.post(
        "/api/v1/auth/oidc/test",
        json={"issuer": "https://issuer.test", "client_id": "vnbui"},
    )
    assert response.status_code == 403
    outbound.assert_not_called()


@pytest.mark.parametrize(
    "method,path", [("PUT", "/api/v1/settings/v3"), ("POST", "/api/v1/auth/oidc/test")]
)
@pytest.mark.parametrize(
    "body", ['{"unknown":"submitted-private","oidc.enabled":[]}', "{broken-private"]
)
def test_tenant_refusal_precedes_body_and_semantics(
    client, monkeypatch, method, path, body
):
    from starlette.requests import Request

    decode = AsyncMock(side_effect=AssertionError("Body must remain unread"))
    validate = MagicMock(side_effect=AssertionError("Semantic oracle reached"))
    outbound = MagicMock(side_effect=AssertionError("Provider reached"))
    audit = MagicMock()
    monkeypatch.setattr(Request, "json", decode)
    monkeypatch.setattr(config.SettingsService, "validate_update", validate)
    monkeypatch.setattr(httpx, "AsyncClient", outbound)
    monkeypatch.setattr(auth, "log_activity", audit)
    monkeypatch.setattr(config, "log_activity", audit)
    response = client.request(
        method, path, content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 403
    for call in (decode, validate, outbound, audit):
        call.assert_not_called()
    assert "private" not in response.text


def test_platform_authority_allows_audited_tls_discovery(client, monkeypatch):
    client.app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="platform", role="viewer", is_platform_admin=True
    )
    discovery = {
        "issuer": "https://issuer.test",
        "authorization_endpoint": "https://issuer.test/auth",
        "token_endpoint": "https://issuer.test/token",
    }
    transport = MagicMock()
    transport.__aenter__ = AsyncMock(return_value=transport)
    transport.__aexit__ = AsyncMock(return_value=None)
    transport.get = AsyncMock(
        return_value=SimpleNamespace(status_code=200, json=lambda: discovery)
    )
    factory = MagicMock(return_value=transport)
    audit = MagicMock()
    monkeypatch.setattr(httpx, "AsyncClient", factory)
    monkeypatch.setattr(auth, "log_activity", audit)
    response = client.post(
        "/api/v1/auth/oidc/test",
        json={
            "issuer": discovery["issuer"],
        },
    )
    assert response.status_code == 200
    assert response.json()["check"] == "discovery_only"
    assert response.json()["credentials_verified"] is False
    assert factory.call_args.kwargs == {"timeout": 10.0}
    audit.assert_called_once()
    assert audit.call_args.kwargs["details"] == {"operation": "discovery"}
    transport.get.assert_awaited_once_with(
        "https://issuer.test/.well-known/openid-configuration"
    )
    assert audit.call_args.kwargs["action"] == "oidc_configuration_test"
    audit.side_effect = RuntimeError("audit unavailable")
    transport.get.reset_mock()
    response = client.post(
        "/api/v1/auth/oidc/test",
        json={"issuer": discovery["issuer"], "client_id": "vnbui"},
    )
    assert response.status_code == 500
    transport.get.assert_not_called()


@pytest.mark.parametrize("failure", ["exception", "body", "plaintext", "issuer"])
def test_discovery_route_refuses_and_redacts_provider_failure(
    client, monkeypatch, caplog, failure
):
    client.app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="platform", role="viewer", is_platform_admin=True
    )
    marker = "private-provider-response"
    discovery = {
        "issuer": "https://issuer.test",
        "authorization_endpoint": "https://issuer.test/auth",
        "token_endpoint": "https://issuer.test/token",
    }
    if failure == "plaintext":
        discovery["token_endpoint"] = "http://issuer.test/token"
    if failure == "issuer":
        discovery["issuer"] = "https://other.test"
    transport = MagicMock()
    transport.__aenter__ = AsyncMock(return_value=transport)
    transport.__aexit__ = AsyncMock(return_value=None)
    transport.get = AsyncMock(
        return_value=SimpleNamespace(
            status_code=503 if failure == "body" else 200,
            text=marker,
            json=lambda: discovery,
        )
    )
    if failure == "exception":
        transport.get.side_effect = RuntimeError(marker)
    monkeypatch.setattr(httpx, "AsyncClient", MagicMock(return_value=transport))
    audit = MagicMock()
    monkeypatch.setattr(auth, "log_activity", audit)
    response = client.post(
        "/api/v1/auth/oidc/test", json={"issuer": "https://issuer.test"}
    )
    assert response.status_code == (500 if failure == "exception" else 400)
    assert marker not in response.text + caplog.text + repr(audit.call_args)
    assert "credentials_verified" not in response.json()


@pytest.mark.parametrize(
    "body",
    [
        [],
        "text",
        None,
        {"issuer": []},
        {"issuer": "https://issuer.test", "client_secret": "private"},
        {"issuer": "https://issuer.test", "client_id": 4},
        {"issuer": "https://issuer.test", "client_id": None},
    ],
)
def test_discovery_rejects_invalid_body_before_audit_or_io(client, monkeypatch, body):
    client.app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="platform", role="viewer", is_platform_admin=True
    )
    audit, outbound = MagicMock(), MagicMock()
    monkeypatch.setattr(auth, "log_activity", audit)
    monkeypatch.setattr(httpx, "AsyncClient", outbound)
    response = client.post("/api/v1/auth/oidc/test", json=body)
    assert response.status_code == 400
    audit.assert_not_called()
    outbound.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "http://issuer.test",
        "https://user:secret@issuer.test",
        "https://issuer.test?secret=1",
        "https://issuer.test#fragment",
        "",
    ],
)
def test_oidc_tls_and_url_credential_boundary(url):
    with pytest.raises(ValueError):
        OIDCService.validate_endpoint(url, issuer=True)


def test_https_token_endpoint_query_is_preserved():
    OIDCService.validate_endpoint("https://issuer.test/token?realm=existing")


def test_discovery_cannot_redirect_credentials_to_plaintext():
    with pytest.raises(ValueError):
        OIDCService.validate_discovery(
            {
                "issuer": "https://issuer.test",
                "authorization_endpoint": "https://issuer.test/auth",
                "token_endpoint": "http://issuer.test/token",
            },
            "https://issuer.test",
        )


@pytest.mark.asyncio
async def test_provider_error_html_and_logs_do_not_echo_external_content(caplog):
    marker = "<script>secret-provider-content</script>"
    response = await auth.oidc_callback(
        MagicMock(), error="denied", error_description=marker
    )
    assert response.status_code == 400
    assert marker not in response.body.decode()
    assert "secret-provider-content" not in caplog.text


@pytest.mark.asyncio
async def test_token_exchange_failure_does_not_echo_body_or_exception(
    monkeypatch, caplog
):
    service = OIDCService()
    service.configure(
        {"enabled": True, "issuer": "https://issuer.test", "client_id": "client"}
    )
    service.get_discovery_document = AsyncMock(
        return_value={"token_endpoint": "https://issuer.test/token"}
    )
    transport = MagicMock()
    transport.__aenter__ = AsyncMock(return_value=transport)
    transport.__aexit__ = AsyncMock(return_value=None)
    transport.post = AsyncMock(
        return_value=SimpleNamespace(
            status_code=400,
            text="secret-marker",
            json=lambda: {"error_description": "secret-marker"},
        )
    )
    monkeypatch.setattr(httpx, "AsyncClient", MagicMock(return_value=transport))
    result = await service.handle_callback(
        "code", "https://app.test/callback", "verifier"
    )
    assert result == (None, "OIDC token exchange rejected")
    transport.post.side_effect = RuntimeError("secret-marker")
    result = await service.handle_callback(
        "code", "https://app.test/callback", "verifier"
    )
    assert result == (None, "OIDC token exchange failed")
    assert "secret-marker" not in caplog.text
