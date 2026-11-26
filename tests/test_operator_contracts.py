"""Synthetic HTTP/schema checks; no product database or remote requests."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
import httpx
from jsonschema import Draft202012Validator

WORK = Path(__file__).resolve().parents[1]
REPO = Path(os.environ.get("VESTA_CONTRACT_SOURCE_ROOT", str(WORK)))
sys.path.insert(0, str(WORK / "backend"))
sys.path.insert(1, str(REPO / "backend"))
from operator_contracts import (
    apply_contracts,
    install_operator_contracts,
    response_inventory,
    settings_patch_schema,
)

# Read actual settings definitions through AST so this contract fixture needs no
# application imports, database session or encryption credentials.
import ast

source = ast.parse((REPO / "backend/core/settings_service.py").read_text())
cls = next(
    node
    for node in source.body
    if isinstance(node, ast.ClassDef) and node.name == "SettingsService"
)
values = {
    node.target.id: ast.literal_eval(node.value)
    for node in cls.body
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
}
DEFINITIONS, SECRETS = values["DEFINITIONS"], values["SECRET_DEFINITIONS"]


def test_exact_settings_patch_keys_types_and_secret_policy():
    schema = settings_patch_schema(DEFINITIONS, SECRETS)
    validator = Draft202012Validator(schema)
    assert set(schema["properties"]) == set(DEFINITIONS) | set(SECRETS)
    assert not list(validator.iter_errors({}))
    for value in ("", "   ", "********", "••••", "new-value"):
        assert not list(validator.iter_errors({"oidc.client_secret": value}))
    for value in (
        {"general.timezone": "UTC"},
        {"storage.type": None},
        {"oidc.enabled": "true"},
        {"storage.s3.secret_key": None},
        {"oidc.default_role": "admin"},
        {
            "backup.capacity_admission": {
                "schema": 1,
                "revision": 1,
                "limit": 0,
                "maintenance": False,
            }
        },
    ):
        assert list(validator.iter_errors(value)), value
    assert not list(
        validator.iter_errors(
            {
                "backup.capacity_admission": {
                    "schema": 1,
                    "revision": 1,
                    "limit": 2,
                    "maintenance": False,
                }
            }
        )
    )
    assert "retain" in schema["properties"]["oidc.client_secret"]["description"]
    assert schema["properties"]["oidc.client_secret"]["writeOnly"]


def fixture_app(require_mtls=False):
    app = FastAPI()

    async def get_current_user():
        return "actor"

    async def get_installation_admin(actor=Depends(get_current_user)):
        raise HTTPException(403, "Installation authority required")

    async def guarded(request: Request, actor=Depends(get_installation_admin)):
        return await request.json()

    @app.put("/api/v1/settings/v3")
    async def settings(value=Depends(guarded)):
        return value

    async def verify_agent_api_key():
        return "agent"

    @app.post("/api/v1/agent-probe")
    async def agent_probe(agent=Depends(verify_agent_api_key)):
        return {}

    async def registration_database():
        return "registration"

    @app.post("/api/v1/agents/register")
    async def registration(db=Depends(registration_database)):
        return {}

    @app.get("/api/v1/backups")
    async def backups():
        return {}

    @app.post("/api/v1/encryption/keys/export")
    async def export():
        from fastapi.responses import Response

        return Response(
            b"\x00\xffkey",
            media_type="application/octet-stream",
            headers={"Content-Disposition": 'attachment; filename="keys.bin"'},
        )

    @app.get("/api/v1/report-executions/{execution_id}/download")
    async def download(execution_id: str):
        return None

    @app.get("/api/v1/unreviewed")
    async def unreviewed():
        return {}

    install_operator_contracts(app, DEFINITIONS, SECRETS, require_mtls=require_mtls)
    return app


def test_schema_publication_does_not_decode_unauthorized_sensitive_body():
    app = fixture_app()
    schema = app.openapi()
    assert schema is app.openapi()
    assert (
        schema["paths"]["/api/v1/settings/v3"]["put"]["requestBody"]["content"][
            "application/json"
        ]["schema"]["additionalProperties"]
        is False
    )

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            for body in (b"not-json", b'{"oidc.client_secret": "control-secret"}'):
                response = await client.put(
                    "/api/v1/settings/v3",
                    content=body,
                    headers={"Content-Type": "application/json"},
                )
                assert response.status_code == 403
                assert "control-secret" not in response.text
            response = await client.post("/api/v1/encryption/keys/export")
            assert response.content == b"\x00\xffkey"
            assert response.headers["content-type"] == "application/octet-stream"

    asyncio.run(exercise())
    binary = schema["paths"]["/api/v1/encryption/keys/export"]["post"]["responses"][
        "200"
    ]["content"]
    assert list(binary) == ["application/octet-stream"]
    assert binary["application/octet-stream"]["schema"]["format"] == "binary"
    report = schema["paths"]["/api/v1/report-executions/{execution_id}/download"][
        "get"
    ]["responses"]["200"]["content"]
    assert set(report) == {
        "application/pdf",
        "text/csv",
        "application/json",
        "text/html",
        "application/octet-stream",
    }
    assert all(value["schema"]["format"] == "binary" for value in report.values())


@pytest.mark.parametrize("require_mtls", [False, True])
def test_auth_domains_and_honest_untyped_inventory(require_mtls):
    schema = fixture_app(require_mtls).openapi()
    operation = schema["paths"]["/api/v1/agent-probe"]["post"]
    assert operation["x-credential-domain"] == "agent"
    assert operation["security"] == (
        [{"AgentMTLS": []}] if require_mtls else [{"AgentKey": []}, {"AgentMTLS": []}]
    )
    assert schema["paths"]["/api/v1/agents/register"]["post"]["security"] == [
        {"RegistrationKey": []}
    ]
    assert (
        schema["paths"]["/api/v1/settings/v3"]["put"]["x-authorization-dependency"]
        == "get_installation_admin"
    )
    inventory = response_inventory(schema)
    # Registration is now described; the deliberately unknown probe and route
    # remain unexplained. A zero here would mean the negative control vanished.
    assert inventory["untyped_count"] == 2
    assert any(
        row["method"] == "GET"
        and row["path"] == "/api/v1/unreviewed"
        and row["opaque_responses"] == ["200:application/json"]
        for row in inventory["untyped"]
    )
    assert (
        schema["paths"]["/api/v1/backups"]["get"]["x-list-contract"]["snapshot"]
        is False
    )


def test_activity_deep_page_and_deterministic_ties(monkeypatch):
    # Product module imports create engines but must not open any connection.
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args: (_ for _ in ()).throw(AssertionError("network forbidden")),
    )
    path = WORK / "backend/routers/activity.py"
    spec = importlib.util.spec_from_file_location("operator_activity_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from datetime import datetime, timedelta

    logs = [
        SimpleNamespace(
            id=f"user-{i:03}",
            created_at=datetime(2026, 1, 1) + timedelta(seconds=i),
            user=None,
            action="action",
            resource_type=None,
            resource_id=None,
            details={},
        )
        for i in range(75)
    ]
    events = [
        SimpleNamespace(
            id=f"system-{i:03}",
            created_at=datetime(2026, 1, 1) + timedelta(seconds=i),
            source="scheduler",
            source_id=None,
            event_type="event",
            attribution="tenant",
            org_id="org",
            resource_type=None,
            resource_id=None,
            details={},
        )
        for i in range(75)
    ]

    class Query:
        def __init__(self, rows):
            self.rows, self.bound = rows, None

        def filter(self, *args):
            return self

        def count(self):
            return len(self.rows)

        def order_by(self, *args):
            return self

        def limit(self, bound):
            self.bound = bound
            return self

        def all(self):
            return sorted(self.rows, key=lambda x: (x.created_at, x.id), reverse=True)[
                : self.bound
            ]

    db = SimpleNamespace(
        query=lambda model: Query(logs if model is module.ActivityLog else events)
    )
    result = asyncio.run(
        module.get_activity(skip=110, limit=10, db=db, current_user=None)
    )
    assert result["total"] == 150 and result["has_more"] is True
    assert len(result["activities"]) == 10
    assert [item["id"] for item in result["activities"][:2]] == [
        "user-019",
        "system-019",
    ]
    result = asyncio.run(
        module.get_activity(skip=145, limit=10, db=db, current_user=None)
    )
    assert len(result["activities"]) == 5 and result["has_more"] is False
    alias = asyncio.run(
        module.get_unified_activity_deprecated(
            skip=110, limit=10, db=db, current_user=None
        )
    )
    assert len(alias["activities"]) == 10


def test_real_settings_route_keeps_authorization_before_decode(monkeypatch):
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args: (_ for _ in ()).throw(AssertionError("network forbidden")),
    )
    from routers import config
    from deps import get_installation_admin

    app = FastAPI()
    app.include_router(config.router)

    async def denied():
        raise HTTPException(403, "Installation authority required")

    app.dependency_overrides[get_installation_admin] = denied
    install_operator_contracts(app, DEFINITIONS, SECRETS)
    schema = app.openapi()
    assert schema["paths"]["/api/v1/settings/v3"]["put"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["properties"]["oidc.client_secret"]["writeOnly"]

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.put(
                "/api/v1/settings/v3",
                content=b"{invalid-sensitive-json",
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 403

    asyncio.run(exercise())


def test_real_secret_validation_matches_declared_retention(monkeypatch):
    from core.settings_service import SettingsService

    service = SettingsService(None)
    monkeypatch.setattr(service, "get", lambda key: DEFINITIONS[key]["default"])
    for value in ("", "   ", "*****", "••••"):
        assert service.validate_update({"storage.s3.secret_key": value}) == {}
    for value in (None, True, 2, []):
        with pytest.raises((ValueError, TypeError)):
            service.validate_update({"storage.s3.secret_key": value})
    with pytest.raises(ValueError):
        service.validate_update({"general.timezone": "UTC"})


def test_credential_list_schemas_match_real_metadata_responses():
    from datetime import datetime
    from unittest.mock import MagicMock
    from models import AgentRegistrationKey, OrchestratorAPIKey, User
    from routers import api_keys

    app = FastAPI()
    app.include_router(api_keys.router)
    install_operator_contracts(app, DEFINITIONS, SECRETS)
    schema = app.openapi()
    actor = User(id="actor", username="admin")
    for model, handler, path, extras in (
        (
            OrchestratorAPIKey,
            api_keys.list_orchestrator_keys,
            "/api/v1/orchestrator-keys",
            {},
        ),
        (
            AgentRegistrationKey,
            api_keys.list_registration_keys,
            "/api/v1/registration-keys",
            {"agent_hostname": None, "max_uses": None, "use_count": 0},
        ),
    ):
        row = model(
            id="credential",
            name="metadata",
            key_prefix="prefix",
            key_hash="hash-never-exposed",
            expires_at=None,
            enabled=True,
            last_used_at=None,
            created_at=datetime(2026, 1, 1),
            created_by=actor.id,
            user=actor,
            **extras,
        )
        db = MagicMock()
        db.query.return_value.order_by.return_value.all.return_value = [row]
        response = asyncio.run(handler(db=db, admin_user=actor))
        wire = schema["paths"][path]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        Draft202012Validator(wire).validate(response)
        assert "hash-never-exposed" not in json.dumps(response)
        assert "api_key" not in response["items"][0]


def test_browser_and_demo_protocols_are_not_described_as_bearer():
    from fastapi import Cookie

    app = FastAPI()

    @app.get("/api/v1/auth/oidc/callback")
    async def oidc():
        return {}

    @app.post("/api/v1/demo/sessions")
    async def create_session():
        return {}

    @app.get("/api/v1/demo/state")
    async def state(token: str | None = Cookie(None, alias="vnbui_demo_session")):
        return {}

    install_operator_contracts(app, DEFINITIONS, SECRETS)
    schema = app.openapi()
    assert schema["paths"]["/api/v1/auth/oidc/callback"]["get"]["security"] == [
        {"OIDCState": [], "OIDCPKCE": []}
    ]
    assert schema["paths"]["/api/v1/demo/sessions"]["post"]["security"] == []
    assert schema["paths"]["/api/v1/demo/state"]["get"]["security"] == [
        {"DemoSession": []}
    ]


@pytest.mark.parametrize("require_mtls", [False, True])
def test_nested_included_router_auth_uses_effective_context_and_source_path(
    require_mtls,
):
    from fastapi import APIRouter

    app = FastAPI()

    async def verify_agent_api_key():
        return "agent"

    async def candidate_credential():
        return "candidate"

    inner = APIRouter()

    @inner.get("/agent")
    async def agent():
        return {}

    outer = APIRouter(dependencies=[Depends(verify_agent_api_key)])
    outer.include_router(inner, prefix="/nested")
    app.include_router(outer, prefix="/gateway")
    protocol = APIRouter()

    @protocol.post("/api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate")
    async def activate(actor=Depends(candidate_credential)):
        return {}

    @protocol.get("/api/v1/demo/state")
    async def demo():
        return {}

    @protocol.get("/api/v1/auth/oidc/callback")
    async def oidc():
        return {}

    app.include_router(protocol, prefix="/gateway")
    install_operator_contracts(app, DEFINITIONS, SECRETS, require_mtls=require_mtls)
    schema = app.openapi()
    operation = schema["paths"]["/gateway/nested/agent"]["get"]
    assert operation["security"] == (
        [{"AgentMTLS": []}] if require_mtls else [{"AgentKey": []}, {"AgentMTLS": []}]
    )
    assert operation["x-credential-domain"] == "agent"
    activation = schema["paths"][
        "/gateway/api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate"
    ]["post"]
    assert activation["security"] == [
        {"AgentCandidate": [], **({"AgentMTLS": []} if require_mtls else {})}
    ]
    assert schema["paths"]["/gateway/api/v1/demo/state"]["get"]["security"] == [
        {"DemoSession": []}
    ]
    assert schema["paths"]["/gateway/api/v1/auth/oidc/callback"]["get"]["security"] == [
        {"OIDCState": [], "OIDCPKCE": []}
    ]


def test_offline_export_refuses_missing_http_credential_domain():
    path = WORK / "ci/export_operator_contract.py"
    spec = importlib.util.spec_from_file_location("operator_export_auth_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    document = {"paths": {"/agent": {"post": {"responses": {}}}}}
    with pytest.raises(ValueError, match="POST /agent"):
        module.validate_auth_descriptions(document)
    document["paths"]["/agent"]["post"]["x-credential-domain"] = "agent"
    module.validate_auth_descriptions(document)
