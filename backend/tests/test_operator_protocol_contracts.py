"""Behavioral contracts: validate real handler/provider results against documentation.

Uses the backend test fixtures. No network, cluster, build, or persistent
database is required.
"""

import asyncio
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from ci.openapi_validation import contract_format_checker
from fastapi.encoders import jsonable_encoder
from jsonschema import Draft202012Validator
from operator_protocol_contracts import apply_protocol_contracts


@pytest.fixture
def document():
    # The first Community contract provides the supported baseline for these readers.
    import operator_contracts

    root = Path(operator_contracts.__file__).resolve().parents[1]
    original = json.loads(
        (
            root / "docs/contracts/operator/6.1.0/profiles/community/openapi.json"
        ).read_text()
    )
    return apply_protocol_contracts(original)


def validate(document, path, method, result, status="200"):
    schema = document["paths"][path][method]["responses"][status]["content"][
        "application/json"
    ]["schema"]
    Draft202012Validator(
        {**schema, "components": document["components"]},
        format_checker=contract_format_checker(),
    ).validate(jsonable_encoder(result))


def test_minimal_document_preserves_denominator():
    document = {
        "paths": {
            "/unowned": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "string"}}
                            }
                        }
                    }
                }
            }
        }
    }
    before = deepcopy(document["paths"])
    apply_protocol_contracts(document)
    assert document["paths"] == before


def test_public_live_helpers(document):
    from routers import public

    for path, handler in (
        ("/health", public.health_check),
        ("/api/v1/version", public.get_version),
        ("/api/v1/features", public.get_features),
        ("/api/v1/license/info", public.get_license_info),
    ):
        validate(document, path, "get", asyncio.run(handler()))


def test_readiness_success_and_error_have_distinct_shapes(document):
    from routers.public import readiness_check

    class ProbeDB:
        def __init__(self, broken=False):
            self.broken = broken

        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        def execute(self, statement):
            if self.broken:
                raise RuntimeError("probe failed")

    validate(document, "/ready", "get", readiness_check(ProbeDB()))
    unavailable = readiness_check(ProbeDB(True))
    assert unavailable.status_code == 503
    validate(document, "/ready", "get", json.loads(unavailable.body), "503")


def test_metrics_is_text_and_disabled_is_404(document, monkeypatch):
    from fastapi import HTTPException
    from routers.public import prometheus_metrics

    monkeypatch.setenv("METRICS_ENABLED", "true")
    result = asyncio.run(prometheus_metrics())
    assert result.headers["content-type"].startswith("text/plain")
    assert isinstance(result.body, bytes)
    assert (
        "application/json"
        not in document["paths"]["/metrics"]["get"]["responses"]["200"]["content"]
    )
    monkeypatch.setenv("METRICS_ENABLED", "false")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(prometheus_metrics())
    assert exc.value.status_code == 404


def test_agent_details_and_vm_identity_optional_values(document, db_session):
    from backend.tests.conftest import make_agent, make_vm
    from routers.agents import get_agent_details, get_vm

    agent = make_agent(db_session, version=None, platform=None)
    vm = make_vm(db_session, agent, provider=None, last_observed_at=None)
    detail = asyncio.run(get_agent_details(agent.id, db_session, SimpleNamespace()))
    validate(document, "/api/v1/agents/{agent_id}", "get", detail)
    assert detail["api_key"] is None
    validate(
        document,
        "/api/v1/vms/{vm_id}",
        "get",
        asyncio.run(get_vm(vm.id, db_session, SimpleNamespace())),
    )


def test_health_include_and_full_alias(document, db_session, monkeypatch):
    from backend.tests.conftest import make_agent
    from routers.health import get_health, get_detailed_health_deprecated

    agent = make_agent(db_session)
    user = SimpleNamespace(org_id=agent.org_id)
    monkeypatch.setattr("routers.health.SettingsService.get_s3_config", lambda _: None)
    partial = asyncio.run(get_health("metrics", user, db_session))
    assert set(partial) == {"status", "timestamp", "metrics"}
    validate(document, "/api/v1/health", "get", partial)
    # SQLite cannot execute PostgreSQL metadata query; the handler's unhealthy
    # database branch is a legitimate successful HTTP projection.
    full = asyncio.run(get_detailed_health_deprecated(user, db_session))
    validate(document, "/api/v1/health/detailed", "get", full)


def test_heartbeat_keeps_nullable_s3_field_without_credentials(document):
    from core.agent_requests import build_heartbeat_response

    value = build_heartbeat_response("agent", "2026-11-09T00:00:00", None)
    validate(document, "/api/v1/health/agents/{agent_id}/heartbeat", "post", value)
    assert value["config"] == {}
    assert value["s3_config"] is None


def test_diagnostics_observed_and_partial(document, db_session, monkeypatch):
    from backend.tests.conftest import make_agent
    from core import support_diagnostics

    agent = make_agent(db_session)
    report = support_diagnostics.collect(db_session, agent.org_id)
    validate(document, "/api/v1/health/diagnostics", "get", report)
    monkeypatch.setattr(
        support_diagnostics,
        "_agents",
        lambda _: (_ for _ in ()).throw(RuntimeError("private")),
    )
    report = support_diagnostics.collect(db_session, agent.org_id)
    assert report["status"] == "partial"
    validate(document, "/api/v1/health/diagnostics", "get", report)


def test_legacy_receipt_actual_provider_acceptance_and_replay(document, db_session):
    from backend.tests.test_storage_transaction import prepare, client_for
    from core.storage_transaction import accept_prepared_receipt

    backup, agent, claim, receipt = prepare(db_session)
    for _ in range(2):
        result = accept_prepared_receipt(
            db_session, backup.id, agent.id, receipt, client_for(receipt)
        )
        validate(
            document,
            "/api/v1/agents/backups/{backup_id}/prepared-receipt",
            "post",
            result,
        )
        assert result["accepted"] is True
        assert backup.status == "running"


def test_realtime_config_role_and_environment_branches(document, monkeypatch):
    from routers.realtime import get_realtime_config

    for role in ("admin", "viewer"):
        for disabled in ("true", "false"):
            monkeypatch.setenv("DISABLE_WEBSOCKET", disabled)
            result = asyncio.run(get_realtime_config(SimpleNamespace(role=role)))
            validate(document, "/api/v1/config/realtime", "get", result)
            assert result["enableWebSocket"] is (disabled == "false")
            assert result["pollingInterval"] == (10000 if role == "viewer" else 5000)


def test_oidc_callback_wrapper_html_refusals_clear_cookies(document):
    from fastapi import FastAPI, HTTPException
    from httpx import AsyncClient, ASGITransport
    from routers.auth import router, oidc_database

    app = FastAPI()
    app.include_router(router)

    async def no_database():
        return None

    app.dependency_overrides[oidc_database] = no_database

    async def exercise():
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            for query in ("?error=access_denied", ""):
                result = await client.get(
                    "/api/v1/auth/oidc/callback" + query, follow_redirects=False
                )
                assert result.status_code == 400
                assert result.headers["content-type"].startswith("text/html")
                assert len(result.headers.get_list("set-cookie")) == 2

            async def unavailable():
                raise HTTPException(503, "binding unavailable")

            app.dependency_overrides[oidc_database] = unavailable
            result = await client.get("/api/v1/auth/oidc/callback")
            assert result.status_code == 503
            assert result.headers["content-type"].startswith("text/html")
            assert len(result.headers.get_list("set-cookie")) == 2

    asyncio.run(exercise())
    responses = document["paths"]["/api/v1/auth/oidc/callback"]["get"]["responses"]
    assert "200" not in responses
    assert "422" not in responses
    assert set(responses["400"]["content"]) == {"text/html"}
