"""Tests for the shallow /health (liveness) and deep /ready (readiness) endpoints.

/health must stay dependency-free (liveness); /ready gates on PostgreSQL so a DB
outage drains traffic instead of masking degradation behind 'Running 1/1'. The
probe query is bounded by a server-side statement_timeout so a degraded backing
store returns 503 fast rather than hanging (see okd/vnbui probe tuning).

NOTE: `routers.public` is imported lazily inside each test. Importing it at module
level runs public.py's module-level licensing/metrics init during pytest COLLECTION
— before test_auto_queue runs — which perturbs global state a fragile capacity test
there depends on (a pre-existing test-isolation quirk: the scheduler binds
core.settings_reader helpers by name, so an early import defeats a later
monkeypatch). Lazy import keeps the load at this file's normal run position.
"""

import asyncio
import json
from unittest.mock import MagicMock

from fastapi.responses import JSONResponse


def test_health_is_shallow_and_dependency_free():
    from routers.public import health_check

    # No DB argument — liveness must not touch dependencies.
    assert asyncio.run(health_check()) == {"status": "ok", "service": "vesta-api"}


def test_health_http_body_matches_the_operator_contract():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from jsonschema import Draft202012Validator

    from operator_protocol_contracts import apply_protocol_contracts
    from routers.public import router

    api = FastAPI()
    api.include_router(router)
    document = api.openapi()
    apply_protocol_contracts(document)
    schema = document["paths"]["/health"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    with TestClient(api) as client:
        response = client.get("/health")
    assert response.status_code == 200
    Draft202012Validator(schema).validate(response.json())


def test_community_flag_schemas_cover_the_actual_responses(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from jsonschema import Draft202012Validator

    from core.installed_profile import InstalledProfile
    from core.licensing import features
    from operator_protocol_contracts import apply_protocol_contracts
    from routers.public import router

    monkeypatch.setattr(features, "profile", InstalledProfile())
    api = FastAPI()
    api.include_router(router)
    document = api.openapi()
    apply_protocol_contracts(document)
    with TestClient(api) as client:
        for endpoint, field in (
            ("/api/v1/features", "flags"),
            ("/api/v1/license/info", "features"),
        ):
            response = client.get(endpoint)
            assert response.status_code == 200
            success = document["paths"][endpoint]["get"]["responses"]["200"]
            schema = success["content"]["application/json"]["schema"]["properties"][
                field
            ]
            assert schema["properties"] == {"client_encryption": {"type": "boolean"}}
            assert schema["required"] == ["client_encryption"]
            assert schema["additionalProperties"] == {"type": "boolean"}
            Draft202012Validator(schema).validate(response.json()[field])


def test_ready_ok_with_live_db(db_session):
    from routers.public import readiness_check

    result = readiness_check(db_session)
    assert result["status"] == "ready"
    assert result["checks"]["database"] == {"status": "ok", "required": True}


def test_ready_returns_503_when_db_down():
    from routers.public import readiness_check

    db = MagicMock()
    db.get_bind.return_value.dialect.name = "sqlite"  # skip the SET LOCAL branch
    db.execute.side_effect = RuntimeError("connection refused")

    result = readiness_check(db)
    assert isinstance(result, JSONResponse)
    assert result.status_code == 503
    body = json.loads(result.body)
    assert body["status"] == "not_ready"
    assert body["checks"]["database"]["status"] == "error"
    assert body["checks"]["database"]["required"] is True
    assert body["checks"]["database"]["code"] == "DATABASE_UNAVAILABLE"
    assert "connection refused" not in result.body.decode()


def test_ready_bounds_query_with_statement_timeout_on_postgres():
    from routers.public import readiness_check

    # On Postgres the probe must set a bounded statement_timeout before SELECT 1,
    # so a slow/degraded backing store returns 503 fast instead of hanging.
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"

    result = readiness_check(db)
    assert result["status"] == "ready"

    executed = [str(c.args[0]) for c in db.execute.call_args_list]
    assert any("statement_timeout" in stmt for stmt in executed)
    assert any("SELECT 1" in stmt for stmt in executed)


def test_readiness_installation_scope_is_bounded(monkeypatch):
    from routers.public import readiness_check
    from core.tenant_context import TenantContext, identity

    monkeypatch.setattr("core.tenant_context.commercial_mode", lambda: True)
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    seen = []
    db.execute.side_effect = lambda statement: seen.append(identity())
    org = "89054667-ea2e-4c31-8408-97b76bab3f75"
    with TenantContext(org):
        assert readiness_check(db)["status"] == "ready"
        assert identity() == (org, None, False)
        db.execute.side_effect = RuntimeError("private")
        assert readiness_check(db).status_code == 503
        assert identity() == (org, None, False)
    assert seen == [(None, None, True), (None, None, True)]
