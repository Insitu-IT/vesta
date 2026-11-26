"""Sequential lifecycle and private-file controls; PostgreSQL races need PG tests."""

import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, JSON, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.getenv("VESTA_ROTATION_SOURCE_ROOT", str(ROOT)))
sys.path.insert(0, str(SOURCE / "backend"))
from core import agent_key_rotation as rotation
import deps
from models import (
    Agent,
    AgentAPIKey,
    AgentCertificate,
    AgentKeyRotation,
    Base,
    Organization,
    User,
    ActivityLog,
)


@pytest.fixture
def fixture(monkeypatch):
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    for table in Base.metadata.tables.values():
        for column in table.c:
            if isinstance(column.type, JSONB):
                column.type = JSON()
    # PostgreSQL has a partial unique pending index; mirror that predicate for
    # these sequential SQLite controls, without claiming PostgreSQL evidence.
    for index in AgentKeyRotation.__table__.indexes:
        if index.name == "ix_agent_key_rotations_pending":
            index.dialect_options["sqlite"]["where"] = text("state = 'pending'")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(rotation, "SessionLocal", sessions)
    monkeypatch.setattr(deps, "REQUIRE_MTLS", False)

    async def inline_worker(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(rotation, "run_owned_worker", inline_worker)
    receipts = {}

    def begin(db, user, action, intent, request_id):
        request_id = request_id or str(uuid4())
        row_id = str(uuid4())

        class Admission:
            row = SimpleNamespace(id=row_id)
            replay = request_id in receipts

            def response(self):
                return JSONResponse(receipts[request_id])

            def finish(self, body, *, secret_fields):
                assert secret_fields == ("api_key",)
                response = dict(body, request_id=request_id, secret_delivery="one_time")
                receipts[request_id] = {
                    key: value for key, value in response.items() if key != "api_key"
                }
                receipts[request_id]["secret_delivery"] = "unavailable"
                db.commit()
                return JSONResponse(response)

        return Admission()

    monkeypatch.setattr(rotation, "begin_admission", begin)
    old = "old_" + uuid4().hex
    with sessions() as db:
        organization = Organization(id=str(uuid4()), name="rotation", enabled=True)
        actor = User(
            id=str(uuid4()),
            org_id=organization.id,
            username="admin",
            password_hash="unused",
            role="admin",
            is_active=True,
        )
        agent = Agent(
            id=str(uuid4()),
            org_id=organization.id,
            hostname="host",
            api_key_hash=deps.hash_api_key(old),
        )
        db.add_all([organization, actor, agent])
        db.flush()
        db.add(
            AgentAPIKey(
                agent_id=agent.id,
                name="host",
                key_hash=deps.hash_api_key(old),
                key_prefix=old[:8],
                enabled=True,
            )
        )
        db.commit()
        ids = organization.id, actor.id, agent.id
    yield SimpleNamespace(
        sessions=sessions,
        org=ids[0],
        actor=ids[1],
        agent=ids[2],
        old=old,
        receipts=receipts,
    )
    engine.dispose()


def stage(fixture, request_id=None):
    with fixture.sessions() as db:
        result = rotation.stage(
            db, db.get(User, fixture.actor), fixture.agent, request_id or str(uuid4())
        )
        return json.loads(result.body)


def proof(fixture, body):
    return rotation.CandidateProof(
        fixture.org,
        fixture.agent,
        body["rotation_id"],
        deps.hash_api_key(body["api_key"]),
    )


def test_old_key_survives_staging_candidate_is_limited_and_activation_replay_does_not_swap(
    fixture,
):
    identity = str(uuid4())
    first = stage(fixture, identity)
    replay = stage(fixture, identity)
    assert replay["rotation_id"] == first["rotation_id"]
    assert replay["secret_delivery"] == "unavailable" and "api_key" not in replay
    with fixture.sessions() as db:
        assert deps._authenticate_agent(fixture.old, None, db).id == fixture.agent
        with pytest.raises(HTTPException):
            deps._authenticate_agent(first["api_key"], None, db)
        row = db.get(AgentKeyRotation, first["rotation_id"])
        assert row.predecessor_hash == deps.hash_api_key(fixture.old)
        assert first["api_key"] not in repr(row.__dict__) + repr(fixture.receipts)
    activated = rotation.activate(proof(fixture, first))
    assert activated["state"] == "activated"
    assert rotation.activate(proof(fixture, first)) == activated
    with fixture.sessions() as db:
        assert deps._authenticate_agent(first["api_key"], None, db).id == fixture.agent
        with pytest.raises(HTTPException):
            deps._authenticate_agent(fixture.old, None, db)
        assert (
            db.query(ActivityLog)
            .filter_by(action="agent_key_rotation_activated")
            .count()
            == 1
        )
        assert (
            db.get(Agent, fixture.agent).api_key_hash
            == db.query(AgentAPIKey).one().key_hash
        )


def test_pending_conflict_expiry_and_explicit_cancel_retain_active_key(fixture):
    first = stage(fixture)
    with pytest.raises(HTTPException) as error:
        stage(fixture)
    assert error.value.status_code == 409
    with fixture.sessions() as db:
        row = db.get(AgentKeyRotation, first["rotation_id"])
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    with pytest.raises(HTTPException) as error:
        rotation.activate(proof(fixture, first))
    assert error.value.status_code == 410
    second = stage(fixture)
    with fixture.sessions() as db:
        assert db.get(AgentKeyRotation, first["rotation_id"]).state == "expired"
        result = rotation.cancel(
            db, db.get(User, fixture.actor), fixture.agent, second["rotation_id"]
        )
        assert result["state"] == "cancelled"
        assert (
            rotation.cancel(
                db, db.get(User, fixture.actor), fixture.agent, second["rotation_id"]
            )["state"]
            == "cancelled"
        )
        assert deps._authenticate_agent(fixture.old, None, db).id == fixture.agent
    with pytest.raises(HTTPException):
        rotation.activate(proof(fixture, second))


@pytest.mark.parametrize(
    "change",
    ["inactive", "deleted", "role", "organization", "predecessor", "wrong-org"],
)
def test_activation_reauthorizes_original_binding(fixture, change):
    body = stage(fixture)
    candidate = proof(fixture, body)
    with fixture.sessions() as db:
        if change == "inactive":
            db.get(User, fixture.actor).is_active = False
        elif change == "deleted":
            db.delete(db.get(User, fixture.actor))
        elif change == "role":
            db.get(User, fixture.actor).role = "viewer"
        elif change == "organization":
            db.get(Organization, fixture.org).enabled = False
        elif change == "predecessor":
            db.get(Agent, fixture.agent).api_key_hash = deps.hash_api_key("changed")
        elif change == "wrong-org":
            candidate = rotation.CandidateProof(
                str(uuid4()),
                fixture.agent,
                body["rotation_id"],
                candidate.candidate_hash,
            )
        db.commit()
    with pytest.raises(HTTPException):
        rotation.activate(candidate)
    with fixture.sessions() as db:
        assert db.get(AgentKeyRotation, body["rotation_id"]).state == "pending"
        assert db.get(Agent, fixture.agent).api_key_hash != candidate.candidate_hash


def test_candidate_dependency_requires_key_and_actual_transport_certificate(
    fixture, monkeypatch
):
    body = stage(fixture)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"x-client-cert-fingerprint", b"spoof")],
    }

    async def resolve(key):
        generator = rotation.candidate_credential(
            fixture.agent, body["rotation_id"], Request(scope), key
        )
        try:
            return await anext(generator)
        finally:
            await generator.aclose()

    monkeypatch.setattr(deps, "REQUIRE_MTLS", True)
    with pytest.raises(HTTPException) as error:
        asyncio.run(resolve(body["api_key"]))
    assert error.value.status_code == 401
    monkeypatch.setattr(deps, "REQUIRE_MTLS", False)
    with pytest.raises(HTTPException):
        asyncio.run(resolve(None))
    candidate = asyncio.run(resolve(body["api_key"]))
    assert (
        candidate.rotation_id == body["rotation_id"] and candidate.org_id == fixture.org
    )
    assert candidate.certificate_fingerprint is None


def test_certificate_is_revalidated_at_activation(fixture, monkeypatch):
    from core.verified_tls import PEER_SCOPE, VerifiedPeer

    body = stage(fixture)
    fingerprint = uuid4().hex * 2
    with fixture.sessions() as db:
        db.get(Agent, fixture.agent).cert_fingerprint = fingerprint
        certificate = AgentCertificate(
            id=str(uuid4()),
            agent_id=fixture.agent,
            fingerprint=fingerprint,
            serial_number=uuid4().hex,
            status="active",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db.add(certificate)
        db.commit()
        certificate_id = certificate.id
    monkeypatch.setattr(deps, "REQUIRE_MTLS", True)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [],
        PEER_SCOPE: VerifiedPeer(fingerprint),
    }

    async def resolve():
        generator = rotation.candidate_credential(
            fixture.agent, body["rotation_id"], Request(scope), body["api_key"]
        )
        try:
            return await anext(generator)
        finally:
            await generator.aclose()

    candidate = asyncio.run(resolve())
    with fixture.sessions() as db:
        db.get(AgentCertificate, certificate_id).status = "revoked"
        db.commit()
    with pytest.raises(HTTPException) as error:
        rotation.activate(candidate)
    assert error.value.status_code == 401


@pytest.mark.parametrize("change", ["disabled", "expired", "mismatched"])
def test_present_key_metadata_controls_ordinary_auth_and_storage_proof(fixture, change):
    from core.storage_attempt_key import _credential
    from core.s3_ownership import StorageOwnershipError

    with fixture.sessions() as db:
        key = db.query(AgentAPIKey).one()
        if change == "disabled":
            key.enabled = False
        elif change == "expired":
            key.expires_at = datetime.utcnow() - timedelta(seconds=1)
        else:
            key.key_hash = deps.hash_api_key("different")
        db.commit()
        with pytest.raises(HTTPException):
            deps._authenticate_agent(fixture.old, None, db)
        with pytest.raises(StorageOwnershipError):
            _credential(db, fixture.agent, ("api-key", deps.hash_api_key(fixture.old)))


def test_lifetime_configuration_is_bounded(monkeypatch):
    monkeypatch.delenv("AGENT_KEY_ROTATION_TTL_HOURS", raising=False)
    assert rotation.ttl_hours() == 24
    for value in ("0", "169", "invalid"):
        monkeypatch.setenv("AGENT_KEY_ROTATION_TTL_HOURS", value)
        with pytest.raises(HTTPException):
            rotation.ttl_hours()


def load_helper():
    path = ROOT / "scripts/activate-agent-key.py"
    spec = importlib.util.spec_from_file_location("activate_agent_key", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_helper_private_file_permissions_symlinks_and_redacted_diagnostics(
    tmp_path, capsys
):
    helper = load_helper()
    candidate = "candidate_" + uuid4().hex
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps({"api_key": candidate}))
    path.chmod(0o600)
    assert helper.private_candidate(path) == candidate
    path.chmod(0o644)
    with pytest.raises(ValueError):
        helper.private_candidate(path)
    path.chmod(0o600)
    symlink = tmp_path / "link"
    symlink.symlink_to(path)
    with pytest.raises(OSError):
        helper.private_candidate(symlink)
    result = helper.main(
        [
            "--activate",
            "--api-url",
            "http://unsafe.test",
            "--agent-id",
            str(uuid4()),
            "--rotation-id",
            str(uuid4()),
            "--candidate-file",
            str(path),
        ]
    )
    assert result == 1 and candidate not in capsys.readouterr().err
    assert (
        helper.NoRedirect().redirect_request(
            None, None, 302, "", {}, "https://elsewhere.test"
        )
        is None
    )


def test_activation_audit_failure_rolls_back_key_and_state(fixture, monkeypatch):
    body = stage(fixture)

    def refused(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(rotation, "log_activity", refused)
    with pytest.raises(RuntimeError):
        rotation.activate(proof(fixture, body))
    with fixture.sessions() as db:
        assert db.get(Agent, fixture.agent).api_key_hash == deps.hash_api_key(
            fixture.old
        )
        assert db.get(AgentKeyRotation, body["rotation_id"]).state == "pending"
        assert db.query(AgentAPIKey).one().key_hash == deps.hash_api_key(fixture.old)


def test_real_rotation_routes_and_schema_use_only_candidate_proof(fixture, monkeypatch):
    from fastapi import FastAPI
    import httpx
    from routers import agents
    from operator_contracts import install_operator_contracts
    from core.settings_service import SettingsService

    async def inline_worker(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(agents, "run_owned_worker", inline_worker)
    app = FastAPI()
    app.include_router(agents.router)

    async def actor():
        return SimpleNamespace(
            id=fixture.actor, org_id=fixture.org, username="admin", role="admin"
        )

    async def database():
        with fixture.sessions() as db:
            yield db

    app.dependency_overrides[deps.get_admin_user] = actor
    app.dependency_overrides[agents.get_db] = database

    async def identity():
        return str(uuid4())

    app.dependency_overrides[agents.request_identity] = identity
    install_operator_contracts(
        app, SettingsService.DEFINITIONS, SettingsService.SECRET_DEFINITIONS
    )
    schema = app.openapi()
    operation = schema["paths"][
        "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate"
    ]["post"]
    assert operation["security"] == [{"AgentCandidate": []}]
    assert operation["x-credential-domain"] == "agent-candidate-activation-only"
    staged_schema = schema["paths"]["/api/v1/agents/{agent_id}/rotate-key"]["post"][
        "responses"
    ]["200"]["content"]["application/json"]["schema"]
    assert staged_schema["discriminator"]["propertyName"] == "secret_delivery"

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/agents/{fixture.agent}/rotate-key",
                headers={"Idempotency-Key": str(uuid4())},
            )
            assert response.status_code == 200
            body = response.json()
            path = f'/api/v1/agents/{fixture.agent}/key-rotations/{body["rotation_id"]}/activate'
            assert (
                await client.post(
                    path, headers={"Authorization": "Bearer not-candidate"}
                )
            ).status_code == 401
            response = await client.post(path, headers={"X-Agent-Key": body["api_key"]})
            assert (
                response.status_code == 200 and response.json()["state"] == "activated"
            )
            assert "api_key" not in response.json()
            again = await client.post(path, headers={"X-Agent-Key": body["api_key"]})
            assert again.json() == response.json()
            return body

    body = asyncio.run(exercise())
    from jsonschema import Draft202012Validator, FormatChecker

    Draft202012Validator(staged_schema, format_checker=FormatChecker()).validate(body)


def test_new_stage_expires_prior_pending_without_invalidating_current_key(fixture):
    first = stage(fixture)
    with fixture.sessions() as db:
        db.get(AgentKeyRotation, first["rotation_id"]).expires_at = datetime.now(
            timezone.utc
        ) - timedelta(seconds=1)
        db.commit()
    second = stage(fixture)
    with fixture.sessions() as db:
        assert db.get(AgentKeyRotation, first["rotation_id"]).state == "expired"
        assert db.get(AgentKeyRotation, second["rotation_id"]).state == "pending"
        assert deps._authenticate_agent(fixture.old, None, db).id == fixture.agent


def test_old_activated_candidate_cannot_authenticate_after_later_rotation(fixture):
    first = stage(fixture)
    rotation.activate(proof(fixture, first))
    second = stage(fixture)
    rotation.activate(proof(fixture, second))
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}

    async def resolve():
        generator = rotation.candidate_credential(
            fixture.agent, first["rotation_id"], Request(scope), first["api_key"]
        )
        try:
            return await anext(generator)
        finally:
            await generator.aclose()

    with pytest.raises(HTTPException) as error:
        asyncio.run(resolve())
    assert error.value.status_code == 403
