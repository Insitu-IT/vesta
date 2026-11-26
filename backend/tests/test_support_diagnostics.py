"""Diagnostic export must be useful without becoming a secret/tenant export."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event

from core.support_diagnostics import ROW_LIMIT, collect, project
from models import (
    Agent,
    Backup,
    BackupVerification,
    Organization,
    OrganizationDefault,
    Restore,
)

SECRET = "planted-password-token-private-key-signed-url"


def org(db):
    return db.get(OrganizationDefault, "oss").org_id


def seed(db, org_id):
    backup_id = str(uuid4())
    agent_id = str(uuid4())
    db.add(
        Agent(
            id=agent_id,
            org_id=org_id,
            hostname=SECRET,
            status="online",
            version="6.0.47",
            config={"password": SECRET},
            capabilities={"token": SECRET},
            metrics={"private_key": SECRET},
        )
    )
    db.add(
        Backup(
            id=backup_id,
            org_id=org_id,
            vm_id=str(uuid4()),
            status="failed",
            storage_path="https://" + SECRET,
            tags={"password": SECRET},
            wrapped_dek=SECRET,
        )
    )
    db.add(
        Restore(
            org_id=org_id,
            backup_id=backup_id,
            created_by=str(uuid4()),
            status="failed",
            target_vm_name=SECRET,
            error_message=SECRET,
        )
    )
    db.add(
        BackupVerification(
            org_id=org_id,
            backup_id=backup_id,
            status="failed",
            result_message=SECRET,
            verification_plan_canonical=SECRET,
        )
    )
    db.commit()
    return backup_id, agent_id


def test_allowlisted_read_only_export(db_session):
    backup_id, agent_id = seed(db_session, org(db_session))
    statements = []
    engine = db_session.get_bind()

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        report = collect(db_session, org(db_session))
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert report["status"] == "collected"
    assert SECRET not in json.dumps(report)
    assert report["sections"]["agents"]["rows"][0]["id"] == agent_id
    assert report["sections"]["backups"]["rows"][0]["id"] == backup_id
    assert report["sections"]["restores"]["rows"][0]["error_recorded"] is True
    assert all(
        sql.lstrip().split()[0].upper() in ("SELECT", "SAVEPOINT", "RELEASE")
        for sql in statements
    )
    assert db_session.in_transaction()


def test_explicit_organization_and_backup_scope(db_session):
    org_id = org(db_session)
    own_id, _ = seed(db_session, org_id)
    other = Organization(name="Other")
    db_session.add(other)
    db_session.commit()
    foreign_id, foreign_agent = seed(db_session, other.id)
    report = collect(db_session, org_id)
    encoded = json.dumps(report)
    assert (
        own_id in encoded and foreign_id not in encoded and foreign_agent not in encoded
    )
    focused = collect(db_session, org_id, backup_id=foreign_id)
    assert focused["sections"]["backups"]["rows"] == []
    assert focused["sections"]["restores"]["rows"] == []
    assert focused["sections"]["verifications"]["rows"] == []


def test_truncation_is_explicit_and_output_bounded(db_session):
    org_id = org(db_session)
    for _ in range(ROW_LIMIT + 2):
        db_session.add(Agent(org_id=org_id, hostname=str(uuid4())))
    db_session.commit()
    report = collect(db_session, org_id)
    section = report["sections"]["agents"]
    assert section["truncated"] is True and len(section["rows"]) == ROW_LIMIT
    assert len(json.dumps(report).encode()) < 128 * 1024


def test_failed_section_is_partial_without_exception_disclosure(
    db_session, monkeypatch, caplog
):
    org_id = org(db_session)
    backup_id, _ = seed(db_session, org_id)
    execute = db_session.execute

    def fail_agents(statement, *args, **kwargs):
        if "FROM agents" in str(statement):
            raise RuntimeError(SECRET)
        return execute(statement, *args, **kwargs)

    monkeypatch.setattr(db_session, "execute", fail_agents)
    report = collect(db_session, org_id)
    assert report["status"] == "partial"
    assert report["sections"]["agents"]["status"] == "unavailable"
    assert report["sections"]["backups"]["rows"][0]["id"] == backup_id
    assert SECRET not in json.dumps(report) + caplog.text
    assert "diagnostic_section_unavailable" in caplog.text


def test_collection_deadline_does_not_run_more_queries(db_session, monkeypatch):
    org_id = org(db_session)
    ticks = iter((0, 11, 12, 13, 14))
    monkeypatch.setattr("core.support_diagnostics.time.monotonic", lambda: next(ticks))
    report = collect(db_session, org_id)
    assert report["status"] == "partial"
    assert all(s["status"] == "unavailable" for s in report["sections"].values())


def test_projection_does_not_trust_strings_or_extra_fields():
    projected = project(
        {
            "id": SECRET,
            "status": SECRET,
            "version": SECRET,
            "created_at": SECRET,
            "config": {"password": SECRET},
            "progress": True,
            "chain_position": -1,
            "native_intent_present": SECRET,
        }
    )
    assert SECRET not in json.dumps(projected)
    assert projected == {
        "id": None,
        "status": "unknown",
        "version": None,
        "created_at": None,
        "progress": None,
        "chain_position": None,
        "native_intent_present": None,
    }
    assert (
        project({"created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)})["created_at"]
        == "2026-01-01T00:00:00+00:00"
    )


def test_collector_refuses_dirty_session_and_invalid_identity(db_session):
    org_id = org(db_session)
    with pytest.raises(ValueError):
        collect(db_session, SECRET)
    with pytest.raises(ValueError):
        collect(db_session, org_id, backup_id=SECRET)
    db_session.add(Agent(org_id=org_id, hostname="not-flushed"))
    with pytest.raises(ValueError, match="unchanged session"):
        collect(db_session, org_id)


@pytest.mark.parametrize(
    "role,expected", [("viewer", 403), ("operator", 403), ("admin", 200)]
)
def test_download_requires_admin_and_is_no_store(db_session, role, expected):
    from database import get_db
    from deps import get_current_user
    from routers.health import router

    org_id = org(db_session)
    seed(db_session, org_id)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        role=role, org_id=org_id
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/health/diagnostics")
        assert response.status_code == expected
        if expected == 200:
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["content-disposition"].startswith("attachment;")
            assert SECRET not in response.text
            assert response.json()["schema"] == "vnbui-support-diagnostics/1"
        assert client.get(
            "/api/v1/health/diagnostics?backup_id=not-a-uuid"
        ).status_code in (403, 422)
