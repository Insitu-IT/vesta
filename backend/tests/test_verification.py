"""Verification must never turn a metadata-only operation into checksum proof."""

from types import SimpleNamespace
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.conftest import make_agent, make_backup, make_vm
from database import get_db
from deps import get_current_user
from models import ActivityLog, BackupVerification, OrganizationDefault
from routers import verification


@pytest.fixture
def client(db_session):
    app = FastAPI()
    app.include_router(verification.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="operator",
        role="operator",
        org_id=db_session.get(OrganizationDefault, "oss").org_id,
    )
    with TestClient(app) as client:
        yield client


def backup(db, status="completed"):
    org_id = db.get(OrganizationDefault, "oss").org_id
    return make_backup(db, make_vm(db, make_agent(db)), status=status, org_id=org_id)


def test_verify_without_accepted_catalog_refuses_without_creating_evidence(
    client, db_session
):
    row = backup(db_session)
    for _ in range(2):
        response = client.post(
            f"/api/v1/backups/{row.id}/verify",
            json={"verification_id": str(uuid.uuid4())},
        )
        assert response.status_code == 409
    assert db_session.query(BackupVerification).count() == 0
    assert db_session.query(ActivityLog).count() == 0
    db_session.refresh(row)
    assert row.status == "completed"


@pytest.mark.parametrize("status, expected", [("missing", 404), ("running", 400)])
def test_verify_preserves_backup_checks(client, db_session, status, expected):
    bid = "missing" if status == "missing" else backup(db_session, status).id
    assert (
        client.post(
            f"/api/v1/backups/{bid}/verify", json={"verification_id": str(uuid.uuid4())}
        ).status_code
        == expected
    )
    assert db_session.query(BackupVerification).count() == 0


def test_viewer_cannot_request_verification(db_session):
    row = backup(db_session)
    app = FastAPI()
    app.include_router(verification.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="viewer", role="viewer"
    )
    with TestClient(app) as client:
        assert (
            client.post(
                f"/api/v1/backups/{row.id}/verify",
                json={"verification_id": str(uuid.uuid4())},
            ).status_code
            == 403
        )
    assert db_session.query(BackupVerification).count() == 0


@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
def test_public_commands_preserve_original_id_and_never_return_secrets(
    db_session, monkeypatch, provider
):
    from backend.tests.test_backup_verification import fixture, response
    from core import backup_verification as scrub

    saved, actor, row = fixture(db_session, provider)
    scrub.apply_progress(row, response(row, "failed"))
    db_session.commit()
    app = FastAPI()
    app.include_router(verification.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: actor
    notified = []
    monkeypatch.setattr(
        verification.verification_executor, "notify", lambda: notified.append(True)
    )
    identity = str(uuid.uuid4())
    path = f"/api/v1/backups/{saved.id}/verify"
    with TestClient(app) as client:
        for _ in range(2):
            result = client.post(path, json={"verification_id": identity})
            assert result.status_code == 202, result.text
            assert result.headers["cache-control"] == "no-store"
            assert result.json()["id"] == identity
            assert result.json()["status"] == "pending"
            assert set(result.json()) == {
                "id",
                "backup_id",
                "verification_type",
                "status",
                "recorded_status",
                "created_by",
                "read_attempts",
                "read_limit",
                "cancel_requested",
                "result_message",
            }
        assert db_session.query(BackupVerification).count() == 2
        assert (
            client.post(path, json={"verification_id": str(uuid.uuid4())}).status_code
            == 409
        )
        pending = db_session.get(BackupVerification, identity)
        pending.status = "held"
        pending.verification_read_attempts = 3
        db_session.commit()
        resumed = client.post(
            path, json={"verification_id": identity, "action": "resume"}
        )
        assert resumed.status_code == 202, resumed.text
        assert resumed.json()["read_limit"] == 6
        cancelled = client.post(
            path, json={"verification_id": identity, "action": "cancel"}
        )
        assert (
            cancelled.status_code == 202
            and cancelled.json()["cancel_requested"] is True
        )
        assert cancelled.json()["status"] == "held"  # Not yet a stopped-reader fact.
        assert (
            client.post(
                path, json={"verification_id": identity, "action": "resume"}
            ).status_code
            == 409
        )
        assert (
            client.post(
                path, json={"verification_id": identity, "keys": {}}
            ).status_code
            == 422
        )
        assert (
            client.post(path, json={"verification_id": "not-a-uuid"}).status_code == 422
        )
    assert len(notified) == 4


@pytest.mark.parametrize("route", ["backup", "all", "detail"])
@pytest.mark.parametrize(
    "kind, message",
    [
        ("checksum", "Checksum verified successfully"),
        ("integrity", "Backup integrity verified successfully"),
        ("mount_test", "Backup integrity verified successfully"),
    ],
)
def test_simulated_history_is_not_presented_as_checksum_proof(
    client, db_session, route, kind, message
):
    row = backup(db_session)
    history = BackupVerification(
        backup_id=row.id,
        status="passed",
        verification_type=kind,
        result_message=message,
    )
    db_session.add(history)
    db_session.commit()
    path = {
        "backup": f"/api/v1/backups/{row.id}/verifications",
        "all": "/api/v1/verifications",
        "detail": f"/api/v1/verifications/{history.id}",
    }[route]
    response = client.get(path)
    assert response.status_code == 200, response.text
    body = response.json()
    result = (
        body[0] if route == "backup" else body["items"][0] if route == "all" else body
    )
    assert result["status"] == "unverified"
    assert result["recorded_status"] == "passed"
    assert "simulated" in result["result_message"].lower()
    db_session.refresh(history)
    assert history.status == "passed"  # Preserve original audit history.
    assert history.result_message == message


def test_status_filter_uses_evidence_status_not_simulated_pass(client, db_session):
    row = backup(db_session)
    db_session.add_all(
        [
            BackupVerification(
                backup_id=row.id,
                status="passed",
                verification_type="checksum",
                result_message="Checksum verified successfully",
            ),
            BackupVerification(
                backup_id=row.id,
                status="failed",
                verification_type="checksum",
                result_message="Digest mismatch",
            ),
        ]
    )
    db_session.commit()
    passed = client.get("/api/v1/verifications?status=passed").json()
    assert passed["total"] == 0 and passed["items"] == []
    unverified = client.get("/api/v1/verifications?status=unverified").json()
    assert unverified["total"] == 1
    assert unverified["items"][0]["status"] == "unverified"
    failed = client.get("/api/v1/verifications?status=failed").json()
    assert failed["total"] == 1
    assert failed["items"][0]["result_message"] == "Digest mismatch"


@pytest.mark.parametrize("route", ["backup", "all", "detail"])
@pytest.mark.parametrize(
    "kind,message",
    [
        ("checksum", "Different old success text"),
        ("integrity", None),
        ("custom", "Operator recorded success"),
        ("artifact_scrub", "artifact_bytes_verified"),
    ],
)
def test_unbound_success_is_unverified_regardless_of_message(
    client, db_session, route, kind, message
):
    saved = backup(db_session)
    row = BackupVerification(
        backup_id=saved.id,
        status="passed",
        verification_type=kind,
        result_message=message,
    )
    db_session.add(row)
    db_session.commit()
    path = {
        "backup": f"/api/v1/backups/{saved.id}/verifications",
        "all": "/api/v1/verifications",
        "detail": f"/api/v1/verifications/{row.id}",
    }[route]
    body = client.get(path).json()
    value = (
        body[0] if route == "backup" else body["items"][0] if route == "all" else body
    )
    assert value["status"] == "unverified" and value["recorded_status"] == "passed"
    assert "no receipt-bound" in value["result_message"]
    assert client.get("/api/v1/verifications?status=passed").json()["total"] == 0
    assert client.get("/api/v1/verifications?status=unverified").json()["total"] == 1
    db_session.refresh(row)
    assert row.status == "passed" and row.result_message == message


@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
def test_guarded_receipt_bound_result_remains_passed_in_reads_and_filters(
    client, db_session, provider
):
    from backend.tests.test_backup_verification import fixture, response
    from core import backup_verification as scrub

    saved, _, row = fixture(db_session, provider)
    value = response(row)
    scrub.apply_progress(row, value)
    db_session.commit()
    scrub.apply_progress(row, value)
    db_session.commit()
    for path in (
        f"/api/v1/backups/{saved.id}/verifications",
        "/api/v1/verifications",
        f"/api/v1/verifications/{row.id}",
    ):
        body = client.get(path).json()
        found = (
            body[0]
            if isinstance(body, list)
            else body["items"][0] if "items" in body else body
        )
        assert found["status"] == "passed", body
    assert client.get("/api/v1/verifications?status=passed").json()["total"] == 1
    assert client.get("/api/v1/verifications?status=unverified").json()["total"] == 0
