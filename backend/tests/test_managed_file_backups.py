"""Exercise the public named-target API and the common timed/manual executor."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest
from sqlalchemy import select

from core import file_backups
from core.community_usage import observe_usage
from database import get_db
from deps import get_current_user
from models import (
    AgentCertificate,
    FileBackup,
    FileSchedule,
    Organization,
    OrganizationDefault,
    SystemEvent,
    User,
    VM,
)
from routers.file_backups import router

from .conftest import make_agent

FINGERPRINT = "a" * 64
ARCHIVE_SHA256 = "b" * 64
STORAGE = {
    "endpoint": "https://backup.test:8443",
    "region": "us-east-1",
    "bucket": "backups-test",
    "prefix": "site/files",
    "recipient_sha256": FINGERPRINT,
}


def add_user(db, role, org_id):
    user = User(
        username=f"{role}-{uuid4()}",
        password_hash="test-only",
        role=role,
        org_id=org_id,
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def installation(db_session, session_factory, monkeypatch):
    organization = db_session.get(OrganizationDefault, "oss").org_id
    admin = add_user(db_session, "admin", organization)
    operator = add_user(db_session, "operator", organization)
    viewer = add_user(db_session, "viewer", organization)
    other = Organization(name="Other organization")
    db_session.add(other)
    db_session.commit()
    foreign = add_user(db_session, "admin", other.id)
    capabilities = {
        "provider": "none",
        "managed_file_sets": ["alpha", "bravo"],
        "managed_file_storage": {
            **STORAGE,
            "recipient_sha256": {"alpha": FINGERPRINT, "bravo": FINGERPRINT},
        },
    }
    agent = make_agent(
        db_session,
        capabilities=capabilities,
        mtls_enabled=True,
        cert_fingerprint=FINGERPRINT,
    )
    cert = AgentCertificate(
        agent_id=agent.id,
        serial_number="ab",
        fingerprint=FINGERPRINT,
        common_name=agent.hostname,
        expires_at=file_backups.clock() + timedelta(days=1),
    )
    db_session.add(cert)
    db_session.commit()
    other_agent = make_agent(db_session, org_id=other.id, capabilities=capabilities)
    target = {"kind": "file_set", "agent_id": agent.id, "file_set": "alpha"}
    who = {"actor": admin}

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: who["actor"]

    def db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = db
    monkeypatch.setattr(file_backups, "is_maintenance_mode", lambda db: False)
    monkeypatch.setattr(file_backups, "new_backup_admission_paused", lambda db: False)
    with TestClient(app) as client:
        yield SimpleNamespace(
            db=db_session,
            client=client,
            who=who,
            admin=admin,
            viewer=viewer,
            operator=operator,
            foreign=foreign,
            agent=agent,
            certificate=cert,
            other_agent=other_agent,
            target=target,
            organization=organization,
            factory=session_factory,
        )


def test_target_authority_opaque_retry_and_inventory(installation, monkeypatch):
    s = installation
    s.who["actor"] = s.viewer
    listings = s.client.get("/api/v1/file-sets").json()["items"]
    assert [x["target"]["file_set"] for x in listings] == ["alpha", "bravo"]
    assert listings[0]["storage"] == STORAGE
    assert (
        s.client.post("/api/v1/file-backups", json={"target": s.target}).status_code
        == 403
    )
    s.who["actor"] = s.operator
    assert (
        s.client.post(
            "/api/v1/file-backups",
            json={
                "target": {**s.target, "agent_id": s.other_agent.id},
            },
        ).status_code
        == 404
    )
    for insecure in (
        {**s.target, "file_set": "../root"},
        {**s.target, "path": "/"},
        {**s.target, "kind": "vm"},
    ):
        assert (
            s.client.post("/api/v1/file-backups", json={"target": insecure}).status_code
            == 422
        )

    create = s.client.post(
        "/api/v1/file-backups",
        json={"target": s.target},
        headers={"Idempotency-Key": "RetryA"},
    )
    assert create.status_code == 202, create.text
    backup_id = create.json()["id"]
    assert create.json()["status"] == "pending"
    monkeypatch.setattr(file_backups, "new_backup_admission_paused", lambda db: True)
    replay = s.client.post(
        "/api/v1/file-backups",
        json={"target": s.target},
        headers={"Idempotency-Key": "RetryA"},
    )
    assert replay.json()["id"] == backup_id
    paused = s.client.post(
        "/api/v1/file-backups",
        json={"target": s.target},
        headers={"Idempotency-Key": "retrya"},
    )
    assert (paused.status_code, paused.json()["detail"]["code"]) == (
        409,
        "backup_admission_paused",
    )
    assert (
        s.client.post(
            "/api/v1/file-backups",
            json={
                "target": {**s.target, "file_set": "bravo"},
            },
            headers={"Idempotency-Key": "RetryA"},
        ).json()["detail"]["code"]
        == "file_request_conflict"
    )
    assert s.db.query(VM).count() == 0
    s.who["actor"] = s.foreign
    assert s.client.get(f"/api/v1/file-backups/{backup_id}").status_code == 404
    assert not s.client.get("/api/v1/file-backups").json()["items"]


class HostTransport:
    def __init__(self):
        self.file_agent_http = self
        self.jobs = {}
        self.calls = []

    def has_authenticated_agent_transport(self):
        return True

    def _get_agent_headers(self):
        return {"X-Orchestrator-Key": "test"}

    def response(self, method, url, status, captured):
        return httpx.Response(status, json=captured, request=httpx.Request(method, url))

    async def post(self, peer, path, *, headers, json):
        assert peer.fingerprint == FINGERPRINT
        url = "https://enrolled-host" + path
        self.calls.append(("post", json["backup_id"], headers, json["storage"]))
        receipt = {
            "backup_id": json["backup_id"],
            "file_set": json["file_set"],
            "status": "completed",
            "files": 2,
            "directories": 1,
            "bytes": 32,
            "s3_path": "s3://backups-test/site/files/managed-files/"
            + json["file_set"]
            + "/"
            + json["backup_id"]
            + "/archive.age",
            "s3_version_id": "version_001",
            "archive_format": file_backups.ARCHIVE_FORMAT,
            "archive_size_bytes": 660,
            "archive_sha256": ARCHIVE_SHA256,
            "recipient_sha256": FINGERPRINT,
            "storage": json["storage"],
        }
        self.jobs[json["backup_id"]] = receipt
        # Acknowledgement lost after the host durably captured this ID.
        raise httpx.ReadTimeout("lost response", request=httpx.Request("POST", url))

    async def get(self, peer, path, *, headers):
        assert peer.fingerprint == FINGERPRINT
        url = "https://enrolled-host" + path
        backup_id = path.rsplit("/", 1)[1]
        self.calls.append(("get", backup_id, headers, None))
        return self.response("GET", url, 200, self.jobs[backup_id])


@pytest.mark.asyncio
async def test_cron_and_manual_share_executor_and_reconcile_same_backup(
    installation, monkeypatch
):
    s = installation
    s.who["actor"] = s.operator
    body = {"name": "nightly files", "target": s.target, "cron_expression": "* * * * *"}
    assert s.client.post("/api/v1/file-schedules", json=body).status_code == 403
    manual_id = s.client.post("/api/v1/file-backups", json={"target": s.target}).json()[
        "id"
    ]
    s.who["actor"] = s.admin
    create = s.client.post("/api/v1/file-schedules", json=body)
    assert create.status_code == 201, create.text
    schedule_id = create.json()["id"]
    assert create.json()["storage"] == STORAGE
    schedule = s.db.get(FileSchedule, schedule_id)
    due = file_backups.clock().replace(second=0, microsecond=0)
    schedule.next_run_at = due
    s.db.commit()
    file_backups.create_due_file_attempts(s.factory, s.organization, due)
    file_backups.create_due_file_attempts(s.factory, s.organization, due)
    transport = HostTransport()
    moment = file_backups.clock() + timedelta(seconds=1)
    checks, notifications = file_backups.claim_checks(
        s.factory, s.organization, moment, transport
    )
    assert len(checks) == 2 and not notifications
    for check in checks:
        assert (
            await file_backups._run_check(s.factory, s.organization, transport, check)
            is None
        )
    assert {method for method, *_ in transport.calls} == {"post"}
    monkeypatch.setattr(file_backups, "clock", lambda: moment + timedelta(seconds=12))
    retries, notifications = file_backups.claim_checks(
        s.factory, s.organization, file_backups.clock(), transport
    )
    for check in retries:
        outcome = await file_backups._run_check(
            s.factory, s.organization, transport, check
        )
        assert outcome[0]
    for backup_id, receipt in transport.jobs.items():
        response = s.client.get(f"/api/v1/file-backups/{backup_id}").json()
        assert response["archive_sha256"] == receipt["archive_sha256"]
        assert response["s3_version_id"] == receipt["s3_version_id"]
        assert response["archive_size_bytes"] == receipt["archive_size_bytes"]
    assert len(retries) == 2 and not notifications
    assert [call[0] for call in transport.calls].count("post") == 2
    assert all(call[2]["X-Vesta-Agent-ID"] == s.agent.id for call in transport.calls)
    assert (
        s.client.get("/api/v1/file-schedules").json()["items"][0]["last_status"]
        == "completed"
    )
    assert s.client.get("/api/v1/file-schedules").json()["items"][0]["last_success_at"]
    assert s.client.get("/api/v1/file-sets").json()["items"][0]["last_success_at"]
    assert s.db.scalar(select(FileBackup).filter_by(id=manual_id)).status == "completed"
    assert (
        s.db.query(SystemEvent).filter_by(event_type="file_backup_completed").count()
        == 2
    )
    assert observe_usage(s.db, exact=True)["successful_backups"] == 2

    assert (
        s.client.patch(
            f"/api/v1/file-schedules/{schedule_id}", json={"target": s.target}
        ).status_code
        == 422
    )
    assert (
        s.client.patch(
            f"/api/v1/file-schedules/{schedule_id}", json={"name": "new name"}
        ).json()["last_status"]
        == "completed"
    )
    assert s.client.delete(f"/api/v1/file-schedules/{schedule_id}").status_code == 204
    assert not s.client.get("/api/v1/file-schedules").json()["items"]
    assert (
        len(
            s.client.get(f"/api/v1/file-backups?schedule_id={schedule_id}").json()[
                "items"
            ]
        )
        == 1
    )
    assert observe_usage(s.db, exact=True)["successful_backups"] == 2


@pytest.mark.asyncio
async def test_pending_scope_change_fails_and_receipt_must_match(installation):
    s = installation
    create = s.client.post("/api/v1/file-backups", json={"target": s.target})
    assert create.status_code == 202
    s.agent.capabilities = {
        **s.agent.capabilities,
        "managed_file_storage": {
            **s.agent.capabilities["managed_file_storage"],
            "prefix": "different",
        },
    }
    s.db.commit()
    host = HostTransport()
    checks, notifications = file_backups.claim_checks(
        s.factory, s.organization, file_backups.clock(), host
    )
    assert not checks and len(notifications) == 1 and not notifications[0][0]
    assert (
        s.client.get(f"/api/v1/file-backups/{create.json()['id']}").json()["status"]
        == "failed"
    )
    resubmit = s.client.post("/api/v1/file-backups", json={"target": s.target})
    assert resubmit.status_code == 202
    checks, _ = file_backups.claim_checks(
        s.factory, s.organization, file_backups.clock(), host
    )
    check = checks[0]
    await file_backups._run_check(s.factory, s.organization, host, check)
    with pytest.raises(ValueError, match="Versioned encrypted"):
        file_backups.validate_observation(host.jobs[check.backup_id], check)


def test_revoked_operator_and_replaced_scheduler_grant_cannot_start(installation):
    s = installation
    s.who["actor"] = s.operator
    manual = s.client.post("/api/v1/file-backups", json={"target": s.target}).json()[
        "id"
    ]
    s.operator.role = "viewer"
    s.db.commit()
    s.who["actor"] = s.admin
    schedule_id = s.client.post(
        "/api/v1/file-schedules",
        json={
            "name": "nightly files",
            "target": s.target,
            "cron_expression": "* * * * *",
        },
    ).json()["id"]
    due = file_backups.clock().replace(second=0, microsecond=0)
    schedule = s.db.get(FileSchedule, schedule_id)
    schedule.next_run_at = due
    s.db.commit()
    file_backups.create_due_file_attempts(s.factory, s.organization, due)
    assert (
        s.client.patch(
            f"/api/v1/file-schedules/{schedule_id}", json={"enabled": True}
        ).status_code
        == 200
    )

    transport = HostTransport()
    checks, notifications = file_backups.claim_checks(
        s.factory, s.organization, file_backups.clock(), transport
    )
    assert not checks and len(notifications) == 2
    assert not transport.calls and all(not outcome[0] for outcome in notifications)
    assert s.client.get(f"/api/v1/file-backups/{manual}").json()["status"] == "failed"
    attempts = s.client.get(f"/api/v1/file-backups?schedule_id={schedule_id}").json()[
        "items"
    ]
    assert len(attempts) == 1 and attempts[0]["status"] == "failed"


def test_file_only_host_does_not_require_vm_connectivity():
    from core.agent_health import assess_agent_health

    metrics = {
        "provider": "none",
        "provider_accessible": False,
        "libvirt_accessible": False,
    }
    limits = {
        "storage_free_gb_threshold": 10,
        "storage_free_percent_threshold": 10,
        "load_percent_threshold": 80,
    }
    assert assess_agent_health(metrics, **limits) == ([], [])
    assert assess_agent_health({**metrics, "provider": "libvirt"}, **limits)[1] == [
        "libvirt_unavailable"
    ]


def test_revoked_agent_certificate_cannot_receive_dispatch(installation):
    s = installation
    pending = s.client.post("/api/v1/file-backups", json={"target": s.target})
    assert pending.status_code == 202
    s.certificate.status = "revoked"
    s.certificate.revoked_at = file_backups.clock()
    s.db.commit()
    transport = HostTransport()
    checks, notifications = file_backups.claim_checks(
        s.factory,
        s.organization,
        file_backups.clock() + timedelta(minutes=16),
        transport,
    )
    assert not checks and len(notifications) == 1 and not notifications[0][0]
    assert not transport.calls


@pytest.mark.parametrize(
    "changed",
    [
        {"endpoint": "https://different.test"},
        {"region": "eu-west-1"},
    ],
)
def test_file_schedule_requires_reactivation_after_destination_drift(
    installation, changed
):
    s = installation
    create = s.client.post(
        "/api/v1/file-schedules",
        json={"name": "Bound", "target": s.target, "cron_expression": "* * * * *"},
    )
    assert create.status_code == 201, create.text
    schedule_id = create.json()["id"]
    due = file_backups.clock().replace(second=0, microsecond=0)
    s.db.get(FileSchedule, schedule_id).next_run_at = due
    s.agent.capabilities = {
        **s.agent.capabilities,
        "managed_file_storage": {
            **s.agent.capabilities["managed_file_storage"],
            **changed,
        },
    }
    s.db.commit()
    file_backups.create_due_file_attempts(s.factory, s.organization, due)
    checks, notifications = file_backups.claim_checks(
        s.factory, s.organization, file_backups.clock(), HostTransport()
    )
    assert not checks and len(notifications) == 1 and not notifications[0][0]
    schedule_path = "/api/v1/file-schedules/" + schedule_id
    assert (
        s.client.get("/api/v1/file-schedules").json()["items"][0]["storage"] == STORAGE
    )
    renewed = s.client.patch(schedule_path, json={"enabled": True})
    assert renewed.status_code == 200 and renewed.json()["storage"] == {
        **STORAGE,
        **changed,
    }
    history = s.client.get("/api/v1/file-backups").json()["items"]
    assert history[0]["status"] == "failed" and history[0]["storage"] == STORAGE


def test_file_capabilities_require_certification_and_retain_last_binding(installation):
    previous = installation.agent.capabilities
    forged = {
        "provider": "libvirt",
        "managed_file_sets": ["other"],
        "managed_file_storage": {
            **STORAGE,
            "recipient_sha256": {"other": FINGERPRINT},
        },
    }
    assert "managed_file_sets" not in file_backups.bind_file_capabilities(
        {}, forged, trusted=False
    )
    assert (
        file_backups.bind_file_capabilities(previous, forged, trusted=False) == previous
    )
    assert file_backups.bind_file_capabilities(previous, forged, trusted=True) == forged
    for endpoint in (
        "https://u@s3.example.test",
        "https://s3.example.test?secret=1",
        "https://s3.example.test#",
        "https://s3.example.test/path",
    ):
        bad = {
            **forged,
            "managed_file_storage": {
                **forged["managed_file_storage"],
                "endpoint": endpoint,
            },
        }
        sanitized = file_backups.bind_file_capabilities(previous, bad, trusted=True)
        assert "managed_file_storage" not in sanitized
