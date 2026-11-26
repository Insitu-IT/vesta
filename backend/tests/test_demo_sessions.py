from datetime import datetime, timedelta

import pytest
from config import settings
from demo.journey import DemoJourney, DemoJourneyError
from demo.limits import DemoLimitError, DemoRateLimiter
from demo.sessions import DemoSessionError, DemoSessionService
from fastapi import FastAPI
from fastapi.testclient import TestClient
from middleware import DemoPolicyMiddleware
from routers.demo import router as demo_router

NOW = datetime(2026, 8, 24, 8, 0)


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def service(db_session, clock, idle=60, absolute=120):
    return DemoSessionService(
        db_session,
        idle_minutes=idle,
        absolute_minutes=absolute,
        now_fn=clock,
    )


def test_sessions_are_opaque_and_isolated(db_session):
    clock = Clock()
    manager = service(db_session, clock)
    first = manager.create()
    second = manager.create()

    assert first.token != second.token
    assert first.token not in first.session.token_hash
    assert len(first.session.token_hash) == 64
    assert first.session.id != second.session.id
    assert first.session.state == second.session.state

    first.session.state = {**first.session.state, "session_marker": "first"}
    db_session.commit()
    db_session.refresh(second.session)
    assert "session_marker" not in second.session.state


def test_idle_expiry_slides_but_never_exceeds_absolute(db_session):
    clock = Clock()
    manager = service(db_session, clock, idle=60, absolute=90)
    created = manager.create()

    clock.now += timedelta(minutes=50)
    touched = manager.require(created.token)
    assert touched.expires_at == NOW + timedelta(minutes=90)
    assert touched.expires_at == touched.absolute_expires_at


def test_expired_session_is_deleted(db_session):
    clock = Clock()
    manager = service(db_session, clock, idle=10, absolute=20)
    created = manager.create()
    clock.now += timedelta(minutes=11)

    with pytest.raises(DemoSessionError) as exc:
        manager.require(created.token)
    assert exc.value.code == "DEMO_SESSION_EXPIRED"
    assert manager.destroy(created.token) is False


def test_reset_restores_versioned_fixture(db_session):
    clock = Clock()
    manager = service(db_session, clock)
    created = manager.create()
    created.session.state = {"tampered": True}
    db_session.commit()

    reset = manager.reset(created.token)
    assert reset.state["environment"] == "demo"
    assert reset.state["simulated"] is True
    assert "tampered" not in reset.state


def test_cleanup_removes_idle_and_absolute_expiry(db_session):
    clock = Clock()
    manager = service(db_session, clock, idle=10, absolute=20)
    manager.create()
    manager.create()
    clock.now += timedelta(minutes=21)
    assert manager.cleanup_expired() == 2


def test_journey_mutations_are_session_local(db_session):
    clock = Clock()
    manager = service(db_session, clock)
    first = manager.create()
    second = manager.create()
    vm = first.session.state["vms"][0]
    journey = DemoJourney(first.session, db_session)

    group = journey.create_group(
        "Production running",
        [{"field": "state", "op": "eq", "value": "running"}],
        "all",
    )
    schedule = journey.create_schedule(
        {
            "name": "Demo weekly",
            "vm_group_id": group["id"],
            "cron_expression": "0 2 * * 0",
            "retention_days": 30,
            "backup_type": "full",
            "enabled": True,
        }
    )
    backup = journey.create_backup(vm["id"], "full", "success")
    restore = journey.create_restore(backup["id"])

    assert group["member_count"] > 0
    assert schedule["simulated"] is True
    assert backup["status"] == "completed"
    assert all(event["simulated"] for event in backup["events"])
    assert restore["message"] == "No VM or disk was changed."
    db_session.refresh(second.session)
    assert len(second.session.state["groups"]) == 4
    assert len(second.session.state["backups"]) == 7


def test_group_update_and_schedule_run(db_session):
    manager = service(db_session, Clock())
    created = manager.create()
    journey = DemoJourney(created.session, db_session)
    group = created.session.state["groups"][0]
    updated = journey.update_group(
        group["id"],
        "Testing only",
        [{"field": "metadata.environment", "op": "eq", "value": "testing"}],
        "all",
    )
    assert updated["name"] == "Testing only"
    assert updated["member_count"] == 2

    schedule = journey.create_schedule(
        {
            "name": "Run now",
            "vm_group_id": group["id"],
            "cron_expression": "0 2 * * 0",
            "retention_days": 30,
            "backup_type": "full",
            "enabled": True,
        }
    )
    backup = journey.run_schedule(schedule["id"])
    assert backup["status"] == "completed"
    assert backup["simulated"] is True


def test_incremental_refuses_without_fallback(db_session):
    manager = service(db_session, Clock())
    created = manager.create()
    unsupported = next(
        vm
        for vm in created.session.state["vms"]
        if not vm["metadata"]["supports_incremental"]
    )

    with pytest.raises(DemoJourneyError) as exc:
        DemoJourney(created.session, db_session).create_backup(
            unsupported["id"], "incremental", "success"
        )
    assert exc.value.code == "INCREMENTAL_UNSUPPORTED"
    db_session.refresh(created.session)
    assert not any(
        backup["vm_id"] == unsupported["id"]
        for backup in created.session.state["backups"]
    )


def test_upload_failure_is_retriable(db_session):
    manager = service(db_session, Clock())
    created = manager.create()
    vm = created.session.state["vms"][0]
    journey = DemoJourney(created.session, db_session)
    failed = journey.create_backup(vm["id"], "full", "upload_failure")

    assert failed["status"] == "upload_failed"
    completed = journey.retry_backup(failed["id"])
    assert completed["status"] == "completed"
    assert completed["events"][-1]["stage"] == "complete"


def test_object_quota_fails_explicitly(db_session, monkeypatch):
    manager = service(db_session, Clock())
    created = manager.create()
    monkeypatch.setattr(
        settings, "demo_max_groups", len(created.session.state["groups"])
    )

    with pytest.raises(DemoJourneyError) as exc:
        DemoJourney(created.session, db_session).create_group(
            "Too many",
            [{"field": "state", "op": "eq", "value": "running"}],
            "all",
        )
    assert exc.value.code == "DEMO_QUOTA_EXCEEDED"


def test_rate_limit_is_persistent_and_resets(db_session):
    clock = Clock()
    limiter = DemoRateLimiter(db_session, now_fn=clock)
    limiter.check("session", "opaque", 2)
    limiter.check("session", "opaque", 2)
    with pytest.raises(DemoLimitError) as exc:
        limiter.check("session", "opaque", 2)
    assert exc.value.code == "DEMO_RATE_LIMITED"
    assert exc.value.retry_after == 60

    clock.now += timedelta(seconds=61)
    limiter.check("session", "opaque", 2)


def test_concurrent_session_capacity_is_explicit(db_session):
    manager = DemoSessionService(
        db_session,
        idle_minutes=60,
        absolute_minutes=120,
        max_sessions=1,
        now_fn=Clock(),
    )
    manager.create()
    with pytest.raises(DemoSessionError) as exc:
        manager.create()
    assert exc.value.code == "DEMO_CAPACITY_REACHED"


def test_demo_policy_denies_standard_api_and_marks_allowed(
    monkeypatch, session_factory
):
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr("database.SessionLocal", session_factory)
    app = FastAPI()
    app.add_middleware(DemoPolicyMiddleware)

    @app.get("/api/v1/demo/ping")
    def demo_ping():
        return {"ok": True}

    @app.post("/api/v1/backups")
    def real_backup():
        return {"should_not_run": True}

    @app.get("/assets/app.js")
    def asset():
        return {"asset": True}

    client = TestClient(app)
    allowed = client.get("/api/v1/demo/ping")
    denied = client.post("/api/v1/backups")
    docs = client.get("/openapi.json")
    asset_response = client.get("/assets/app.js")

    assert allowed.status_code == 200
    assert allowed.headers["X-Vnbui-Simulated"] == "true"
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "DEMO_POLICY_DENIED"
    assert docs.status_code == 403
    assert asset_response.status_code == 200


def test_demo_policy_rate_limits_source(monkeypatch, session_factory):
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "demo_source_requests_per_minute", 1)
    monkeypatch.setattr("database.SessionLocal", session_factory)
    app = FastAPI()
    app.add_middleware(DemoPolicyMiddleware)

    @app.get("/api/v1/demo/ping")
    def demo_ping():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/api/v1/demo/ping").status_code == 200
    limited = client.get("/api/v1/demo/ping")
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 60
    assert limited.json()["detail"]["code"] == "DEMO_RATE_LIMITED"


def test_demo_router_session_lifecycle(db_session, monkeypatch):
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "demo_cookie_secure", True)
    monkeypatch.setattr(settings, "demo_max_sessions", 10)
    app = FastAPI()
    app.include_router(demo_router)

    from database import get_db

    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url="https://demo.example")

    created = client.post("/api/v1/demo/sessions")
    assert created.status_code == 201
    assert created.json()["simulated"] is True
    assert "HttpOnly" in created.headers["set-cookie"]
    assert "Secure" in created.headers["set-cookie"]

    state = client.get("/api/v1/demo/state")
    assert state.status_code == 200
    assert state.json()["fixture_version"]

    reset = client.post("/api/v1/demo/reset")
    assert reset.status_code == 200
    assert reset.json()["state"]["environment"] == "demo"

    destroyed = client.delete("/api/v1/demo/sessions/current")
    assert destroyed.status_code == 204
    assert client.get("/api/v1/demo/state").status_code == 401


def test_demo_router_evaluator_journey(db_session, monkeypatch):
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "demo_cookie_secure", True)
    monkeypatch.setattr(settings, "demo_max_sessions", 10)
    app = FastAPI()
    app.include_router(demo_router)

    from database import get_db

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app, base_url="https://demo.example")
    assert client.post("/api/v1/demo/sessions").status_code == 201
    state = client.get("/api/v1/demo/state").json()

    preview = client.post(
        "/api/v1/demo/groups/preview",
        json={
            "name": "Running",
            "rules": [{"field": "state", "op": "eq", "value": "running"}],
        },
    )
    assert preview.status_code == 200
    assert preview.json()["total"] > 0

    backup = client.post(
        "/api/v1/demo/backups",
        json={"vm_id": state["vms"][0]["id"], "backup_type": "full"},
    )
    assert backup.status_code == 201
    assert backup.json()["events"][-1]["status"] == "completed"

    restore = client.post(
        "/api/v1/demo/restores", json={"backup_id": backup.json()["id"]}
    )
    assert restore.status_code == 201
    assert restore.json()["simulated"] is True

    refused = client.post(
        "/api/v1/demo/backups",
        json={
            "vm_id": next(
                vm["id"]
                for vm in state["vms"]
                if not vm["metadata"]["supports_incremental"]
            ),
            "backup_type": "incremental",
        },
    )
    assert refused.status_code == 422
    assert refused.json()["detail"]["code"] == "INCREMENTAL_UNSUPPORTED"
