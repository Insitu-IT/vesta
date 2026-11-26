"""Manual backup admission must not block the serving API event loop."""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
import httpx
import pytest


@pytest.mark.asyncio
async def test_create_backup_admission_keeps_same_app_health_responsive(monkeypatch):
    from database import get_db
    from deps import get_operator_or_admin
    from routers import backups, public

    entered = threading.Event()
    release = threading.Event()
    backup = SimpleNamespace(id="backup", status="pending")

    def blocked_create(self, **kwargs):
        entered.set()
        assert release.wait(15), "test did not release backup admission"
        return SimpleNamespace(success=True, backup=backup)

    monkeypatch.setattr(backups.BackupService, "_create_backup_flush", blocked_create)
    monkeypatch.setattr(backups.BackupService, "get_vm_name", lambda self, _: "lab")
    monkeypatch.setattr(backups, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(backups, "USE_REAL_BACKUP_EXECUTOR", False)
    # Isolate receipt persistence, retaining the actual synchronous route and
    # blocking service call. Restricted-PG tests own admission authority proof.
    request_id = "dc074d87-a588-4b79-b5cb-fc486195b8d8"
    admission = SimpleNamespace(
        replay=False,
        dispatch=MagicMock(),
        finish=MagicMock(
            side_effect=lambda body: JSONResponse(dict(body, request_id=request_id))
        ),
    )
    begin = MagicMock(return_value=admission)
    monkeypatch.setattr(backups, "begin_admission", begin)
    simulated = []

    async def no_background_work(backup_id):
        simulated.append(backup_id)

    monkeypatch.setattr(backups, "simulate_backup_execution", no_background_work)
    app = FastAPI()
    app.include_router(backups.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: SimpleNamespace()
    app.dependency_overrides[get_operator_or_admin] = lambda: SimpleNamespace(
        id="operator", org_id="organization"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://unit.invalid"
    ) as client:
        pending = asyncio.create_task(
            client.post(
                "/api/v1/backups",
                json={"vm_id": "00000000-0000-0000-0000-000000000001"},
                headers={"Idempotency-Key": request_id},
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            health = await asyncio.wait_for(client.get("/health"), 5)
            assert health.status_code == 200
            # Prove independence from the uncompleted admission, rather than
            # imposing a runner-speed threshold. A blocked loop fails this.
            assert not release.is_set()
            assert not pending.done()
        finally:
            release.set()
        response = await asyncio.wait_for(pending, 5)
        assert response.status_code == 200
        assert response.json()["id"] == "backup"
        assert response.json()["request_id"] == request_id
        assert begin.call_args.args[2] == "backup.create"
        assert begin.call_args.args[4] == request_id
        admission.dispatch.assert_called_once_with("backup", "backup")
        admission.finish.assert_called_once()
        assert simulated == [], "admission must not use request-lifetime dispatch"


def test_manual_delete_provider_wait_keeps_same_app_health_responsive(monkeypatch):
    from database import get_db
    from deps import get_operator_or_admin
    from routers import backups, public

    entered = threading.Event()
    release = threading.Event()
    backup = SimpleNamespace(
        id="backup",
        status="completed",
        capacity_state="released",
        vm=SimpleNamespace(name="lab"),
        vm_id="vm",
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = backup

    async def blocked_delete(_db, _backup):
        entered.set()
        assert release.wait(2), "test did not release provider wait"
        _backup.status = "deleted"
        return 7

    monkeypatch.setattr(
        backups.backup_deletion_service, "delete_payload", blocked_delete
    )
    monkeypatch.setattr(backups, "log_activity", lambda *args, **kwargs: None)
    app = FastAPI()
    app.include_router(backups.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_operator_or_admin] = lambda: SimpleNamespace(
        id="operator", org_id="organization"
    )

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(client.delete, "/api/v1/backups/backup")
        assert entered.wait(1)
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        response = pending.result(timeout=2)
        assert response.status_code == 200
        assert response.json()["deleted_bytes"] == 7


def test_bulk_delete_provider_wait_keeps_same_app_health_responsive(monkeypatch):
    from database import get_db
    from deps import get_operator_or_admin
    from routers import bulk, public

    entered = threading.Event()
    release = threading.Event()
    backup = SimpleNamespace(
        id="backup",
        status="completed",
        capacity_state="unreserved",
        vm=SimpleNamespace(name="lab"),
        vm_id="vm",
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = backup

    async def blocked_delete(_db, _backup):
        entered.set()
        assert release.wait(2), "test did not release bulk provider wait"
        _backup.status = "deleted"
        return 7

    monkeypatch.setattr(bulk.backup_deletion_service, "delete_payload", blocked_delete)
    monkeypatch.setattr(bulk, "log_activity", lambda *args, **kwargs: None)
    app = FastAPI()
    app.include_router(bulk.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_operator_or_admin] = lambda: SimpleNamespace(
        id="operator", org_id="organization"
    )

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(
            client.post, "/api/v1/backups/bulk-delete", json={"backup_ids": ["backup"]}
        )
        assert entered.wait(1)
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        response = pending.result(timeout=2)
        assert response.status_code == 200
        assert response.json()["summary"]["deleted"] == 1


def test_manual_cleanup_provider_wait_keeps_same_app_health_responsive(monkeypatch):
    from deps import get_admin_user
    from routers import backups, public

    entered = threading.Event()
    release = threading.Event()

    async def blocked_cleanup(*, dry_run=None):
        entered.set()
        assert release.wait(2), "test did not release retention wait"
        return {"deleted_count": 0, "deleted_bytes": 0, "dry_run": dry_run}

    monkeypatch.setattr(backups.retention_enforcer, "enforce_all", blocked_cleanup)
    app = FastAPI()
    app.include_router(backups.router)
    app.include_router(public.router)
    app.dependency_overrides[get_admin_user] = lambda: SimpleNamespace(id="admin")

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(client.post, "/api/v1/backups/cleanup?dry_run=true")
        assert entered.wait(1)
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        response = pending.result(timeout=2)
        assert response.status_code == 200
        assert response.json()["dry_run"] is True


def test_backup_list_database_wait_keeps_same_app_health_responsive():
    from database import get_db
    from deps import get_current_user
    from routers import backups, public

    entered = threading.Event()
    release = threading.Event()
    db = MagicMock()
    query = MagicMock()
    db.query.return_value.join.return_value = query

    def blocked_count():
        entered.set()
        assert release.wait(2), "test did not release backup query"
        return 0

    query.count.side_effect = blocked_count
    query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = (
        []
    )
    app = FastAPI()
    app.include_router(backups.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="viewer", org_id="organization"
    )

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(client.get, "/api/v1/backups")
        assert entered.wait(1)
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        response = pending.result(timeout=2)
        assert response.status_code == 200
        assert response.json()["total"] == 0


def test_blocked_readiness_query_keeps_same_app_health_responsive():
    from database import get_db
    from routers import public

    entered = threading.Event()
    release = threading.Event()
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "sqlite"

    def blocked_query(statement):
        entered.set()
        assert release.wait(2), "test did not release readiness wait"

    db.execute.side_effect = blocked_query
    app = FastAPI()
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(client.get, "/ready")
        assert entered.wait(1)
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        assert pending.result(timeout=2).status_code == 200
