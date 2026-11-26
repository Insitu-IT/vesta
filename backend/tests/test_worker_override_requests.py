"""Unsupported per-backup concurrency must fail before any route allocates work."""

import pytest
from pydantic import ValidationError

from schemas.models import (
    BackupCreate,
    BackupQueueCreate,
    BulkBackupCreate,
    ScheduleCreate,
    ScheduleUpdate,
)

REQUESTS = [
    (BackupCreate, {"vm_id": "never-allocated"}),
    (BackupQueueCreate, {"vm_id": "never-allocated"}),
    (BulkBackupCreate, {"vm_ids": ["never-allocated"]}),
    (
        ScheduleCreate,
        {"name": "paused", "vm_id": "never-allocated", "cron_expression": "0 1 * * *"},
    ),
    (ScheduleUpdate, {}),
]


@pytest.mark.parametrize("model,payload", REQUESTS)
@pytest.mark.parametrize("workers", [False, True, 0, 1, 8, 256, "2", {}, []])
def test_non_null_workers_rejected(model, payload, workers):
    with pytest.raises(ValidationError) as error:
        model(**payload, workers=workers)
    assert error.value.errors()[0]["loc"] == ("workers",)
    assert (
        "Per-backup worker overrides are unsupported" in error.value.errors()[0]["msg"]
    )


@pytest.mark.parametrize("model,payload", REQUESTS)
def test_omitted_and_null_workers_allowed(model, payload):
    assert model(**payload).workers is None
    assert model(**payload, workers=None).workers is None


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("post", "/api/v1/backups", {"vm_id": "never-allocated"}),
        ("post", "/api/v1/backups/queue", {"vm_id": "never-allocated"}),
        ("post", "/api/v1/backups/bulk-create", {"vm_ids": ["never-allocated"]}),
        (
            "post",
            "/api/v1/schedules",
            {
                "name": "paused",
                "vm_id": "never-allocated",
                "cron_expression": "0 1 * * *",
            },
        ),
        ("put", "/api/v1/schedules/legacy", {"name": "unsubmitted"}),
    ],
)
def test_routes_refuse_workers_before_allocation(monkeypatch, method, path, payload):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from database import get_db
    from deps import get_operator_or_admin
    from routers import backups, bulk, queue, schedules
    from core.operator_requests import Admission

    db = Mock()
    allocation = Mock(
        side_effect=AssertionError("unsupported request reached allocation")
    )
    for module in (backups, bulk):
        monkeypatch.setattr(module, "BackupService", allocation)
    for module in (backups, queue):
        monkeypatch.setattr(module, "_add_to_queue_flush", allocation)
    for module in (backups, bulk, queue):
        monkeypatch.setattr(module, "begin_admission", allocation)
    monkeypatch.setattr(Admission, "dispatch", allocation)
    monkeypatch.setattr(bulk, "_resolve_bulk_vm_ids", allocation)
    monkeypatch.setattr(schedules, "revoke_grant_flush", allocation)
    app = FastAPI()
    for module in (backups, bulk, queue, schedules):
        app.include_router(module.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_operator_or_admin] = lambda: SimpleNamespace(
        id="operator", org_id="org"
    )
    with TestClient(app) as client:
        response = getattr(client, method)(path, json={**payload, "workers": 2})
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body", "workers"]
    assert "omit workers" in response.json()["detail"][0]["msg"]
    assert not db.method_calls
    allocation.assert_not_called()
