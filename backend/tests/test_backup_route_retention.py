"""Retention survives capacity queueing inside one admission transaction.

Admission/database authority is isolated here and proved separately with restricted
PostgreSQL. This test checks the route's retained policy and original actor.
"""

import json
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import BackgroundTasks
from fastapi.responses import JSONResponse
import pytest

from schemas.models import BackupCreate


@pytest.mark.parametrize("requested,expected", [(None, 90), (7, 7)])
def test_capacity_queue_preserves_selected_retention(monkeypatch, requested, expected):
    from routers import backups

    db = object()
    service = SimpleNamespace(
        _create_backup_flush=Mock(
            return_value=SimpleNamespace(success=False, error_code=429)
        ),
        get_vm_name=Mock(return_value="disposable-test-vm"),
    )
    enqueue = Mock(return_value=SimpleNamespace(id="not-dispatched"))
    configured_default = Mock(return_value=90)
    monkeypatch.setattr(backups, "BackupService", lambda _: service)
    monkeypatch.setattr(backups, "_add_to_queue_flush", enqueue)
    request_id = "dc074d87-a588-4b79-b5cb-fc486195b8d8"
    actor = SimpleNamespace(id="original-actor", org_id="original-org", role="operator")
    admission = SimpleNamespace(
        replay=False,
        dispatch=Mock(),
        finish=Mock(
            side_effect=lambda body: JSONResponse(dict(body, request_id=request_id))
        ),
    )
    begin = Mock(return_value=admission)
    monkeypatch.setattr(backups, "begin_admission", begin)
    activity = Mock()
    monkeypatch.setattr(backups, "log_activity", activity)
    # Before the fix this attribute is unused and the null case queues30, not90.
    monkeypatch.setattr(
        backups, "get_default_retention_days", configured_default, raising=False
    )

    tasks = BackgroundTasks()
    intent = BackupCreate(vm_id="not-dispatched", retention_days=requested)
    response = backups.create_backup(intent, tasks, db, actor, request_id=request_id)
    result = json.loads(response.body)

    begin.assert_called_once_with(db, actor, "backup.create", intent, request_id)
    admission.finish.assert_called_once()
    admission.dispatch.assert_not_called()
    assert tasks.tasks == []
    assert result["request_id"] == request_id
    assert activity.call_args.kwargs["commit"] is False
    assert result["status"] == "queued"
    assert enqueue.call_args.kwargs["retention_days"] == expected
    assert enqueue.call_args.kwargs["created_by"] == "original-actor"
    if requested is None:
        configured_default.assert_called_once_with(db)
    else:
        configured_default.assert_not_called()
