"""Reject invalid retention before API routes can admit or queue any work."""

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
    (BackupCreate, {"vm_id": "not-submitted"}),
    (BackupQueueCreate, {"vm_id": "not-submitted"}),
    (BulkBackupCreate, {"vm_ids": ["not-submitted"]}),
    (
        ScheduleCreate,
        {
            "name": "not-submitted",
            "vm_id": "not-submitted",
            "cron_expression": "0 1 * * *",
        },
    ),
    (ScheduleUpdate, {}),
]


@pytest.mark.parametrize("model,payload", REQUESTS)
@pytest.mark.parametrize("days", [-1, 0, 36501])
def test_invalid_retention_refused(model, payload, days):
    with pytest.raises(ValidationError) as error:
        model(**payload, retention_days=days)
    assert error.value.errors()[0]["loc"] == ("retention_days",)


@pytest.mark.parametrize("model,payload", REQUESTS)
@pytest.mark.parametrize("days", [1, 30, 36500])
def test_supported_retention_boundaries(model, payload, days):
    assert model(**payload, retention_days=days).retention_days == days


@pytest.mark.parametrize("model,payload", REQUESTS)
def test_omission_preserves_create_default_or_patch_no_change(model, payload):
    assert model(**payload).retention_days == (None if model is ScheduleUpdate else 30)


def test_queue_cannot_persist_null_retention():
    with pytest.raises(ValidationError):
        BackupQueueCreate(vm_id="not-submitted", retention_days=None)


@pytest.mark.parametrize("model,payload", [REQUESTS[0], REQUESTS[-1]])
def test_explicit_null_preserves_default_selection_or_patch_no_change(model, payload):
    assert model(**payload, retention_days=None).retention_days is None
