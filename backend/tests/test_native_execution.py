"""Actual producer requests cannot move to a new execution namespace on replay."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.native_inventory import digest
from core.native_job import bind_execution
from core.s3_ownership import StorageOwnershipError


def specimen():
    intent = dict(
        backup_id="backup", attempt_id="attempt", source={"domain_uuid": "domain"}
    )
    backup = SimpleNamespace(
        native_job_intent=intent, native_job_transaction_id=101, native_execution=None
    )
    value = dict(
        attempt_id="attempt",
        intent_sha256=digest(intent),
        producer_request_sha256="a" * 64,
    )
    return backup, value


def test_first_execution_and_identical_binding_preserve_database_identity():
    backup, value = specimen()
    bind_execution(backup, value)
    assert backup.native_execution["request_sha256"] == "a" * 64
    backup.native_execution["bound_xid"] = 102
    before = deepcopy(backup.native_execution)
    bind_execution(backup, value)
    assert backup.native_execution == before


@pytest.mark.parametrize("fault", ["request", "intent", "schema", "xid", "unknown"])
def test_changed_or_malformed_execution_cannot_be_adopted(fault):
    backup, value = specimen()
    bind_execution(backup, value)
    backup.native_execution["bound_xid"] = 102
    if fault == "request":
        value["producer_request_sha256"] = "b" * 64
    elif fault == "intent":
        backup.native_job_intent = dict(
            backup.native_job_intent, source={"domain_uuid": "replacement"}
        )
    elif fault == "schema":
        backup.native_execution["schema"] = 2
    elif fault == "xid":
        backup.native_execution["bound_xid"] = True
    else:
        backup.native_execution["unknown"] = True
    before = deepcopy(backup.native_execution)
    with pytest.raises(StorageOwnershipError):
        bind_execution(backup, value)
    assert backup.native_execution == before


@pytest.mark.parametrize("created", [None, 99, 100, True])
def test_existing_unknown_native_execution_stays_held(created):
    backup, value = specimen()
    backup.native_job_transaction_id = created
    backup.native_execution = dict(schema=1, state="preexisting", boundary_xid=100)
    before = deepcopy(backup.native_execution)
    with pytest.raises(StorageOwnershipError):
        bind_execution(backup, value)
    assert backup.native_execution == before


def test_preexisting_row_with_new_post_upgrade_intent_can_bind():
    backup, value = specimen()
    backup.native_execution = dict(schema=1, state="preexisting", boundary_xid=100)
    bind_execution(backup, value)
    assert backup.native_execution["state"] == "bound"
    assert backup.native_execution["request_sha256"] == value["producer_request_sha256"]
