"""Exact operator plan validation before a migration-owner connection is opened."""

import copy

import pytest

from core.restore_cleanup_review import validate


def plan():
    return {
        "schema": 1,
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "restore_id": "22222222-2222-4222-8222-222222222222",
        "org_id": "org",
        "backup_id": "backup",
        "target_namespace": "test-vms",
        "target_vm_name": "recovered-vm",
        "target_pvc_names": ["data-a", "data-b"],
        "plan_sha256": "a" * 64,
        "result_sha256": "b" * 64,
        "journal_sha256": "c" * 64,
        "producer_quiescence_sha256": "d" * 64,
        "resource_quiescence_sha256": "e" * 64,
        "evidence_sha256": "f" * 64,
        "approved_by": "operator",
        "ticket": "change-1",
    }


def test_exact_review_plan():
    assert validate(plan())["target_pvc_names"] == ["data-a", "data-b"]


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema=True),
        lambda d: d.update(operation_id="wrong"),
        lambda d: d.update(journal_sha256="wrong"),
        lambda d: d.update(target_pvc_names=["data-b", "data-a"]),
        lambda d: d.update(target_pvc_names=["data-a", "data-a"]),
        lambda d: d.update(target_pvc_names=[]),
        lambda d: d.update(approved_by="  "),
        lambda d: d.update(extra="unsafe"),
        lambda d: d.pop("resource_quiescence_sha256"),
    ],
)
def test_malformed_review_refused(change):
    document = copy.deepcopy(plan())
    change(document)
    with pytest.raises(ValueError):
        validate(document)
