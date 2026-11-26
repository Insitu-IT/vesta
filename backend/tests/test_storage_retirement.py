"""Only the exact reviewed DB release may be handed to the original agent."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_retirement import retirement_proof
from models import Backup, S3Publication, VM


def fixture(monkeypatch):
    request = json.loads(
        (
            Path(__file__).parents[2] / "agent/contracts/storage_semantic_valid.json"
        ).read_text()
    )
    journal_hash = "a" * 64
    operation_id = "11111111-1111-4111-8111-111111111111"
    capacity_id = "22222222-2222-4222-8222-222222222222"
    backup = SimpleNamespace(
        id=request["backup_id"],
        org_id=request["org_id"],
        vm_id=request["plan"]["source"]["vm_id"],
        status="failed",
        capacity_state="released",
        capacity_id=capacity_id,
        capacity_release={
            "schema": 1,
            "reason": "reviewed_modern_quiescence",
            "operation_id": operation_id,
            "capacity_id": capacity_id,
            "journal_sha256": journal_hash,
        },
        capacity_modern_reviews=[
            {
                "classification": "released",
                "operation_id": operation_id,
                "journal_sha256": journal_hash,
                "publication_ids": [request["reservation_id"]],
            }
        ],
    )
    vm = SimpleNamespace(agent_id=request["agent_id"], provider="kubevirt")
    publication = SimpleNamespace(
        id=request["reservation_id"],
        org_id=request["org_id"],
        kind="payload",
        state="deleted",
        expected_plan={"schema": 3, "transaction": request},
    )
    db = MagicMock()

    def query(model):
        result = MagicMock()
        result.filter_by.return_value = result
        result.populate_existing.return_value = result
        result.with_for_update.return_value = result
        result.one_or_none.return_value = {Backup: backup, VM: vm}.get(model)
        result.all.return_value = [publication] if model is S3Publication else []
        return result

    db.query.side_effect = query
    db.scalar.return_value = "b" * 64
    monkeypatch.setattr("core.storage_attempt_key._credential", lambda *args: None)
    binding = {key: request[key] for key in ("reservation_id", "plan_sha256")}
    binding.update(
        attempt_id=request["plan"]["attempt_id"], journal_sha256=journal_hash
    )
    return db, request, binding, backup, vm, publication


def test_exact_review_returns_nonsecret_bound_proof(monkeypatch):
    db, request, binding, *_ = fixture(monkeypatch)
    proof = retirement_proof(
        db, request["backup_id"], request["agent_id"], binding, ("api-key", "hash")
    )
    assert proof == {
        "schema": 1,
        "org_id": request["org_id"],
        "backup_id": request["backup_id"],
        "reservation_id": request["reservation_id"],
        "attempt_id": request["plan"]["attempt_id"],
        "plan_sha256": request["plan_sha256"],
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "capacity_id": "22222222-2222-4222-8222-222222222222",
        "journal_sha256": "a" * 64,
        "release_sha256": "b" * 64,
    }


def test_native_proof_requires_original_closed_inventory(monkeypatch):
    from core.native_inventory import digest

    db, _, _, backup, vm, publication = fixture(monkeypatch)
    request = json.loads(
        (
            Path(__file__).parents[2] / "agent/contracts/native_storage_examples.json"
        ).read_text()
    )[0]["request"]
    backup.id, backup.org_id = request["backup_id"], request["org_id"]
    backup.vm_id = request["plan"]["source"]["vm_id"]
    vm.agent_id, vm.provider = request["agent_id"], "libvirt"
    publication.id, publication.org_id = request["reservation_id"], request["org_id"]
    publication.expected_plan = {"schema": 3, "transaction": request}
    backup.capacity_modern_reviews[0]["publication_ids"] = [publication.id]
    intent = dict(
        backup_id=backup.id,
        org_id=backup.org_id,
        agent_id=vm.agent_id,
        attempt_id=request["plan"]["attempt_id"],
    )
    inventory = request["plan"]["source"]["inventory"]
    backup.native_job_intent = intent
    backup.native_inventory = dict(
        intent_sha256=digest(intent),
        inventory=inventory,
        inventory_sha256=digest(inventory),
        push_result={"fixture": True},
    )
    calls = []
    monkeypatch.setattr(
        "core.native_manifest.bind_inventory", lambda *args: calls.append(args)
    )
    binding = dict(
        reservation_id=publication.id,
        attempt_id=intent["attempt_id"],
        plan_sha256=request["plan_sha256"],
        journal_sha256="a" * 64,
    )
    assert (
        retirement_proof(db, backup.id, vm.agent_id, binding, ("api-key", "hash"))[
            "backup_id"
        ]
        == backup.id
    )
    assert calls == [(backup.native_inventory["push_result"], inventory, intent)]
    backup.native_inventory = dict(backup.native_inventory, inventory_sha256="f" * 64)
    with pytest.raises(StorageOwnershipError):
        retirement_proof(db, backup.id, vm.agent_id, binding, ("api-key", "hash"))


@pytest.mark.parametrize(
    "change",
    [
        lambda f: f[2].update(journal_sha256="c" * 64),
        lambda f: setattr(f[3], "capacity_state", "reserved"),
        lambda f: setattr(f[4], "agent_id", "other"),
        lambda f: setattr(f[5], "state", "reserved"),
        lambda f: f[3].capacity_modern_reviews[0].update(publication_ids=["other"]),
        lambda f: f[3].capacity_release.update(reason="ordinary_release"),
        lambda f: f[2].update(extra="forged"),
    ],
)
def test_missing_or_mismatched_release_refused(monkeypatch, change):
    state = fixture(monkeypatch)
    change(state)
    db, request, binding, *_ = state
    with pytest.raises(StorageOwnershipError):
        retirement_proof(
            db, request["backup_id"], request["agent_id"], binding, ("api-key", "hash")
        )
