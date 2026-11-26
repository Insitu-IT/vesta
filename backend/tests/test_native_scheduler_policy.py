"""Automatic parent drift must refuse before native producer-side effects."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core import native_job
from core.native_manifest import FORMAT
from core.s3_ownership import StorageOwnershipError
from models import BackupQueue
from backend.tests.test_scheduler_scope import scope  # noqa: F401
from backend.tests.test_scheduler_policy_decision import DECISION, POLICY


@pytest.fixture
def saved(scope):  # noqa: F811
    scope["options"].update(backup_type="automatic", backup_policy=deepcopy(POLICY))
    backup = SimpleNamespace(
        id="backup",
        org_id=scope["org_id"],
        vm_id=scope["members"][0]["vm_id"],
        authority_kind="scheduler",
        scheduler_occurrence_id="occurrence",
        backup_type="incremental",
        native_job_intent=None,
        native_job_transaction_id="transaction",
        encryption_key_id=None,
    )
    queue = SimpleNamespace(
        status="claimed", backup_type="incremental", backup_decision=deepcopy(DECISION)
    )
    grant = SimpleNamespace(scope=scope)
    db, queues, grants = Mock(), Mock(), Mock()
    db.query.side_effect = lambda model: queues if model is BackupQueue else grants
    queues.filter_by.return_value.one_or_none.return_value = queue
    grants.join.return_value.filter.return_value.one_or_none.return_value = grant
    return SimpleNamespace(db=db, backup=backup, queue=queue, grant=grant)


def test_native_saved_parent_must_match_before_effects(saved):
    native_job._scheduler_parent(
        saved.db, saved.backup, {"generation_id": DECISION["generation_id"]}
    )
    for parent in (None, {}, {"generation_id": "another-generation"}):
        with pytest.raises(StorageOwnershipError):
            native_job._scheduler_parent(saved.db, saved.backup, parent)


@pytest.mark.parametrize("mutation", ["held", "kind", "decision", "policy"])
def test_native_policy_custody_drift_refuses(saved, mutation):
    if mutation == "held":
        saved.queue.status = "held_claimed"
    elif mutation == "kind":
        saved.backup.backup_type = "full"
    elif mutation == "decision":
        saved.queue.backup_decision = None
    else:
        saved.grant.scope["options"]["backup_policy"]["max_incrementals"] = 5
    with pytest.raises(StorageOwnershipError):
        native_job._scheduler_parent(
            saved.db, saved.backup, {"generation_id": DECISION["generation_id"]}
        )


def test_fixed_incremental_does_not_need_automatic_policy(saved):
    saved.grant.scope["options"]["backup_type"] = "incremental"
    saved.grant.scope["options"].pop("backup_policy")
    saved.queue.backup_decision = None
    native_job._scheduler_parent(
        saved.db, saved.backup, {"generation_id": "ordinary-selected-parent"}
    )


def test_parent_drift_does_not_allocate_native_intent_or_encryption(saved, monkeypatch):
    source = dict(backup_type="incremental", parent_backup_id=None)
    monkeypatch.setattr(
        native_job, "admit", lambda *_: (saved.backup, None, Mock(), source)
    )
    monkeypatch.setattr(
        "core.native_lineage.select_parent",
        lambda *_: ({"generation_id": "changed"}, {}),
    )
    encryption = Mock(side_effect=AssertionError("Must refuse before key preparation"))
    monkeypatch.setattr("core.storage_encryption.select_encryption", encryption)
    with pytest.raises(StorageOwnershipError):
        native_job.prepare_job(saved.db, saved.backup.id)
    assert saved.backup.native_job_intent is None
    encryption.assert_not_called()
    saved.db.commit.assert_not_called()
    saved.db.rollback.assert_called_once()


def test_readmission_rejects_even_a_current_intent_with_a_different_saved_parent(
    saved, monkeypatch
):
    source = dict(backup_type="incremental", parent_backup_id=None)
    agent = SimpleNamespace(id="agent")
    target = dict(capability_profile="db-rooted-consumer-verified/1", region="test")
    encryption = dict(format="none", key_ref=None)
    parent = {"generation_id": "changed"}
    intent = dict(
        source=source,
        actor_id=None,
        agent_id=agent.id,
        producer=FORMAT,
        attempt_id="attempt",
        checkpoint="vnbui-attempt",
        target=target,
        encryption=encryption,
        parent=parent,
        push_parent={},
    )
    saved.backup.native_job_intent = intent
    monkeypatch.setattr(
        native_job, "admit", lambda *_: (saved.backup, None, agent, source)
    )
    monkeypatch.setattr("core.storage_dispatch.read_target", lambda *_: target)
    monkeypatch.setattr(
        "core.storage_encryption.select_encryption", lambda *_: encryption
    )
    monkeypatch.setattr("core.native_lineage.select_parent", lambda *_: (parent, {}))
    with pytest.raises(StorageOwnershipError):
        native_job.readmit_job(saved.db, saved.backup.id, intent)
    assert saved.backup.native_job_intent == intent
    saved.db.commit.assert_not_called()
