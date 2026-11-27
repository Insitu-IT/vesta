"""Saved policy decisions cannot be reinterpreted during custody lookup."""

from copy import deepcopy
from datetime import date
from unittest.mock import Mock, call
from types import SimpleNamespace

import pytest

from core.scheduler_policy import BackupPolicyError
from core.scheduler_policy_decision import (
    choose_for_claim,
    resolved_options,
    validate_decision,
)

POLICY = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
OPTIONS = dict(
    backup_type="automatic",
    backup_policy=POLICY,
    retention_days=30,
    workers=None,
    exclude_disks=[],
)
DECISION = dict(
    schema=1,
    policy=POLICY,
    backup_type="incremental",
    reason="within_policy",
    observed_date="2026-10-14",
    root_date="2026-10-13",
    incremental_count=1,
    generation_id="cf5e5296-bfcb-4127-a847-3351c72eac0f",
    root_backup_id="edb5145e-0a8e-45d0-9f2a-06fac9b8dc5a",
)


def test_saved_kind_resolves_without_recomputing_at_a_later_date():
    assert validate_decision(DECISION, POLICY) == DECISION
    options = resolved_options(OPTIONS, DECISION, claimed=True)
    assert options == dict(
        backup_type="incremental", retention_days=30, workers=None, exclude_disks=[]
    )
    assert (
        OPTIONS["backup_type"] == "automatic"
        and DECISION["backup_type"] == "incremental"
    )
    assert "backup_policy" not in options


@pytest.mark.parametrize(
    "change",
    [
        {"schema": True},
        {"schema": 2},
        {"extra": None},
        {"reason": "guessed"},
        {"incremental_count": True},
        {"incremental_count": "1"},
        {"root_date": "2026-10-15"},
        {"observed_date": "20261014"},
        {"observed_date": None},
        {"generation_id": None},
        {"backup_type": "full"},
        {"reason": "previous_failure"},
        {"policy": {**POLICY, "max_incrementals": 5}},
    ],
)
def test_saved_decision_rejects_mutated_or_incomplete_facts(change):
    with pytest.raises(BackupPolicyError):
        validate_decision(dict(DECISION, **change), POLICY)


def test_unclaimed_queue_keeps_mode_but_not_a_policy_model_attribute():
    assert resolved_options(OPTIONS) == dict(
        backup_type="automatic", retention_days=30, workers=None, exclude_disks=[]
    )
    with pytest.raises(BackupPolicyError):
        resolved_options(OPTIONS, DECISION)
    with pytest.raises(BackupPolicyError):
        resolved_options(OPTIONS, claimed=True)


@pytest.mark.parametrize("mode", ["full", "incremental"])
def test_fixed_grant_does_not_acquire_automatic_authority(mode):
    options = dict(backup_type=mode, retention_days=30, workers=None, exclude_disks=[])
    assert resolved_options(options, claimed=True) == options
    with pytest.raises(BackupPolicyError):
        resolved_options(options, DECISION, claimed=True)


def test_absent_current_head_can_choose_full_but_query_failure_cannot():
    db = Mock()
    db.query.return_value.filter_by.return_value.populate_existing.return_value.one_or_none.return_value = (
        None
    )
    args = dict(
        org_id="org",
        vm_id="vm",
        grant_id="grant",
        source_snapshot={},
        policy=POLICY,
        today=date(2026, 10, 14),
    )
    decision = choose_for_claim(db, **args)
    assert (
        decision["backup_type"] == "full" and decision["reason"] == "parent_unavailable"
    )
    assert decision["generation_id"] is None and decision["root_backup_id"] is None
    db.query.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        choose_for_claim(db, **args)


def test_decision_copy_does_not_mutate_original_sealed_policy():
    decision = validate_decision(deepcopy(DECISION), POLICY)
    decision["policy"]["max_incrementals"] = 5
    assert (
        POLICY["max_incrementals"] == 6 and DECISION["policy"]["max_incrementals"] == 6
    )


@pytest.mark.parametrize(
    "authority,decision",
    [("human", None), ("scheduler", None), ("scheduler", DECISION)],
)
def test_backup_detail_reports_saved_decision_without_recomputing(authority, decision):
    from routers.backups import get_backup
    from models import Backup, BackupQueue, OperatorDispatch, OperatorRequest

    backup = SimpleNamespace(
        id="backup",
        org_id="organization",
        vm_id="vm",
        vm=SimpleNamespace(name="source"),
        authority_kind=authority,
        scheduler_occurrence_id="occurrence",
        status="completed",
        progress=100,
        storage_progress=None,
        size_bytes=1,
        retention_days=30,
        backup_type="incremental",
        storage_path="s3://fixture/backup",
        tags={},
        created_at=None,
        completed_at=None,
    )
    db = Mock()
    backups, queues, dispatches = Mock(), Mock(), Mock()

    def query(*models):
        if models == (Backup,):
            return backups
        if models == (BackupQueue,):
            return queues
        assert len(models) == 2 and models[0] is OperatorDispatch
        assert models[1] is OperatorRequest.request_id
        return dispatches

    db.query.side_effect = query
    db.execute.return_value.one_or_none.return_value = None
    dispatches.join.return_value.filter.return_value.all.return_value = []
    backups.filter.return_value.first.return_value = backup
    queues.filter_by.return_value.one_or_none.return_value = SimpleNamespace(
        backup_decision=decision
    )
    response = get_backup(backup.id, db, current_user=object())
    assert response["scheduler_decision"] == decision
    assert response["recovery_publication"] is None
    if authority == "scheduler":
        queues.filter_by.assert_called_once_with(
            started_backup_id=backup.id,
            scheduler_occurrence_id="occurrence",
            vm_id="vm",
        )
        assert db.query.call_args_list.count(call(BackupQueue)) == 1
    else:
        queues.filter_by.assert_not_called()
