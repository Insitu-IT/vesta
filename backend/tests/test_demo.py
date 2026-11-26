from datetime import datetime, timezone

import pytest
from demo.executor import (
    DemoExecutionError,
    backup_plan,
    restore_plan,
    retry_upload_plan,
)
from demo.fixture import FIXTURE_VERSION, assert_public_fixture, build_fixture

NOW = datetime(2026, 8, 24, 5, 0, tzinfo=timezone.utc)


def test_fixture_is_deterministic_and_self_describing():
    first = build_fixture(NOW).as_dict()
    second = build_fixture(NOW).as_dict()

    assert first == second
    assert first["fixture_version"] == FIXTURE_VERSION
    assert first["environment"] == "demo"
    assert first["simulated"] is True
    assert len(first["agents"]) == 2
    assert len(first["vms"]) == 12
    assert first["persona"]["hands_on"] == "single-tenant backup operator"
    assert first["persona"]["msp_context"] == "guided-only"


def test_fixture_relations_and_incremental_chain_are_valid():
    fixture = build_fixture(NOW).as_dict()
    agent_ids = {agent["id"] for agent in fixture["agents"]}
    vm_ids = {vm["id"] for vm in fixture["vms"]}
    backup_by_id = {backup["id"]: backup for backup in fixture["backups"]}

    assert all(vm["agent_id"] in agent_ids for vm in fixture["vms"])
    assert all(backup["vm_id"] in vm_ids for backup in fixture["backups"])

    incrementals = [
        backup
        for backup in fixture["backups"]
        if backup["backup_type"] == "incremental"
    ]
    assert [backup["chain_position"] for backup in incrementals] == [1, 2]
    for backup in incrementals:
        parent = backup_by_id[backup["parent_backup_id"]]
        assert parent["status"] == "completed"
        assert parent["chain_id"] == backup["chain_id"]


def test_fixture_rejects_internal_markers():
    with pytest.raises(ValueError, match="prohibited marker"):
        assert_public_fixture(
            {"endpoint": "https://" + "data" + "01" + ".insitu" + ".local"}
        )


def test_incremental_is_explicitly_refused_without_capability():
    with pytest.raises(DemoExecutionError) as exc:
        backup_plan(
            "operation-1",
            "incremental",
            supports_incremental=False,
            has_completed_parent=True,
        )

    assert exc.value.code == "INCREMENTAL_UNSUPPORTED"
    assert "no full backup was started" in str(exc.value)


def test_incremental_is_explicitly_refused_without_parent():
    with pytest.raises(DemoExecutionError) as exc:
        backup_plan(
            "operation-1",
            "incremental",
            supports_incremental=True,
            has_completed_parent=False,
        )

    assert exc.value.code == "INCREMENTAL_PARENT_REQUIRED"
    assert "no full backup was started" in str(exc.value)


def test_backup_failure_retry_and_restore_are_universally_marked():
    failure = backup_plan(
        "operation-2",
        "full",
        supports_incremental=True,
        has_completed_parent=False,
        scenario="upload_failure",
    )
    retry = retry_upload_plan()
    restore = restore_plan(backup_status="completed")
    events = failure + retry + restore

    assert failure[-1].status == "upload_failed"
    assert retry[-1].status == "completed"
    assert restore[-1].status == "completed"
    assert "no VM or disk was changed" in restore[-1].message
    assert all(event.simulated is True for event in events)
    assert all(event.environment == "demo" for event in events)


def test_restore_refuses_incomplete_backup():
    with pytest.raises(DemoExecutionError) as exc:
        restore_plan(backup_status="upload_failed")
    assert exc.value.code == "RESTORE_POINT_NOT_READY"
