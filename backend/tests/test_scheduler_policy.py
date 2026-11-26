"""Automatic-policy boundaries, without fabricated authority or lineage."""

from datetime import date, datetime, timedelta, timezone

import pytest

from core.scheduler_policy import (
    BackupPolicyError,
    decide_automatic,
    validate_mode,
    validate_policy,
)

POLICY = {"schema": 1, "full_every_days": 7, "max_incrementals": 6}
DAY = date(2026, 10, 7)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {**POLICY, "extra": 1},
        {**POLICY, "schema": True},
        {**POLICY, "schema": 2},
        {**POLICY, "full_every_days": True},
        {**POLICY, "full_every_days": 0},
        {**POLICY, "full_every_days": 36501},
        {**POLICY, "full_every_days": "7"},
        {**POLICY, "max_incrementals": True},
        {**POLICY, "max_incrementals": 0},
        {**POLICY, "max_incrementals": 256},
        {**POLICY, "max_incrementals": 1.5},
    ],
)
def test_policy_has_one_strict_shape(value):
    with pytest.raises(BackupPolicyError):
        validate_policy(value)


def test_validation_does_not_mutate_or_return_the_input():
    value = dict(POLICY)
    result = validate_policy(value)
    assert result == value and result is not value


def test_no_usable_parent_requires_full():
    assert decide_automatic(POLICY, today=DAY) == {
        "backup_type": "full",
        "reason": "parent_unavailable",
    }


@pytest.mark.parametrize(
    "facts",
    [
        {"today": datetime(2026, 10, 7, tzinfo=timezone.utc)},
        {"today": DAY, "root_date": DAY},
        {"today": DAY, "incremental_count": 0},
        {"today": DAY, "root_date": DAY, "incremental_count": True},
        {"today": DAY, "root_date": DAY, "incremental_count": -1},
        {"today": DAY, "root_date": DAY, "incremental_count": "0"},
        {"today": DAY, "root_date": DAY + timedelta(days=1), "incremental_count": 0},
    ],
)
def test_unknown_parent_facts_do_not_become_a_reseed(facts):
    with pytest.raises(BackupPolicyError):
        decide_automatic(POLICY, **facts)


def test_full_interval_is_inclusive_at_the_utc_day_boundary():
    policy = {**POLICY, "max_incrementals": 255}
    assert (
        decide_automatic(
            policy, today=DAY + timedelta(days=6), root_date=DAY, incremental_count=1
        )["backup_type"]
        == "incremental"
    )
    assert decide_automatic(
        policy, today=DAY + timedelta(days=7), root_date=DAY, incremental_count=1
    ) == {"backup_type": "full", "reason": "full_interval"}


def test_chain_bound_takes_precedence_when_both_limits_are_due():
    assert decide_automatic(
        POLICY, today=DAY + timedelta(days=7), root_date=DAY, incremental_count=6
    ) == {"backup_type": "full", "reason": "max_incrementals"}


def test_weekly_full_then_six_daily_incrementals_then_new_full():
    root, count, kinds = None, None, []
    for offset in range(8):
        day = DAY + timedelta(days=offset)
        decision = decide_automatic(
            POLICY, today=day, root_date=root, incremental_count=count
        )
        kinds.append(decision["backup_type"])
        if decision["backup_type"] == "full":
            root, count = day, 0
        else:
            count += 1
    assert kinds == ["full", *(["incremental"] * 6), "full"]


def test_maximum_policy_reseeds_before_exceeding_restore_bound():
    from core.storage_restore import MAX_CHAIN_MEMBERS

    policy = {**POLICY, "max_incrementals": MAX_CHAIN_MEMBERS - 1}
    assert validate_policy(policy)["max_incrementals"] == 255
    assert (
        decide_automatic(policy, today=DAY, root_date=DAY, incremental_count=255)[
            "backup_type"
        ]
        == "full"
    )


@pytest.mark.parametrize("mode", ["full", "incremental"])
def test_fixed_modes_do_not_accept_an_automatic_policy(mode):
    assert validate_mode(mode, None) is None
    with pytest.raises(BackupPolicyError):
        validate_mode(mode, POLICY)


def test_create_schema_requires_explicit_policy_for_automatic_mode():
    from schemas import ScheduleCreate, ScheduleUpdate
    from pydantic import ValidationError

    fields = dict(name="daily", vm_id="test-vm", cron_expression="0 2 * * *")
    assert ScheduleCreate(**fields).backup_policy is None
    with pytest.raises(ValidationError):
        ScheduleCreate(**fields, backup_type="automatic")
    with pytest.raises(ValidationError):
        ScheduleCreate(**fields, backup_type="incremental", backup_policy=POLICY)
    request = ScheduleCreate(**fields, backup_type="automatic", backup_policy=POLICY)
    assert request.backup_policy == POLICY and request.enabled is False
    with pytest.raises(ValidationError):
        ScheduleUpdate(backup_policy={**POLICY, "max_incrementals": True})
