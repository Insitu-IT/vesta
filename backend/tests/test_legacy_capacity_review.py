"""Private historical-capacity plan validation before any database connection."""

from copy import deepcopy

import pytest

from core.legacy_capacity_review import validate


def sample():
    return {
        "schema": 1,
        "reviews": [
            {
                "schema": 1,
                "operation_id": "77777777-7777-4777-8777-777777777777",
                "backup_id": "backup-1",
                "org_id": "org-1",
                "vm_id": "vm-1",
                "capacity_id": "88888888-8888-4888-8888-888888888888",
                "classification": "uncertain",
                "evidence_sha256": "a" * 64,
                "approved_by": "operator",
                "ticket": "TEST-ONLY",
            }
        ],
    }


def test_valid_held_and_release_shapes():
    plan = sample()
    held = plan["reviews"][0]
    assert validate(plan) == [held]
    released = dict(
        held,
        operation_id="99999999-9999-4999-8999-999999999999",
        classification="released",
        producer_quiescence_sha256="b" * 64,
        chain_custody_sha256="c" * 64,
        object_custody_sha256="d" * 64,
    )
    plan["reviews"].append(released)
    assert validate(plan) == [held, released]


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(schema=True),
        lambda p: p["reviews"][0].update(classification="released"),
        lambda p: p["reviews"][0].update(capacity_id="not-a-uuid"),
        lambda p: p["reviews"][0].update(evidence_sha256="short"),
        lambda p: p["reviews"][0].update(ticket=" "),
        lambda p: p["reviews"][0].update(extra="unreviewed"),
        lambda p: p["reviews"].append(deepcopy(p["reviews"][0])),
    ],
)
def test_invalid_or_ambiguous_plan_refused(change):
    plan = sample()
    change(plan)
    with pytest.raises(ValueError):
        validate(plan)
