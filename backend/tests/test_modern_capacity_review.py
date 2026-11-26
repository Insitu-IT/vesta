"""Plan-schema checks before a migration-owner connection is opened."""

import copy

import pytest

from core.modern_capacity_review import validate


def plan(classification="released"):
    review = {
        "schema": 1,
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "backup_id": "backup",
        "org_id": "org",
        "vm_id": "vm",
        "capacity_id": "22222222-2222-4222-8222-222222222222",
        "classification": classification,
        "evidence_sha256": "a" * 64,
        "approved_by": "operator",
        "ticket": "change-1",
    }
    if classification == "released":
        review.update(
            {
                "producer_quiescence_sha256": "b" * 64,
                "chain_custody_sha256": "c" * 64,
                "object_custody_sha256": "d" * 64,
                "journal_sha256": "e" * 64,
                "publication_ids": ["publication-a", "publication-b"],
            }
        )
    return {"schema": 1, "reviews": [review]}


def test_exact_release_plan():
    assert validate(plan())[0]["classification"] == "released"


@pytest.mark.parametrize("classification", ["uncertain", "occupied"])
def test_held_plan_requires_no_release_fields(classification):
    assert validate(plan(classification))[0]["classification"] == classification


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["reviews"][0].update(journal_sha256="wrong"),
        lambda d: d["reviews"][0].update(
            publication_ids=["publication-b", "publication-a"]
        ),
        lambda d: d["reviews"][0].update(
            publication_ids=["publication-a", "publication-a"]
        ),
        lambda d: d["reviews"][0].update(operation_id="WRONG"),
        lambda d: d["reviews"][0].update(extra="field"),
        lambda d: d["reviews"].append(copy.deepcopy(d["reviews"][0])),
        lambda d: d.update(schema=True),
    ],
)
def test_malformed_release_refused(change):
    document = plan()
    change(document)
    with pytest.raises(ValueError):
        validate(document)


def test_held_plan_cannot_carry_release_fields():
    document = plan("uncertain")
    document["reviews"][0]["journal_sha256"] = "e" * 64
    with pytest.raises(ValueError):
        validate(document)
