"""Closed negative wire evidence never infers release from absence/error text."""

from copy import deepcopy
import pytest

from core.native_inventory import digest
from core.native_no_effect import validate
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical


def specimen():
    intent = {
        "backup_id": "backup",
        "attempt_id": "attempt",
        "source": {"domain_uuid": "domain"},
    }
    refusal = dict(
        schema="libvirt-prebegin-refusal/1",
        backup_id="backup",
        attempt_id="attempt",
        domain_uuid="domain",
        request_sha256="a" * 64,
        reason="another hypervisor job is active",
    )
    return intent, dict(
        intent_canonical=canonical(intent).decode(),
        intent_sha256=digest(intent),
        refusal_canonical=canonical(refusal).decode(),
        refusal_sha256=digest(refusal),
    )


def test_exact_positive_refusal():
    intent, value = specimen()
    validate(value, intent)
    assert value == specimen()[1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("intent_sha256", "0" * 64),
        ("refusal_sha256", "0" * 64),
        ("intent_canonical", "{}"),
        ("refusal_canonical", "{}"),
        ("extra", "unexpected"),
        ("intent_sha256", None),
    ],
)
def test_unbound_or_unknown_evidence_refused(field, value):
    intent, body = specimen()
    body[field] = value
    with pytest.raises(StorageOwnershipError):
        validate(body, intent)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "libvirt-begin-intent/1"),
        ("attempt_id", "other"),
        ("domain_uuid", "other"),
        ("reason", ""),
        ("reason", None),
        ("reason", "x" * 2049),
        ("request_sha256", "invalid"),
        ("extra", True),
    ],
)
def test_rehashed_wrong_refusal_still_refused(field, value):
    import json

    intent, body = specimen()
    refusal = json.loads(body["refusal_canonical"])
    refusal[field] = value
    body.update(
        refusal_canonical=canonical(refusal).decode(), refusal_sha256=digest(refusal)
    )
    with pytest.raises(StorageOwnershipError):
        validate(body, intent)


def test_noncanonical_duplicate_field_refused():
    intent, body = specimen()
    body = deepcopy(body)
    body["refusal_canonical"] = (
        body["refusal_canonical"][:-1] + ',"reason":"replacement"}'
    )
    with pytest.raises(StorageOwnershipError):
        validate(body, intent)


def test_capacity_guard_is_inserted_before_review_early_returns_not_nested_begin():
    import importlib.util
    from pathlib import Path

    versions = Path(__file__).resolve().parents[1] / "alembic/versions"

    def load(filename):
        spec = importlib.util.spec_from_file_location(filename, versions / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    prior = load("20260923_capacity_prerequisite.py").FUNCTIONS["vnbui_capacity_owner"]
    migration = load("20261014_native_no_effect.py")
    # The platform-read exception block includes another, indented BEGIN.
    assert prior.count("BEGIN\n") > 1
    composed = migration.owner_sql(prior)
    assert composed.index(migration.GUARD) < composed.index("IF TG_OP='DELETE'")
    assert composed.replace(migration.GUARD, "", 1) == prior
    with pytest.raises(RuntimeError):
        migration.owner_sql(prior + "\nBEGIN\n")


def test_capacity_guard_references_real_backup_columns():
    import importlib.util
    from pathlib import Path
    import re
    from models import Backup

    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/20261014_native_no_effect.py"
    )
    spec = importlib.util.spec_from_file_location("native_no_effect_guard", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    fields = set(re.findall(r"\b(?:NEW|OLD)\.([a-z_][a-z0-9_]*)", migration.GUARD))
    assert fields and fields <= set(Backup.__table__.columns.keys())
    assert "NEW.tags:=" in migration.GUARD


@pytest.mark.parametrize("validation_fails", [False, True])
def test_upgrade_validates_deferred_events_before_alter(monkeypatch, validation_fails):
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace

    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/20261014_native_no_effect.py"
    )
    spec = importlib.util.spec_from_file_location("native_no_effect_order", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    calls = []

    def execute(sql):
        calls.append(("execute", sql))
        if validation_fails:
            raise RuntimeError("deferred constraint refused")

    monkeypatch.setattr(migration.op, "execute", execute)
    monkeypatch.setattr(
        migration.op, "add_column", lambda *args: calls.append(("alter", args))
    )
    monkeypatch.setattr(
        migration.op,
        "get_bind",
        lambda: SimpleNamespace(scalar=lambda _: "CREATE FUNCTION owner()\nBEGIN\nEND"),
    )
    if validation_fails:
        with pytest.raises(RuntimeError, match="deferred constraint refused"):
            migration.upgrade()
        assert len(calls) == 1
    else:
        migration.upgrade()
        assert [kind for kind, _ in calls] == ["execute", "alter", "execute"]
        assert migration.GUARD in calls[-1][1]
    assert calls[0] == ("execute", "SET CONSTRAINTS ALL IMMEDIATE")
