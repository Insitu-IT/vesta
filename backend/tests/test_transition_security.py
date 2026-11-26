"""Reference custody/shape controls; PostgreSQL deparser behavior needs PG CI."""

import hashlib
import json
from unittest.mock import MagicMock

import pytest

from core import transition_security as subject


def test_reference_hash_bound_and_bounded(tmp_path):
    path = tmp_path / "reference.json"
    raw = b'{"contract":"test"}'
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert subject.load_reference(path, digest) == {"contract": "test"}
    path.write_bytes(raw + b" ")
    with pytest.raises(ValueError):
        subject.load_reference(path, digest)
    path.write_bytes(b" " * (subject.LIMIT + 1))
    with pytest.raises(ValueError):
        subject.load_reference(path, hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize(
    "field", ["contract", "head", "migrations_sha256", "postgres_major", "objects"]
)
def test_reference_version_and_migration_refusal_before_inventory(monkeypatch, field):
    monkeypatch.setattr(
        subject, "migration_identity", lambda: ("head", "digest", set())
    )
    reference = dict(
        contract="vnbui-installed-security/2",
        head="head",
        migrations_sha256="digest",
        postgres_major=16,
        reference_database="reference",
        reference_database_oid=12,
        reference_system_identifier="7000000000000000001",
        objects={key: {} for key in subject.QUERIES},
    )
    reference[field] = {} if field == "objects" else "different"
    connection = MagicMock()
    connection.scalar.return_value = "160001"
    observe = MagicMock(
        side_effect=AssertionError("No target inventory before reference admission")
    )
    monkeypatch.setattr(subject, "snapshot", observe)
    with pytest.raises(ValueError):
        subject.compare_installed(connection, reference)
    observe.assert_not_called()


def test_canonical_encoding_is_order_independent():
    assert subject.canonical({"a": 1, "b": 2}) == subject.canonical({"b": 2, "a": 1})
    assert json.loads(subject.canonical({"a": 1})) == {"a": 1}


@pytest.mark.parametrize("rows", [[("x",)] * 4097, [("x" * (subject.LIMIT + 1),)]])
def test_catalog_inventory_bounds_refuse(rows):
    connection = MagicMock()
    connection.execute.return_value.fetchmany.return_value = rows
    with pytest.raises(ValueError, match="bound"):
        subject.snapshot(connection)


def test_definitions_never_appear_in_reference_findings():
    connection = MagicMock()
    marker = "private_function_body_or_policy_literal"
    connection.execute.return_value.fetchmany.return_value = [(marker,)]
    result = subject.snapshot(connection)
    assert marker not in json.dumps(result)
    assert all(
        value["count"] == 1 and len(value["sha256"]) == 64 for value in result.values()
    )


@pytest.mark.parametrize(
    "cluster,oid,name,rejected",
    [
        ("7000000000000000001", 12, "reference", True),
        ("7000000000000000001", 12, "renamed", True),
        ("7000000000000000001", 13, "other", False),
        ("7000000000000000002", 12, "reference", False),
        ("7000000000000000002", 13, "reference", False),
    ],
)
def test_scoped_identity_collision_and_true_self_reference(
    monkeypatch, cluster, oid, name, rejected
):
    # Independently captured catalogs through connection doubles: no claim of
    # running two PostgreSQL clusters. Real same-cluster checks are in PG CI.
    monkeypatch.setattr(
        subject, "migration_identity", lambda: ("head", "digest", set())
    )
    reference_connection = MagicMock()
    reference_connection.execute.return_value.scalars.return_value = ["head"]
    reference_connection.execute.return_value.one.return_value = ("reference", 12)
    reference_connection.scalar.side_effect = ["160001", "7000000000000000001"]
    inventory = {key: {"count": 1, "sha256": "a" * 64} for key in subject.QUERIES}
    observe = MagicMock(return_value=inventory)
    monkeypatch.setattr(subject, "snapshot", observe)
    reference = subject.capture_reference(reference_connection)
    observe.reset_mock()
    target = MagicMock()
    target.execute.return_value.one.return_value = (name, oid)
    target.scalar.side_effect = ["160001", cluster]
    if rejected:
        with pytest.raises(ValueError, match="own security reference"):
            subject.compare_installed(target, reference)
        observe.assert_not_called()
    else:
        assert all(
            item["count"] == 0 for item in subject.compare_installed(target, reference)
        )
        observe.assert_called_once_with(target)


def test_cluster_identity_permission_failure_never_compares(monkeypatch):
    monkeypatch.setattr(
        subject, "migration_identity", lambda: ("head", "digest", set())
    )
    reference = {
        "contract": "vnbui-installed-security/2",
        "head": "head",
        "migrations_sha256": "digest",
        "postgres_major": 16,
        "reference_database": "reference",
        "reference_database_oid": 12,
        "reference_system_identifier": "7000000000000000001",
        "objects": {key: {} for key in subject.QUERIES},
    }
    connection = MagicMock()
    connection.execute.return_value.one.return_value = ("target", 13)
    connection.scalar.side_effect = ["160001", PermissionError("identity unavailable")]
    observe = MagicMock()
    monkeypatch.setattr(subject, "snapshot", observe)
    with pytest.raises(PermissionError):
        subject.compare_installed(connection, reference)
    observe.assert_not_called()
