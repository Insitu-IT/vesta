"""Failed writer closure is attributable termination, not successful data."""

from copy import deepcopy

import pytest

from core.native_closed_failure import validate
from core.native_inventory import digest
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical


def specimen():
    intent = {
        "backup_id": "backup",
        "attempt_id": "attempt",
        "source": {
            "domain_uuid": "domain",
            "disks": [{"target": "vda"}],
            "exclusions": [],
        },
    }
    closure = {
        "schema": "libvirt-closed-failure/1",
        "backup_id": "backup",
        "attempt_id": "attempt",
        "domain_uuid": "domain",
        "request_sha256": "a" * 64,
        "begin_ack_sha256": "b" * 64,
        "invocation_id": "c" * 32,
        "job_ids": ["backup-vda-node"],
        "terminal_events": [
            {"id": "backup-vda-node", "status": s}
            for s in ("created", "running", "aborting", "concluded", "null")
        ],
        "artifacts": [
            {
                "path": "vda.qcow2",
                "device": 10,
                "inode": 42,
                "size": 100,
                "mtime_ns": 123,
                "ctime_ns": 124,
            }
        ],
    }
    value = {
        "intent_canonical": canonical(intent).decode(),
        "intent_sha256": digest(intent),
        "closure_canonical": canonical(closure).decode(),
        "closure_sha256": digest(closure),
    }
    return intent, value, closure


def test_positive_closed_failure_is_not_success_or_no_effect():
    intent, value, closure = specimen()
    assert validate(value, intent) == closure
    assert value == specimen()[1]


def test_supported_128_disk_closure_is_not_truncated_to_64k():
    intent, value, closure = specimen()
    targets = [f"vd{n:03}" for n in range(128)]
    intent["source"]["disks"] = [dict(target=target) for target in targets]
    closure["job_ids"] = ["backup-" + target + "-" + "x" * 490 for target in targets]
    closure["terminal_events"] = [
        dict(id=job, status=state)
        for job in closure["job_ids"]
        for state in ("created", "running", "aborting", "concluded", "null")
    ]
    artifact = closure["artifacts"][0]
    closure["artifacts"] = [
        dict(artifact, path=target + ".qcow2", inode=n + 1)
        for n, target in enumerate(targets)
    ]
    value.update(
        intent_canonical=canonical(intent).decode(),
        intent_sha256=digest(intent),
        closure_canonical=canonical(closure).decode(),
        closure_sha256=digest(closure),
    )
    assert len(value["closure_canonical"]) > 64 * 1024
    assert validate(value, intent) == closure


def test_migration_composes_before_prior_guard_and_uses_real_columns():
    import importlib.util
    import re
    from pathlib import Path
    from models import Backup

    versions = Path(__file__).resolve().parents[1] / "alembic/versions"

    def load(filename):
        spec = importlib.util.spec_from_file_location(filename, versions / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    original = load("20260923_capacity_prerequisite.py").FUNCTIONS[
        "vnbui_capacity_owner"
    ]
    migration = load("20261016_native_closed_failure.py")
    composed = migration.owner_sql(original)
    assert composed.index(migration.GUARD) < composed.index("IF TG_OP='DELETE'")
    assert (
        composed.replace(migration.GUARD, "", 1).replace(migration.DECLARATIONS, "", 1)
        == original
    )
    fields = set(re.findall(r"\b(?:NEW|OLD)\.([a-z_][a-z0-9_]*)", migration.GUARD))
    assert fields <= set(Backup.__table__.columns.keys())
    with pytest.raises(RuntimeError):
        migration.owner_sql(original + "\nBEGIN\n")


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "backup",
        "attempt",
        "domain",
        "request",
        "ack",
        "invocation",
        "missing-created",
        "not-terminal",
        "reused-id",
        "foreign-id",
        "unknown-state",
        "duplicate-job",
        "missing-disk",
        "extra-artifact",
        "foreign-path",
        "boolean-inode",
        "zero-inode",
        "negative-size",
        "extra-field",
    ],
)
def test_rehashed_invalid_closure_is_refused(fault):
    intent, value, closure = specimen()
    if fault in {
        "schema",
        "backup",
        "attempt",
        "domain",
        "request",
        "ack",
        "invocation",
    }:
        field = {
            "backup": "backup_id",
            "attempt": "attempt_id",
            "domain": "domain_uuid",
            "request": "request_sha256",
            "ack": "begin_ack_sha256",
            "invocation": "invocation_id",
        }.get(fault, fault)
        closure[field] = "wrong"
    elif fault == "missing-created":
        closure["terminal_events"].pop(0)
    elif fault == "not-terminal":
        closure["terminal_events"].pop()
    elif fault == "reused-id":
        closure["terminal_events"].append(
            {"id": "backup-vda-node", "status": "created"}
        )
    elif fault == "foreign-id":
        closure["terminal_events"][0]["id"] = "foreign"
    elif fault == "unknown-state":
        closure["terminal_events"][1]["status"] = "ready"
    elif fault == "duplicate-job":
        closure["job_ids"].append(closure["job_ids"][0])
    elif fault == "missing-disk":
        closure["artifacts"] = []
    elif fault == "extra-artifact":
        closure["artifacts"].append(deepcopy(closure["artifacts"][0]))
    elif fault == "foreign-path":
        closure["artifacts"][0]["path"] = "../foreign.qcow2"
    elif fault == "boolean-inode":
        closure["artifacts"][0]["inode"] = True
    elif fault == "zero-inode":
        closure["artifacts"][0]["inode"] = 0
    elif fault == "negative-size":
        closure["artifacts"][0]["size"] = -1
    elif fault == "extra-field":
        closure["success"] = True
    value.update(
        closure_canonical=canonical(closure).decode(), closure_sha256=digest(closure)
    )
    with pytest.raises(StorageOwnershipError):
        validate(value, intent)


def test_changed_intent_and_duplicate_json_fields_refused():
    intent, value, _ = specimen()
    intent["source"]["exclusions"] = ["vda"]
    with pytest.raises(StorageOwnershipError):
        validate(value, intent)
    intent, value, _ = specimen()
    value["closure_canonical"] = (
        value["closure_canonical"][:-1] + ',"schema":"libvirt-closed-failure/1"}'
    )
    from core.native_closed_failure import digest_text

    value["closure_sha256"] = digest_text(value["closure_canonical"])
    with pytest.raises(StorageOwnershipError):
        validate(value, intent)
