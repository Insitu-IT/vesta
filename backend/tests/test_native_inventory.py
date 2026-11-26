"""Independent native inventory wire controls; no local-job authority claim."""

from copy import deepcopy
import json
from pathlib import Path

import pytest
from core.native_inventory import validate, digest
from core.s3_ownership import StorageOwnershipError


def test_native_generated_go_fields_match_backend_runtime():
    from agent.contracts import contracts
    from core import native_inventory

    for name in ("NATIVE_FILESET_FIELDS", "NATIVE_DISK_FIELDS", "NATIVE_FILE_FIELDS"):
        assert getattr(native_inventory, name) == getattr(contracts, name)


def test_native_preparation_accepts_observed_capacity_without_changing_producer_identity(
    monkeypatch, db_session
):
    from uuid import uuid4
    from datetime import datetime
    from backend.tests.conftest import make_agent, make_backup, make_vm
    from core.native_job import prepare_job

    agent = make_agent(db_session)
    uid = str(uuid4())
    identity = dict(target="vda", source="/fixture/disk", bus="virtio", format="qcow2")
    vm = make_vm(
        db_session,
        agent,
        provider="libvirt",
        uuid=uid,
        vm_uid=uid,
        disks=[
            dict(
                identity,
                capacity_bytes=4096,
                capacity_source="libvirt.domain.blockInfo.capacity",
            )
        ],
    )
    backup = make_backup(
        db_session,
        vm,
        backup_type="full",
        exclude_disks=[],
        capacity_state="reserved",
        capacity_id=str(uuid4()),
        capacity_reserved_at=datetime.utcnow(),
        capacity_policy_revision=1,
        authority_kind="human",
    )
    monkeypatch.setattr(
        "core.scheduler_admission.lock_original_authority",
        lambda *args, **kwargs: (None, backup, vm, agent, None, None, None),
    )
    monkeypatch.setattr(
        "core.backup_capacity.validate_reserved_capacity", lambda *args: None
    )
    monkeypatch.setattr(
        "core.storage_dispatch.read_target",
        lambda settings: dict(
            endpoint="https://store.invalid",
            bucket="test",
            region="region",
            prefix="",
            capability_profile="db-rooted-consumer-verified/1",
        ),
    )
    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    result = prepare_job(db_session, backup.id)
    assert result["source"]["disks"] == [identity]
    vm.disks = [dict(identity, capacity_bytes=None)]
    assert prepare_job(db_session, backup.id) == result
    vm.disks = [dict(identity, unexpected="x")]
    with pytest.raises(StorageOwnershipError):
        prepare_job(db_session, backup.id)
    vm.disks = [dict(identity, source="/fixture/changed")]
    with pytest.raises(StorageOwnershipError):
        prepare_job(db_session, backup.id)


@pytest.mark.parametrize("existing", [None, "virtnbdbackup.0", "vnbui-invented"])
def test_full_job_checkpoint_is_producer_defined_and_never_rewritten(
    monkeypatch, existing
):
    from types import SimpleNamespace
    from core import native_job

    source = {"backup_type": "full", "parent_backup_id": None}
    intent = None if existing is None else {"source": source, "checkpoint": existing}
    row = SimpleNamespace(
        id="backup", org_id="org", authority_kind="human", native_job_intent=intent
    )
    actor, agent = SimpleNamespace(id="actor"), SimpleNamespace(id="agent")
    monkeypatch.setattr(
        native_job, "admit", lambda db, backup: (row, actor, agent, source)
    )
    monkeypatch.setattr(
        "core.storage_dispatch.read_target",
        lambda _: dict(
            endpoint="https://fixture.invalid",
            bucket="backups",
            region="test",
            prefix="",
            capability_profile="db-rooted-consumer-verified/1",
        ),
    )
    monkeypatch.setattr(
        "core.storage_encryption.select_encryption",
        lambda *a, **kw: dict(format="none", key_ref=None),
    )
    effects = []
    db = SimpleNamespace(
        commit=lambda: effects.append("commit"),
        rollback=lambda: effects.append("rollback"),
    )
    if existing is not None:
        with pytest.raises(StorageOwnershipError):
            native_job.prepare_job(db, row.id)
        assert row.native_job_intent == intent
        assert effects == ["rollback"]
    else:
        result = native_job.prepare_job(db, row.id)
        assert result["checkpoint"] == "vnbui-" + result["attempt_id"]
        assert result["producer"] == "libvirt-push-qcow2/1"
        assert result["parent"] is None and result["push_parent"] is None
        assert effects == ["commit"]


def specimen():
    return json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "tests/fixtures/storage-contract-v1/libvirt-native-fileset.json"
        ).read_text()
    )


@pytest.mark.parametrize("state", ["exited", "sealed"])
def test_native_closed_job_accepts_explicit_positive_custody(state):
    from core.native_job import validate_closed_job

    intent = dict(job_id="vnbui-native-attempt", attempt_id="attempt")
    closed = dict(**intent, invocation_id="b" * 32, state=state, exit_code=0)
    validate_closed_job(closed, intent)


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "unknown"),
        ("state", "running"),
        ("state", []),
        ("exit_code", 1),
        ("exit_code", False),
        ("job_id", "foreign"),
        ("attempt_id", "foreign"),
        ("invocation_id", ""),
    ],
)
def test_native_sealed_closure_rejects_uncertain_or_unbound_custody(field, value):
    from core.native_job import validate_closed_job

    intent = dict(job_id="vnbui-native-attempt", attempt_id="attempt")
    closed = dict(**intent, invocation_id="b" * 32, state="sealed", exit_code=0)
    closed[field] = value
    with pytest.raises(StorageOwnershipError):
        validate_closed_job(closed, intent)


def rehash(value):
    for f in value["files"]:
        f["artifact_id"] = digest(
            [
                value[k]
                for k in (
                    "format",
                    "domain_uuid",
                    "backup_id",
                    "attempt_id",
                    "job_id",
                    "checkpoint",
                )
            ]
            + [
                f[k]
                for k in (
                    "member_backup_id",
                    "member_checkpoint",
                    "path",
                    "role",
                    "disk_id",
                )
            ]
        )


def test_native_go_fixture_digest_and_shape():
    value = specimen()
    expected = deepcopy(value)
    rehash(value)
    assert value == expected
    assert validate(value) == value


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "member",
        "checkpoint",
        "case",
        "depth",
        "duplicate",
        "role",
        "disk",
        "size",
        "boolean",
        "inode",
        "hash",
    ],
)
def test_native_invalid_inventory(fault):
    value = specimen()
    f = value["files"][0]
    if fault == "extra":
        f["secret"] = "forbidden"
    elif fault == "member":
        f["member_backup_id"] = value["attempt_id"]
    elif fault == "checkpoint":
        f["member_checkpoint"] = "foreign"
    elif fault == "case":
        f["path"] = "A/x"
        value["files"][1]["path"] = "a/y"
    elif fault == "depth":
        f["path"] = "a/" * 16 + "x"
    elif fault == "duplicate":
        value["files"].append(deepcopy(f))
    elif fault == "role":
        f["role"] = "unknown"
    elif fault == "disk":
        f["disk_id"] = "foreign"
    elif fault == "size":
        f["size"] = 2**63
    elif fault == "boolean":
        f["size"] = False
    elif fault == "inode":
        f["inode"] = value["files"][1]["inode"]
    rehash(value)
    if fault == "hash":
        f["artifact_id"] = "0" * 64
    with pytest.raises(StorageOwnershipError):
        validate(value)
