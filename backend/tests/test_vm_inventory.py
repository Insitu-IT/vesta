"""Inventory is an observation stream, never permission to erase backup owners."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from models import VM, Backup, VMGroup
from core.vm_inventory import sync_inventory, identity_fields
from core.backup_service import BackupService
from .conftest import make_agent, make_vm, make_backup


def entry(uid="vm-new", name="same", namespace="ns", **kwargs):
    return dict(
        name=name,
        uuid=uid,
        vm_uid=uid,
        vmi_uid="instance-1",
        provider="kubevirt",
        namespace=namespace,
        state="running",
        disks=[{"target": "data", "format": "raw"}],
        **kwargs
    )


def test_absent_history_with_fk_enforced(db_session):
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    agent = make_agent(db_session)
    old = make_vm(db_session, agent, name="absent")
    history = make_backup(db_session, old, status="completed")
    group = VMGroup(name="historical", vms=[old])
    db_session.add(group)
    db_session.commit()
    # Positive control: the old destructive implementation really cannot succeed.
    with pytest.raises(IntegrityError):
        db_session.execute(text("DELETE FROM vms WHERE id=:id"), {"id": old.id})
    db_session.rollback()
    sync_inventory(db_session, agent, {"vms": [entry()], "complete": True})
    assert db_session.get(Backup, history.id).vm_id == old.id
    assert old in group.vms
    assert old.inventory_present is False and old.absent_since
    assert db_session.query(VM).count() == 2
    assert identity_fields(old)["inventory_present"] is False


def test_replacement_and_namespaces_do_not_inherit(db_session):
    agent = make_agent(db_session)
    sync_inventory(db_session, agent, {"vms": [entry(uid="old")], "complete": True})
    old = db_session.query(VM).one()
    history = make_backup(db_session, old, status="completed", chain_id="old-chain")
    sync_inventory(
        db_session,
        agent,
        {"vms": [entry(), entry(uid="other", namespace="other")], "complete": True},
    )
    new = db_session.query(VM).filter(VM.vm_uid == "vm-new").one()
    assert new.id != old.id and new.replaces_vm_id == old.id
    assert new.backups == [] and new.groups == []
    assert history.vm_id == old.id and old.inventory_present is False
    assert db_session.query(VM).filter(VM.inventory_present.is_(True)).count() == 2
    pending = Backup(id="next", vm_id=new.id, backup_type="incremental")
    BackupService(db_session)._resolve_chain(pending, new.id)
    # No implicit downgrade or old-chain inheritance: transaction admission holds
    # the requested incremental until an authoritative current parent exists.
    assert pending.backup_type == "incremental" and pending.parent_backup_id is None
    assert pending.chain_id is None


def test_stopped_empty_partial_and_restart(db_session):
    agent = make_agent(db_session)
    first = entry()
    sync_inventory(db_session, agent, {"vms": [first], "complete": True})
    vm = db_session.query(VM).one()
    original_id = vm.id
    first["vmi_uid"] = "instance-2"
    sync_inventory(db_session, agent, {"vms": [first], "complete": True})
    assert vm.id == original_id and vm.vmi_uid == "instance-2"
    first.update(state="stopped", vmi_uid="")
    sync_inventory(db_session, agent, {"vms": [first], "complete": True})
    assert vm.inventory_present and vm.state == "stopped" and vm.vmi_uid is None
    sync_inventory(db_session, agent, {"vms": [], "complete": False})
    assert vm.inventory_present
    sync_inventory(db_session, agent, {"vms": [], "complete": True})
    assert not vm.inventory_present and vm.absent_since
    assert not BackupService.check_disk_eligibility(vm)["eligible"]
    sync_inventory(db_session, agent, {"vms": [first], "complete": True})
    assert vm.id == original_id and vm.absent_since is None


def test_delayed_recreation_preserves_relationship_without_inheritance(db_session):
    agent = make_agent(db_session)
    sync_inventory(db_session, agent, {"vms": [entry(uid="old")], "complete": True})
    old = db_session.query(VM).one()
    history = make_backup(db_session, old, status="completed", chain_id="old-chain")
    group = VMGroup(name="old-membership", vms=[old])
    db_session.add(group)
    db_session.commit()
    sync_inventory(db_session, agent, {"vms": [], "complete": True})
    absent_since = old.absent_since
    sync_inventory(db_session, agent, {"vms": [entry()], "complete": True})
    new = db_session.query(VM).filter(VM.vm_uid == "vm-new").one()
    assert new.id != old.id and new.replaces_vm_id == old.id
    assert not old.inventory_present and old.absent_since == absent_since
    assert history.vm_id == old.id and group.vms == [old]
    assert new.backups == [] and new.groups == []
    pending = Backup(id="delayed-next", vm_id=new.id, backup_type="incremental")
    BackupService(db_session)._resolve_chain(pending, new.id)
    assert pending.backup_type == "incremental" and pending.parent_backup_id is None
    assert pending.chain_id != history.chain_id
    # Refreshing the same identity must not rewrite its predecessor.
    sync_inventory(db_session, agent, {"vms": [entry()], "complete": True})
    assert new.replaces_vm_id == old.id


@pytest.mark.parametrize("reverse", [False, True])
def test_delayed_recreation_selects_deterministic_history(db_session, reverse):
    agent = make_agent(db_session)
    at = datetime(2026, 1, 1)
    # Observation time wins over creation time; creation then ID break ties.
    cases = [
        ("old-observation", at, at + timedelta(days=3)),
        ("older-creation", at + timedelta(days=2), at),
        ("tie-a", at + timedelta(days=2), at + timedelta(days=1)),
        ("tie-z", at + timedelta(days=2), at + timedelta(days=1)),
        ("legacy", None, at),
    ]
    for uid, observed, created in reversed(cases) if reverse else cases:
        make_vm(
            db_session,
            agent,
            id=uid,
            name="same",
            provider="kubevirt",
            namespace="ns",
            vm_uid=uid,
            inventory_present=False,
            last_observed_at=observed,
            created_at=created,
            absent_since=at,
        )
    sync_inventory(db_session, agent, {"vms": [entry()], "complete": True})
    new = db_session.query(VM).filter(VM.vm_uid == "vm-new").one()
    assert new.replaces_vm_id == "tie-z"


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"vms": None},
        {"vms": [], "complete": "true"},
        {"vms": [entry(), {}], "complete": True},
        {"vms": [entry(), entry()], "complete": True},
        {
            "vms": [
                dict(name="legacy", uuid="vmi-id", metadata={"provider": "kubevirt"})
            ]
        },
    ],
)
def test_invalid_batch_never_partially_updates(db_session, bad):
    agent = make_agent(db_session)
    vm = make_vm(db_session, agent)
    with pytest.raises(HTTPException) as exc:
        sync_inventory(db_session, agent, bad)
    assert exc.value.status_code == 422
    assert db_session.query(VM).count() == 1 and vm.inventory_present


def test_legacy_vmi_uuid_is_not_stable_identity(db_session):
    agent = make_agent(db_session)
    old = make_vm(
        db_session,
        agent,
        name="same",
        uuid="instance-1",
        vm_metadata={"provider": "kubevirt", "namespace": "ns"},
    )
    sync_inventory(db_session, agent, {"vms": [entry()], "complete": True})
    assert old.vm_uid is None and old.uuid == "instance-1" and not old.inventory_present
    assert db_session.query(VM).filter(VM.vm_uid == "vm-new").one().id != old.id


def test_libvirt_uuid_continuity(db_session):
    agent = make_agent(db_session)
    old = make_vm(db_session, agent, uuid="stable-libvirt")
    sync_inventory(
        db_session,
        agent,
        {"vms": [{"name": "renamed", "uuid": "stable-libvirt"}], "complete": True},
    )
    assert db_session.query(VM).count() == 1
    assert old.name == "renamed" and old.vm_uid == "stable-libvirt"


@pytest.mark.asyncio
async def test_inventory_api_exposes_history_and_fences_backup(db_session):
    from routers.agents import sync_agent_vms, get_vm, list_vms
    from core.vm_inventory import legacy_event_vm

    agent = make_agent(db_session)
    result = await sync_agent_vms(
        agent.hostname, {"vms": [entry()], "complete": True}, agent, db_session
    )
    assert result["synced"] == 1
    vm = db_session.query(VM).one()
    detail = await get_vm(vm.id, db_session, {})
    assert detail["namespace"] == "ns" and detail["vm_uid"] == "vm-new"
    assert detail["vmi_uid"] == "instance-1" and detail["last_observed_at"]
    assert legacy_event_vm(db_session, agent.id, "same") is None
    await sync_agent_vms(
        agent.hostname, {"vms": [], "complete": True}, agent, db_session
    )
    result = await list_vms(inventory_present=True, db=db_session, current_user={})
    assert result["total"] == 0
    detail = await get_vm(vm.id, db_session, {})
    assert detail["inventory_present"] is False and detail["absent_since"]
    allowed, _, code = BackupService(db_session).can_start_backup(
        vm.id, check_maintenance=False
    )
    assert not allowed and code == 409


def test_migration_preserves_rows_and_enforces_identity():
    import importlib.util
    import io
    import re
    from pathlib import Path
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = (
        Path(__file__).parents[1] / "alembic/versions/20260904_vm_inventory_identity.py"
    )
    spec = importlib.util.spec_from_file_location("inventory_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    output = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output}
    )
    with Operations.context(context):
        migration.upgrade()
    sql = output.getvalue()
    assert "UNIQUE (agent_id, provider, namespace, vm_uid)" in sql
    assert "REFERENCES vms (id)" in sql
    assert "inventory_present BOOLEAN DEFAULT true NOT NULL" in sql
    # UPDATE in CREATE TRIGGER declares coverage; it is not a data rewrite.
    assert not re.search(r"(?im)^\s*(DELETE|UPDATE|DROP)\b", sql)
    assert "CREATE TRIGGER vm_predecessor_scope BEFORE INSERT OR UPDATE" in sql
    with pytest.raises(RuntimeError, match="pre-migration"):
        migration.downgrade()


def test_policy_inventory_complete_is_per_namespace_and_preserves_deselected_history(
    db_session,
):
    agent = make_agent(
        db_session,
        capabilities={"provider": "kubevirt"},
        metrics={
            "scope": {
                "source_namespaces": ["one", "two"],
                "selected_source_namespaces": ["one", "two"],
            }
        },
    )
    sync_inventory(
        db_session,
        agent,
        {
            "vms": [
                entry(uid="uid-one", namespace="one"),
                entry(uid="uid-two", namespace="two"),
            ],
            "complete": True,
            "source_namespaces": ["one", "two"],
        },
    )
    rows = {vm.namespace: vm for vm in db_session.query(VM).all()}
    ids = {ns: vm.id for ns, vm in rows.items()}
    sync_inventory(
        db_session, agent, {"vms": [], "complete": True, "source_namespaces": ["one"]}
    )
    assert not rows["one"].inventory_present
    assert rows["two"].inventory_present and rows["two"].id == ids["two"]
    sync_inventory(
        db_session, agent, {"vms": [], "complete": True, "source_namespaces": []}
    )
    assert rows["two"].inventory_present
    with pytest.raises(HTTPException):
        sync_inventory(db_session, agent, {"vms": [], "complete": True})
    assert rows["two"].inventory_present


@pytest.mark.parametrize("memory", [None, 0, 1048576])
def test_kubevirt_memory_unknown_and_provenance(db_session, memory):
    agent = make_agent(db_session)
    metadata = {
        "memory": {"known": bool(memory), "source": "vmi.spec.domain.memory.guest"},
        "changed_block_tracking": {"state": None, "source": "vmi"},
    }
    sync_inventory(
        db_session,
        agent,
        {"vms": [entry(memory_kb=memory, metadata=metadata)], "complete": True},
    )
    vm = db_session.query(VM).one()
    assert vm.memory_kb == (memory or None)
    assert vm.vm_metadata == metadata
