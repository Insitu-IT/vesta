"""Fresh restore plans retain catalog ancestry and explicit tenant authority."""

from copy import deepcopy
from types import SimpleNamespace
import uuid
import json

import pytest
from fastapi import BackgroundTasks, HTTPException

from core.kubevirt_restore import (
    build_plan,
    validate_target,
    hydrate_request,
    apply_progress,
)
from core.s3_ownership import StorageOwnershipError
from models import (
    Agent,
    Organization,
    Restore,
    User,
    VM,
    OperatorDispatch,
    S3Publication,
    StorageLineageGeneration,
)
from backend.tests.test_storage_restore import member


def fixture(db):
    generation, claim, backup = member(db)
    request = claim.expected_plan["transaction"]
    org = Organization(id=backup.org_id, name="Restore tenant", enabled=True)
    user = User(
        id=str(uuid.uuid4()),
        org_id=org.id,
        username="restore-operator",
        email="restore@example.invalid",
        password_hash="unused",
        role="operator",
        is_active=True,
    )
    agent = Agent(
        id=request["agent_id"], org_id=org.id, hostname="restore-agent", status="online"
    )
    vm = VM(
        id=backup.vm_id,
        org_id=org.id,
        name=request["plan"]["vm_name"],
        agent_id=agent.id,
        provider="kubevirt",
        namespace="ns",
        vm_uid="uid",
        uuid="uid",
        inventory_present=True,
    )
    db.add_all([org, user, agent, vm])
    db.commit()
    target = dict(
        namespace="ns",
        vm_name="restored-vm",
        disks=[
            dict(
                volume_name="data",
                pvc_name="restored-data",
                storage_class="ceph",
                volume_mode="Filesystem",
                access_mode="ReadWriteOnce",
                capacity_bytes=2 * 1024 * 1024,
            )
        ],
        networks=[dict(name="default", type="pod", network_name="")],
        dependencies={},
    )
    return backup, user, target


def make_plan(db, backup, user, target):
    return build_plan(
        db,
        backup_id=backup.id,
        org_id=user.org_id,
        actor_id=user.id,
        restore_id=str(uuid.uuid4()),
        target=target,
    )


def select_schema2(db, backup):
    from core.storage_wire import plan_digest

    claim = db.query(S3Publication).filter_by(backup_id=backup.id).one()
    generation = db.query(StorageLineageGeneration).filter_by(backup_id=backup.id).one()
    request = deepcopy(claim.expected_plan["transaction"])
    source = request["plan"]["source"]
    excluded = deepcopy(source["volumes"][0])
    excluded.update(name="boot", pvc_name="source-boot", pvc_uid="excluded-uid")
    excluded["mapping"]["disk_name"] = "boot"
    source.update(schema=2, native_volumes=deepcopy(source["volumes"]) + [excluded])
    request["plan"]["exclusions"] = ["boot"]
    request["plan_sha256"] = plan_digest(request["plan"])
    claim.expected_plan = dict(schema=3, transaction=request)
    generation.accepted_request = deepcopy(request)
    db.commit()
    return source


def restore_capability(db, backup):
    agent = db.get(Agent, db.get(VM, backup.vm_id).agent_id)
    agent.capabilities = dict(
        provider="kubevirt", kubevirt_restore_profiles=["kubevirt-selected-disks/1"]
    )
    db.commit()
    return agent


def test_schema2_plan_maps_only_protected_disks_with_explicit_restore_capability(
    db_session,
):
    backup, user, target = fixture(db_session)
    source = select_schema2(db_session, backup)
    restore_capability(db_session, backup)
    before = deepcopy(source)
    plan = make_plan(db_session, backup, user, target)
    assert plan["target"]["disks"] == target["disks"]
    assert [disk["volume_name"] for disk in plan["target"]["disks"]] == ["data"]
    assert plan["bundle"]["members"][0]["request"]["plan"]["source"] == before
    assert len(before["native_volumes"]) == 2
    target["disks"][0]["pvc_name"] = "source-boot"
    with pytest.raises(StorageOwnershipError, match="source or undersized"):
        make_plan(db_session, backup, user, target)


@pytest.mark.parametrize(
    "profiles",
    [
        None,
        [],
        "kubevirt-selected-disks/1",
        ["old/1"],
        ["kubevirt-selected-disks/1"] * 2,
    ],
)
def test_schema2_restore_refuses_missing_or_invalid_capability_before_admission(
    db_session, profiles
):
    backup, user, target = fixture(db_session)
    select_schema2(db_session, backup)
    agent = restore_capability(db_session, backup)
    agent.capabilities = dict(provider="kubevirt", kubevirt_restore_profiles=profiles)
    db_session.commit()
    with pytest.raises(StorageOwnershipError, match="kubevirt-selected-disks/1"):
        make_plan(db_session, backup, user, target)
    assert db_session.query(Restore).count() == 0


def test_schema2_restore_rechecks_partial_heartbeat_withdrawal_before_credentials(
    db_session, monkeypatch
):
    from core.storage_transfer import refreshed_capabilities
    from core.settings_service import SettingsService

    backup, user, target = fixture(db_session)
    select_schema2(db_session, backup)
    agent = restore_capability(db_session, backup)
    plan = make_plan(db_session, backup, user, target)
    agent.capabilities = refreshed_capabilities(
        agent.capabilities, {"incremental": True}
    )
    assert "kubevirt_restore_profiles" not in agent.capabilities
    db_session.commit()
    monkeypatch.setattr(
        SettingsService,
        "get_s3_config",
        lambda *_: pytest.fail("credentials read after restore capability withdrawal"),
    )
    restore = SimpleNamespace(
        id=plan["restore_id"],
        org_id=user.org_id,
        backup_id=backup.id,
        kubevirt_plan=plan,
    )
    with pytest.raises(StorageOwnershipError, match="kubevirt-selected-disks/1"):
        hydrate_request(db_session, restore)


def test_schema2_dispatch_admission_refuses_downgraded_agent_without_advancing_restore(
    db_session, monkeypatch
):
    from core.restore_executor import admit_restore

    backup, user, target = fixture(db_session)
    select_schema2(db_session, backup)
    agent = restore_capability(db_session, backup)
    plan = make_plan(db_session, backup, user, target)
    restore = Restore(
        id=plan["restore_id"],
        org_id=user.org_id,
        backup_id=backup.id,
        created_by=user.id,
        status="pending",
        restore_to_original=False,
        kubevirt_plan=plan,
    )
    db_session.add(restore)
    agent.capabilities = {
        "provider": "kubevirt",
        "kubevirt_native_disk_profiles": ["kubevirt-native-disks/1"],
    }
    db_session.commit()
    monkeypatch.setattr("core.restore_executor.commercial_mode", lambda: True)
    with pytest.raises(StorageOwnershipError, match="kubevirt-selected-disks/1"):
        admit_restore(db_session, restore.id, user.org_id, user.id, "pending")
    assert restore.status == "pending"
    assert restore.kubevirt_plan == plan


def test_durable_plan_contains_only_accepted_bundle_and_explicit_target(db_session):
    backup, user, target = fixture(db_session)
    plan = make_plan(db_session, backup, user, target)
    assert plan["target"] == target
    assert plan["bundle"]["members"][-1]["request"]["backup_id"] == backup.id
    assert set(plan) == {
        "schema",
        "org_id",
        "agent_id",
        "restore_id",
        "target",
        "bundle",
    }
    assert not any(k in plan for k in ("keys", "s3", "image"))
    assert plan["bundle"]["members"][0]["receipt"]


@pytest.mark.parametrize(
    "problem",
    [
        "tenant",
        "actor",
        "role",
        "disabled",
        "source-vm",
        "source-pvc",
        "small",
        "partial",
        "network",
        "dependency",
        "existing-vm",
        "image",
    ],
)
def test_admission_refuses_foreign_or_unsafe_destination(db_session, problem):
    backup, user, target = fixture(db_session)
    if problem == "tenant":
        user.org_id = str(uuid.uuid4())
    elif problem == "actor":
        user.is_active = False
    elif problem == "role":
        user.role = "viewer"
    elif problem == "disabled":
        db_session.get(Organization, user.org_id).enabled = False
    elif problem == "source-vm":
        target["vm_name"] = "vm"
    elif problem == "source-pvc":
        target["disks"][0]["pvc_name"] = "pvc"
    elif problem == "small":
        target["disks"][0]["capacity_bytes"] = 1
    elif problem == "partial":
        target["disks"] = []
    elif problem == "network":
        target["networks"][0] = dict(
            name="default", type="multus", network_name="other/network"
        )
    elif problem == "dependency":
        target["dependencies"] = {"secret/../../other": "foo"}
    elif problem == "existing-vm":
        db_session.add(
            VM(
                org_id=user.org_id,
                agent_id=backup.vm.agent_id,
                name="restored-vm",
                namespace="ns",
                provider="kubevirt",
                uuid="already",
                inventory_present=True,
            )
        )
    elif problem == "image":
        target["image"] = "caller-controlled:image"
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        make_plan(db_session, backup, user, target)


def test_multidisk_block_and_filesystem_target_mapping():
    source = {
        "namespace": "source",
        "volumes": [
            {"name": "root", "pvc_name": "old-root", "capacity_bytes": 4096},
            {"name": "data", "pvc_name": "old-data", "capacity_bytes": 8192},
        ],
    }
    target = dict(
        namespace="target",
        vm_name="new-vm",
        disks=[
            dict(
                volume_name="root",
                pvc_name="new-root",
                storage_class="ceph-fs",
                access_mode="ReadWriteOnce",
                volume_mode="Filesystem",
                capacity_bytes=8192,
            ),
            dict(
                volume_name="data",
                pvc_name="new-data",
                storage_class="ceph-block",
                access_mode="ReadWriteMany",
                volume_mode="Block",
                capacity_bytes=8192,
            ),
        ],
        networks=[],
        dependencies={},
    )
    assert validate_target(target, source, "old-vm") == target
    target["disks"][1]["pvc_name"] = "new-root"
    with pytest.raises(StorageOwnershipError):
        validate_target(target, source, "old-vm")


def test_completion_requires_exact_fresh_resource_identities():
    restore = SimpleNamespace(
        id="restore",
        kubevirt_plan={
            "target": dict(
                namespace="ns", vm_name="fresh", disks=[{"pvc_name": "fresh-root"}]
            )
        },
    )
    response = dict(
        restore_id="restore",
        status="completed",
        progress_percent=100,
        result=dict(
            namespace="ns",
            vm_name="fresh",
            run_strategy="Halted",
            vm_uid="vm-uid",
            job_uid="job-uid",
            job_name="job",
            plan_sha256="a" * 64,
            pvc_uids={"fresh-root": "pvc-uid"},
        ),
    )
    apply_progress(restore, response)
    assert (
        restore.status == "completed" and restore.kubevirt_result["vm_uid"] == "vm-uid"
    )
    for key, value in [
        ("namespace", "foreign"),
        ("run_strategy", "Always"),
        ("pvc_uids", {"source-root": "uid"}),
        ("vm_uid", ""),
    ]:
        bad = deepcopy(response)
        bad["result"][key] = value
        with pytest.raises(StorageOwnershipError):
            apply_progress(restore, bad)


def test_create_persists_plan_and_resume_uses_same_identity(db_session, monkeypatch):
    from routers import restores as router

    backup, user, target = fixture(db_session)
    monkeypatch.setattr(router, "log_activity", lambda *a, **k: None)
    tasks = BackgroundTasks()
    response = router.create_restore(
        dict(backup_id=backup.id, restore_to_original=False, kubevirt_target=target),
        tasks,
        user,
        db_session,
        request_id=str(uuid.uuid4()),
    )
    assert response.status_code == 201
    response = json.loads(response.body)
    saved = db_session.get(Restore, response["id"])
    assert saved.kubevirt_plan["restore_id"] == saved.id and saved.status == "pending"
    assert tasks.tasks == []
    work = db_session.query(OperatorDispatch).one()
    assert (
        work.resource_id == saved.id
        and work.kind == "restore"
        and work.state == "pending"
    )
    saved.status = "dispatching"
    db_session.commit()
    repeated = BackgroundTasks()
    resumed = router.resume_kubevirt_restore(saved.id, repeated, user, db_session)
    assert resumed["id"] == saved.id and len(repeated.tasks) == 1
    assert repeated.tasks[0].args == (saved.id, saved.org_id, user.id)
    with pytest.raises(HTTPException) as refusal:
        router.cancel_restore(saved.id, user, db_session)
    assert refusal.value.status_code == 409 and saved.status == "dispatching"


def test_hydration_refuses_changed_accepted_bundle_before_resolving_keys(
    db_session, monkeypatch
):
    backup, user, target = fixture(db_session)
    plan = make_plan(db_session, backup, user, target)
    restore = SimpleNamespace(
        id=plan["restore_id"],
        org_id=user.org_id,
        backup_id=backup.id,
        kubevirt_plan=plan,
    )
    plan["bundle"]["members"][0]["receipt"]["objects"][0]["etag"] = '"changed"'
    monkeypatch.setattr(
        "core.storage_attempt_key.unwrap_retained_attempt_key",
        lambda *a: pytest.fail("key exposed"),
    )
    with pytest.raises(StorageOwnershipError):
        hydrate_request(db_session, restore)
