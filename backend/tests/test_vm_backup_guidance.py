from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.conftest import make_agent, make_backup, make_vm
from core.storage_transfer import refreshed_capabilities
from core.vm_backup_guidance import backup_guidance
from models import Backup, StorageLineageGeneration, StorageLineageHead

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)
APIS = {
    name: "served"
    for name in (
        "virtualmachinebackups",
        "virtualmachinebackuptrackers",
        "virtualmachineexports",
    )
}


def observed_vm(db, provider="kubevirt"):
    kv = provider == "kubevirt"
    agent = make_agent(
        db,
        capabilities={
            "provider": provider,
            "storage_admission_used_percent": 95,
            "kubevirt_native_disk_profiles": ["kubevirt-native-disks/1"],
        },
        metrics=dict(
            provider=provider,
            backup_method="kubevirt_pull_transaction" if kv else "native_push",
            supports_incremental=True,
            provider_accessible=True,
            updated_at=NOW.isoformat(),
            disk_usage_percent=80,
            backup_storage_total_bytes=1000,
            backup_storage_free_bytes=200,
            storage_role="journal" if kv else "native_capture",
            scope={
                "source_namespaces": ["test"],
                "selected_source_namespaces": ["test"],
            },
        ),
    )
    uid = str(uuid4())
    disk = dict(target="data", format="qcow2", bus="virtio", source="/test/data")
    if kv:
        disk = dict(
            target="data",
            source_type="dataVolume",
            backup_eligible=True,
            pvc_namespace="test",
            pvc_name="claim",
            pvc_uid="volume-uid",
            pvc_resource_version="100",
            capacity_bytes=4096,
            mapping=dict(disk_name="data", device="disk", bus="virtio", serial=None),
        )
    return make_vm(
        db,
        agent,
        provider=provider,
        vm_uid=uid,
        uuid=uid,
        namespace="test" if kv else "",
        vmi_uid="instance" if kv else None,
        last_observed_at=NOW.replace(tzinfo=None),
        disks=[disk],
        vm_metadata={
            "changed_block_tracking": {"state": "Enabled", "source": "vmi"},
            "backup_instance_readiness": "ready",
            "backup_tracker": {"state": "absent"},
            "backup_apis": APIS,
        },
    )


def assess(db, vm, excluded=()):
    return backup_guidance(db, vm, list(excluded), now=NOW)


def checkpoint(db, vm):
    if vm.provider == "kubevirt":
        from core.storage_dispatch import compile_request
        from core.storage_semantics import digest

        parent = make_backup(db, vm, status="completed", backup_type="full")
        disk = vm.disks[0]
        volume = {
            key: disk[key]
            for key in ("pvc_name", "pvc_uid", "pvc_resource_version", "capacity_bytes")
        }
        source = dict(
            schema=1,
            agent_id=vm.agent_id,
            vm_uid=vm.vm_uid,
            vm_id=vm.id,
            namespace=vm.namespace,
            volumes=[dict(name="data", **volume)],
        )
        claim = SimpleNamespace(
            id=str(uuid4()),
            object_key=f"vnbui-owned/v1/{digest(vm.org_id)}/{digest(parent.id)}/payload/",
            endpoint="https://store.invalid",
            bucket="bucket",
        )
        request = compile_request(
            claim,
            source,
            vm,
            parent,
            dict(capability_profile="db-rooted-consumer-verified/1"),
        )
        tracker = "tracker"
    else:
        from backend.tests.test_native_storage_wire import EXAMPLES
        from core.native_storage import build_artifacts
        from core.storage_wire import plan_digest

        request = deepcopy(EXAMPLES[0]["request"])
        plan = request["plan"]
        source = plan["source"]
        vm.uuid = vm.vm_uid = source["inventory"]["domain_uuid"]
        parent = make_backup(db, vm, id=request["backup_id"], status="completed")
        tracker = vm.uuid
        parent.native_job_intent = {
            "source": {"domain_uuid": vm.uuid, "disks": deepcopy(vm.disks)}
        }
        request.update(org_id=vm.org_id, agent_id=vm.agent_id)
        source.update(agent_id=vm.agent_id, vm_id=vm.id)
        plan["artifacts"] = build_artifacts(
            source, vm.org_id, parent.id, request["reservation_id"], plan["encryption"]
        )
        request["plan_sha256"] = plan_digest(plan)
    common = dict(
        org_id=vm.org_id,
        vm_id=vm.id,
        root_backup_id=parent.id,
        checkpoint="checkpoint",
        tracker_uid=tracker,
        manifest_receipt_sha256="b" * 64,
    )
    generation = StorageLineageGeneration(
        **common,
        id=str(uuid4()),
        backup_id=parent.id,
        state="accepted",
        receipt_sha256="a" * 64,
        root_receipt_sha256="a" * 64,
        accepted_request=request,
    )
    db.add(generation)
    db.add(StorageLineageHead(**common, state="current", generation_id=generation.id))
    if vm.provider == "kubevirt":
        vm.vm_metadata = dict(
            vm.vm_metadata,
            backup_tracker={
                "state": "observed",
                "uid_sha256": digest(tracker),
                "checkpoint_sha256": digest("checkpoint"),
            },
        )
    db.commit()
    return parent


def test_full_then_incremental_needs_accepted_matching_source(db_session):
    vm = observed_vm(db_session)
    make_backup(db_session, vm, status="completed")
    assert assess(db_session, vm).reason == "checkpoint_missing"
    checkpoint(db_session, vm)
    before = db_session.query(Backup).count()
    assert assess(db_session, vm).mode == "incremental"
    vm.disks = [dict(vm.disks[0], pvc_resource_version="105")]
    assert assess(db_session, vm).mode == "incremental"
    vm.disks = [dict(vm.disks[0], pvc_uid="replacement")]
    assert assess(db_session, vm).reason == "checkpoint_changed"
    assert db_session.query(Backup).count() == before


@pytest.mark.parametrize(
    ("state", "source", "mode", "reason"),
    [
        ("Disabled", "vmi", "blocked", "cbt_disabled"),
        ("PendingRestart", "vmi", "blocked", "cbt_pending_restart"),
        ("Initializing", "vmi", "blocked", "cbt_pending"),
        ("Future", "vmi", "unknown", "cbt_unknown"),
        ("Enabled", "vm", "unknown", "cbt_unknown"),
        (None, "vmi", "unknown", "cbt_unknown"),
    ],
)
def test_current_vmi_alone_can_supply_cbt(db_session, state, source, mode, reason):
    vm = observed_vm(db_session)
    vm.vm_metadata = dict(
        vm.vm_metadata, changed_block_tracking={"state": state, "source": source}
    )
    result = assess(db_session, vm)
    assert (result.mode, result.reason) == (mode, reason)


def test_stopped_vm_legacy_data_stale_inventory_and_failed_discovery(db_session):
    vm = observed_vm(db_session)
    vm.state, vm.vmi_uid = "stopped", None
    vm.vm_metadata = dict(
        vm.vm_metadata, changed_block_tracking={"source": "vm", "state": "Enabled"}
    )
    stopped = assess(db_session, vm)
    assert (stopped.mode, stopped.reason, stopped.cbt_source, stopped.cbt_state) == (
        "blocked",
        "vmi_stopped",
        "vm",
        "enabled",
    )
    vm.state = "pending"
    assert assess(db_session, vm).mode == "unknown"
    vm.state, vm.vmi_uid = "running", "instance"
    vm.vm_metadata = dict(
        vm.vm_metadata, changed_block_tracking={"source": "vmi", "state": "Enabled"}
    )
    vm.vm_metadata = dict(
        vm.vm_metadata, backup_apis={**APIS, "virtualmachineexports": "not_served"}
    )
    result = assess(db_session, vm)
    assert result.mode == "blocked" and result.missing_apis == ["virtualmachineexports"]
    vm.vm_metadata = dict(vm.vm_metadata, backup_apis={})
    assert assess(db_session, vm).reason == "backup_api_unknown"
    vm.last_observed_at = NOW - timedelta(minutes=10)
    assert assess(db_session, vm).reason == "inventory_stale"
    vm.inventory_present = False
    assert assess(db_session, vm).reason == "vm_absent"


def test_volume_snapshot_evidence_never_claims_group_execution(db_session):
    vm = observed_vm(db_session)
    second = dict(
        vm.disks[0],
        target="second",
        pvc_uid="second-pvc",
        pvc_name="second-claim",
        mapping=dict(disk_name="second", device="disk", bus="virtio", serial=None),
    )
    vm.disks = [*vm.disks, second, {"target": "seed", "source_type": "unsupported"}]
    vm.vm_metadata = dict(
        vm.vm_metadata,
        volume_snapshot_statuses={"data": True, "second": False, "other": True},
        backup_apis={**APIS, "group_snapshot": "served"},
    )
    warning = assess(db_session, vm)
    assert (warning.reason, warning.affected_disks) == ("exclude_unsupported", ["seed"])
    assert assess(db_session, vm, ["data", "second"]).reason == "invalid_selection"
    result = assess(db_session, vm, ["seed", "second"])
    assert result.mode == "full" and result.persistent_disks == ["data", "second"]
    assert result.volume_snapshot_statuses == {"data": True, "second": False}
    assert (
        result.group_snapshot_api,
        result.storage_group_snapshot,
        result.group_snapshot_execution,
    ) == ("served", "unverified", "unavailable")
    vm.agent.capabilities = {"provider": "kubevirt"}
    assert assess(db_session, vm, ["seed", "second"]).reason == "disk_profile_required"
    second["backup_eligible"] = False
    assert (
        assess(db_session, vm, ["seed", "second"]).reason
        == "persistent_disk_unavailable"
    )


def test_low_and_at_limit_measure_actual_filesystem_not_cbt_history(db_session):
    vm = observed_vm(db_session)
    vm.agent.metrics = dict(
        vm.agent.metrics, disk_usage_percent=93, health_reasons=["storage_low"]
    )
    result = assess(db_session, vm)
    assert (result.storage.state, result.mode, result.cbt_history_capacity) == (
        "low",
        "full",
        "unmeasured",
    )
    vm.agent.metrics = dict(
        vm.agent.metrics, disk_usage_percent=95, backup_storage_free_bytes=50
    )
    result = assess(db_session, vm)
    assert (result.mode, result.reason, result.storage.admission_used_percent) == (
        "blocked",
        "storage_at_limit",
        95,
    )
    vm.agent.capabilities = refreshed_capabilities(
        vm.agent.capabilities, {"provider": "kubevirt"}
    )
    assert assess(db_session, vm).storage.admission_used_percent is None
    vm.agent.metrics = dict(vm.agent.metrics, storage_measurement_error="private path")
    result = assess(db_session, vm)
    assert (
        result.reason == "storage_unmeasured"
        and "private path" not in result.model_dump_json()
    )
    vm.agent.metrics = dict(
        vm.agent.metrics, updated_at=(NOW - timedelta(minutes=5)).isoformat()
    )
    assert assess(db_session, vm).reason == "provider_offline"


@pytest.mark.parametrize(
    ("tracker", "mode", "reason"),
    [
        ({"state": "absent"}, "full", "tracker_missing"),
        (
            {
                "state": "observed",
                "uid_sha256": "0" * 64,
                "checkpoint_sha256": "0" * 64,
            },
            "full",
            "tracker_changed",
        ),
        ({"state": "unknown"}, "unknown", "tracker_unobserved"),
        ({"state": "source_mismatch"}, "blocked", "tracker_conflict"),
    ],
)
def test_catalog_requires_matching_observed_tracker(db_session, tracker, mode, reason):
    vm = observed_vm(db_session)
    checkpoint(db_session, vm)
    vm.vm_metadata = dict(vm.vm_metadata, backup_tracker=tracker)
    result = assess(db_session, vm)
    assert (result.mode, result.reason) == (mode, reason)


@pytest.mark.parametrize(
    ("provider", "disk", "reason"),
    [
        (
            "kubevirt",
            {"target": "boot", "source_type": "unsupported"},
            "no_persistent_disks",
        ),
        (
            "libvirt",
            dict(target="vda", source="/fixture/disk", bus="virtio", format="raw"),
            "no_qcow2_disks",
        ),
    ],
)
def test_excluding_every_disk_is_never_proposed(db_session, provider, disk, reason):
    vm = observed_vm(db_session, provider)
    vm.disks = [disk]
    result = assess(db_session, vm)
    assert (result.mode, result.reason, result.affected_disks) == (
        "blocked",
        reason,
        [],
    )
    assert assess(db_session, vm, [disk["target"]]).reason == reason


@pytest.mark.parametrize(
    ("readiness", "expected"),
    [
        ("paused", "vmi_paused"),
        ("io_paused", "vmi_io_paused"),
        ("not_ready", "vmi_not_ready"),
        (None, "vmi_not_ready"),
    ],
)
def test_running_phase_alone_does_not_establish_readiness(
    db_session, readiness, expected
):
    vm = observed_vm(db_session)
    vm.vm_metadata = dict(vm.vm_metadata, backup_instance_readiness=readiness)
    assert assess(db_session, vm).reason == expected


def test_libvirt_selection_and_checkpoint_custody(db_session):
    vm = observed_vm(db_session, "libvirt")
    checkpoint(db_session, vm)
    assert assess(db_session, vm).reason == "native_checkpoint_unverified"
    make_backup(db_session, vm, status="failed", native_fenced_failure_xid=12)
    assert assess(db_session, vm).reason == "checkpoint_changed"
    vm.disks = vm.disks + [
        dict(vm.disks[0], target="raw", format="raw", source="/test/raw")
    ]
    assert assess(db_session, vm).affected_disks == ["raw"]
    assert assess(db_session, vm, ["raw"]).mode == "full"
    assert assess(db_session, vm, ["disk"]).reason == "invalid_selection"
    assert assess(db_session, vm, ["raw", "raw"]).reason == "invalid_selection"
    assert assess(db_session, vm, ["raw", "data"]).reason == "invalid_selection"
    vm.agent.metrics = dict(vm.agent.metrics, supports_incremental=False)
    assert assess(db_session, vm, ["raw"]).reason == "agent_full_only"


def test_guidance_endpoint_keeps_existing_schema_and_checks_tenant(db_session):
    from database import get_db
    from deps import hash_password
    from models import Organization, User
    from routers.auth import router as auth_router
    from routers.agents import router

    vm = observed_vm(db_session, "libvirt")
    app = FastAPI()
    app.include_router(router)
    app.include_router(auth_router)
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    url = f"/api/v1/vms/{vm.id}/backup-guidance"
    assert client.get(url).status_code == 401
    user = User(
        username="reader",
        password_hash=hash_password("test-only-viewer-password"),
        role="viewer",
        org_id=vm.org_id,
    )
    db_session.add(user)
    db_session.commit()
    login = client.post(
        "/api/v1/auth/login",
        data={"username": "reader", "password": "test-only-viewer-password"},
    )
    assert login.status_code == 200
    client.headers.update({"Authorization": "Bearer " + login.json()["access_token"]})
    response = client.get(
        url, params=[("exclude_disk", "data"), ("exclude_disk", "data")]
    )
    assert response.status_code == 200 and response.json()[
        "documentation_url"
    ].startswith("https://vestabackup.com/docs/")
    assert "backup_guidance" not in client.get(f"/api/v1/vms/{vm.id}").json()
    assert client.get(url, params={"exclude_disk": "x" * 129}).status_code == 422
    other_org = Organization(name="Other isolated organization")
    db_session.add(other_org)
    db_session.flush()
    vm.org_id = other_org.id
    db_session.commit()
    assert client.get(url).status_code == 404
