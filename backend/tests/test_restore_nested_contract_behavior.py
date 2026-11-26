"""Known restore/policy protocols remain closed descriptions of actual helpers.

No VM, disk, provider, agent, database or executor operation is performed.
"""

from copy import deepcopy
from types import SimpleNamespace as NS
from uuid import uuid4

import jsonschema
import pytest
from fastapi import FastAPI
from ci.openapi_validation import contract_format_checker

from core import kubevirt_restore, native_restore
from core.s3_ownership import StorageOwnershipError
from core.scheduler_policy import BackupPolicyError
from core.scheduler_policy_decision import EARLY_FULL, validate_decision
from core.settings_service import SettingsService
from operator_contracts import install_operator_contracts
from operator_restore_contracts import restore_shapes, scheduler_decision
from routers import backups, restores


def validate(schema, value, document=None):
    full = {**schema, **({"components": document["components"]} if document else {})}
    jsonschema.Draft202012Validator(
        full, format_checker=contract_format_checker()
    ).validate(value)


def reject(schema, value, document=None):
    with pytest.raises(jsonschema.ValidationError):
        validate(schema, value, document)


@pytest.fixture
def shapes():
    return restore_shapes()


@pytest.fixture(scope="session")
def document():
    app = FastAPI()
    for module in (backups, restores):
        app.include_router(module.router)
    install_operator_contracts(
        app, SettingsService.DEFINITIONS, SettingsService.SECRET_DEFINITIONS
    )
    return app.openapi()


@pytest.fixture
def kubevirt_case():
    source = {
        "namespace": "source",
        "volumes": [{"name": "root", "pvc_name": "source-pvc", "capacity_bytes": 1024}],
    }
    target = {
        "namespace": "restored",
        "vm_name": "restored-vm",
        "disks": [
            {
                "volume_name": "root",
                "pvc_name": "restored-pvc",
                "storage_class": "fast",
                "access_mode": "ReadWriteOnce",
                "volume_mode": "Filesystem",
                "capacity_bytes": 2048,
            }
        ],
        "networks": [
            {"name": "default", "type": "pod", "network_name": ""},
            {"name": "extra", "type": "multus", "network_name": "target-nad"},
        ],
        "dependencies": {
            "secret/source-secret": "target-secret",
            "configMap/source-config": "target-config",
        },
    }
    return source, target


@pytest.fixture
def native_case():
    manifest = {
        "disks": [{"target": "vda", "virtual_size": 4096}],
        "exclusions": ["vdb"],
    }
    target = {
        "vm_name": "Restored-VM",
        "disks": ["vda"],
        "drop_excluded_disks": ["vdb"],
        "networks": [{"source_mac": "aa:bb:cc:dd:ee:ff", "network": "target-network"}],
    }
    return manifest, target


def test_native_input_four_fields_normalized_target_allocates_uuid(shapes, native_case):
    manifest, target = native_case
    validate(shapes["NativeRestoreInput"], target)
    saved = native_restore.validate_target(target, manifest, "source-vm")
    assert set(target) == {"vm_name", "disks", "drop_excluded_disks", "networks"}
    assert set(saved) == set(target) | {"vm_uuid"} and "vm_uuid" not in target
    validate(shapes["NativeRestoreTarget"], saved)
    reject(shapes["NativeRestoreInput"], saved)
    reject(shapes["NativeRestoreTarget"], target)
    assert (
        native_restore.validate_target(target, manifest, "source-vm")["vm_uuid"]
        != saved["vm_uuid"]
    )
    with pytest.raises(StorageOwnershipError):
        native_restore.validate_target(saved, manifest, "source-vm")


def test_kubevirt_target_actual_normalization(shapes, kubevirt_case):
    source, target = kubevirt_case
    saved = kubevirt_restore.validate_target(target, source, "source-vm")
    validate(shapes["KubeVirtRestoreTarget"], saved)
    assert saved == target and saved is not target


@pytest.mark.parametrize(
    "change",
    [
        "unknown_top",
        "unknown_disk",
        "bad_dns",
        "empty_disks",
        "zero_capacity",
        "bad_mode",
        "bad_network",
        "long_dependency",
    ],
)
def test_kubevirt_structural_refusals_are_in_schema(shapes, kubevirt_case, change):
    source, target = kubevirt_case
    if change == "unknown_top":
        target["unknown"] = "cannot hide"
    elif change == "unknown_disk":
        target["disks"][0]["unknown"] = "cannot hide"
    elif change == "bad_dns":
        target["namespace"] = "x" * 64
    elif change == "empty_disks":
        target["disks"] = []
    elif change == "zero_capacity":
        target["disks"][0]["capacity_bytes"] = 0
    elif change == "bad_mode":
        target["disks"][0]["volume_mode"] = "guessed"
    elif change == "bad_network":
        target["networks"][0]["type"] = "bridge"
    elif change == "long_dependency":
        target["dependencies"] = {"secret/" + "x" * 64: "target"}
    with pytest.raises(StorageOwnershipError):
        kubevirt_restore.validate_target(target, source, "source-vm")
    reject(shapes["KubeVirtRestoreTarget"], target)


@pytest.mark.parametrize(
    "change",
    [
        "unknown_top",
        "unknown_network",
        "empty_disks",
        "bad_name",
        "uppercase_mac",
        "missing_mac",
        "too_many_disks",
    ],
)
def test_native_structural_refusals_are_in_schema(shapes, native_case, change):
    manifest, target = native_case
    if change == "unknown_top":
        target["unknown"] = "cannot hide"
    elif change == "unknown_network":
        target["networks"][0]["unknown"] = "cannot hide"
    elif change == "empty_disks":
        target["disks"] = []
    elif change == "bad_name":
        target["vm_name"] = "x" * 129
    elif change == "uppercase_mac":
        target["networks"][0]["source_mac"] = "AA:BB:CC:DD:EE:FF"
    elif change == "missing_mac":
        del target["networks"][0]["source_mac"]
    elif change == "too_many_disks":
        target["disks"] = ["vda"] * 129
    with pytest.raises(StorageOwnershipError):
        native_restore.validate_target(target, manifest, "source-vm")
    reject(shapes["NativeRestoreInput"], target)


def test_target_source_binding_is_stricter_than_standalone_shape(
    shapes, kubevirt_case, native_case
):
    source, target = kubevirt_case
    target["disks"][0]["capacity_bytes"] = 1
    validate(shapes["KubeVirtRestoreTarget"], target)
    with pytest.raises(StorageOwnershipError):
        kubevirt_restore.validate_target(target, source, "source-vm")
    manifest, native = native_case
    native["disks"] = ["other-disk"]
    validate(shapes["NativeRestoreInput"], native)
    with pytest.raises(StorageOwnershipError):
        native_restore.validate_target(native, manifest, "source-vm")


def kubevirt_result(target):
    return {
        "namespace": target["namespace"],
        "vm_name": target["vm_name"],
        "vm_uid": "vm-uid",
        "job_uid": "job-uid",
        "job_name": "restore-job",
        "plan_sha256": "nonempty-runtime-bound-identifier",
        "run_strategy": "Halted",
        "pvc_uids": {disk["pvc_name"]: "pvc-uid" for disk in target["disks"]},
    }


def native_result(restore_id, target):
    return {
        "vm_name": target["vm_name"],
        "vm_uuid": target["vm_uuid"],
        "state": "shutoff",
        "plan_sha256": "a" * 64,
        "disks": [
            {
                "target": "vda",
                "path": f"/private/restores/{restore_id}/disks/vda.raw",
                "size_bytes": 4096,
                "sha256": "b" * 64,
            }
        ],
    }


def test_kubevirt_completed_progress_projects_closed_exact_result(
    shapes, kubevirt_case
):
    _, target = kubevirt_case
    restore = NS(id=str(uuid4()), kubevirt_plan={"target": target})
    raw = kubevirt_result(target)
    raw["untrusted_extra"] = "not projected"
    kubevirt_restore.apply_progress(
        restore,
        {
            "restore_id": restore.id,
            "status": "completed",
            "progress_percent": 100,
            "result": raw,
        },
    )
    validate(shapes["KubeVirtRestoreResult"], restore.kubevirt_result)
    assert (
        "untrusted_extra" not in restore.kubevirt_result
        and restore.status == "completed"
        and restore.error_message is None
    )
    reject(shapes["KubeVirtRestoreResult"], raw)
    for change in ("wrong_namespace", "missing_uid", "empty_pvc", "running_vm"):
        bad = kubevirt_result(target)
        if change == "wrong_namespace":
            bad["namespace"] = "other"
        elif change == "missing_uid":
            del bad["job_uid"]
        elif change == "empty_pvc":
            bad["pvc_uids"] = {}
        else:
            bad["run_strategy"] = "Always"
        with pytest.raises(StorageOwnershipError):
            kubevirt_restore.apply_progress(
                restore,
                {
                    "restore_id": restore.id,
                    "status": "completed",
                    "progress_percent": 100,
                    "result": bad,
                },
            )


def test_native_completed_progress_projects_inactive_result_and_exact_disks(
    shapes, native_case
):
    manifest, target = native_case
    saved = native_restore.validate_target(target, manifest, "source-vm")
    restore = NS(
        id=str(uuid4()),
        native_plan={
            "target": saved,
            "bundle": {"members": [{"push_result": {"manifest": manifest}}]},
        },
    )
    raw = native_result(restore.id, saved)
    raw["untrusted_extra"] = "not projected"
    native_restore.apply_progress(
        restore,
        {
            "restore_id": restore.id,
            "status": "completed",
            "progress_percent": 100,
            "result": raw,
        },
    )
    validate(shapes["NativeRestoreResult"], restore.native_result)
    assert (
        restore.native_result["state"] == "shutoff"
        and "untrusted_extra" not in restore.native_result
    )
    reject(shapes["NativeRestoreResult"], raw)
    for change in (
        "wrong_uuid",
        "active_vm",
        "old_state_spelling",
        "bad_plan_hash",
        "bad_size",
        "dot_path",
        "extra_disk_field",
    ):
        bad = native_result(restore.id, saved)
        if change == "wrong_uuid":
            bad["vm_uuid"] = str(uuid4())
        elif change == "active_vm":
            bad["state"] = "running"
        elif change == "old_state_spelling":
            bad["state"] = "shut off"
        elif change == "bad_plan_hash":
            bad["plan_sha256"] = "not-a-digest"
        elif change == "bad_size":
            bad["disks"][0]["size_bytes"] = 1
        elif change == "dot_path":
            bad["disks"][0]["path"] = f"/private/../{restore.id}/disks/vda.raw"
        else:
            bad["disks"][0]["extra"] = True
        with pytest.raises(StorageOwnershipError):
            native_restore.apply_progress(
                restore,
                {
                    "restore_id": restore.id,
                    "status": "completed",
                    "progress_percent": 100,
                    "result": bad,
                },
            )
        if change in {
            "active_vm",
            "old_state_spelling",
            "bad_plan_hash",
            "extra_disk_field",
        }:
            reject(shapes["NativeRestoreResult"], bad)


@pytest.mark.parametrize("module", [kubevirt_restore, native_restore])
def test_progress_nonterminal_states_and_invalid_progress(module):
    restore = NS(id="r")
    module.apply_progress(
        restore, {"restore_id": "r", "status": "running", "progress_percent": 20}
    )
    assert restore.status == "running" and restore.error_message is None
    module.apply_progress(
        restore,
        {"restore_id": "r", "status": "cleanup_required", "progress_percent": 20},
    )
    assert restore.status == "cleanup_required" and restore.error_message
    for progress in (True, -1, 101):
        with pytest.raises(StorageOwnershipError):
            module.apply_progress(
                restore,
                {"restore_id": "r", "status": "running", "progress_percent": progress},
            )


POLICY = {"schema": 1, "full_every_days": 7, "max_incrementals": 3}


def decision(reason="within_policy"):
    early = reason in EARLY_FULL
    return {
        "schema": 1,
        "policy": deepcopy(POLICY),
        "observed_date": "2026-11-09",
        "generation_id": None if early else "00000000-0000-4000-8000-000000000001",
        "root_backup_id": None if early else "00000000-0000-4000-8000-000000000002",
        "root_date": (
            None
            if early
            else "2026-11-01" if reason == "full_interval" else "2026-11-08"
        ),
        "incremental_count": (
            None if early else 3 if reason == "max_incrementals" else 1
        ),
        "backup_type": "incremental" if reason == "within_policy" else "full",
        "reason": reason,
    }


@pytest.mark.parametrize(
    "reason",
    [*sorted(EARLY_FULL), "within_policy", "full_interval", "max_incrementals"],
)
def test_all_saved_scheduler_decisions_runtime_and_schema(reason):
    value = decision(reason)
    saved = validate_decision(value, POLICY)
    validate(scheduler_decision(), saved)
    assert (
        saved == value and saved is not value and saved["policy"] is not value["policy"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "missing",
        "boolean_schema",
        "unknown_reason",
        "wrong_type",
        "early_parent",
        "negative_count",
        "invalid_uuid",
        "policy_bounds",
        "bad_date",
    ],
)
def test_invalid_decision_structural_mixes_refused_by_both(change):
    value = decision(
        "parent_unavailable" if change == "early_parent" else "within_policy"
    )
    if change == "unknown":
        value["unexpected"] = True
    elif change == "missing":
        del value["generation_id"]
    elif change == "boolean_schema":
        value["schema"] = True
    elif change == "unknown_reason":
        value["reason"] = "guessed"
    elif change == "wrong_type":
        value["backup_type"] = "full"
    elif change == "early_parent":
        value["root_date"] = "2026-11-08"
    elif change == "negative_count":
        value["incremental_count"] = -1
    elif change == "invalid_uuid":
        value["generation_id"] = "not-a-uuid"
    elif change == "policy_bounds":
        value["policy"]["max_incrementals"] = 0
    elif change == "bad_date":
        value["observed_date"] = "2026-02-30"
    with pytest.raises((BackupPolicyError, ValueError)):
        validate_decision(value, POLICY)
    reject(scheduler_decision(), value)


@pytest.mark.parametrize(
    "change", ["future_root", "wrong_interval", "wrong_count", "different_policy"]
)
def test_schema_does_not_claim_crossfield_decision_recomputation(change):
    value = decision(
        "full_interval"
        if change == "wrong_interval"
        else "max_incrementals" if change == "wrong_count" else "within_policy"
    )
    if change == "future_root":
        value["root_date"] = "2026-11-10"
    elif change == "wrong_interval":
        value["root_date"] = "2026-11-08"
    elif change == "wrong_count":
        value["incremental_count"] = 1
    elif change == "different_policy":
        value["policy"]["full_every_days"] = 9
    validate(scheduler_decision(), value)
    with pytest.raises(BackupPolicyError):
        validate_decision(value, POLICY)


def test_known_result_target_and_decision_fields_cannot_revert_to_metadata(
    shapes, kubevirt_case, native_case
):
    manifest, target = native_case
    saved = native_restore.validate_target(target, manifest, "source-vm")
    cases = {
        "KubeVirtRestoreTarget": kubevirt_case[1],
        "NativeRestoreInput": target,
        "NativeRestoreTarget": saved,
        "KubeVirtRestoreResult": kubevirt_result(kubevirt_case[1]),
        "NativeRestoreResult": native_result("restore-id", saved),
    }
    for name, value in cases.items():
        validate(shapes[name], value)
        reject(shapes[name], {**value, "unknown_protocol_field": True})
        for key in value:
            incomplete = deepcopy(value)
            del incomplete[key]
            reject(shapes[name], incomplete)
    value = decision()
    reject(scheduler_decision(), {**value, "unknown_protocol_field": True})
    for key in value:
        incomplete = deepcopy(value)
        del incomplete[key]
        reject(scheduler_decision(), incomplete)


def test_request_admission_list_detail_and_backup_decision_wire_integration(
    document, kubevirt_case, native_case
):
    # Enrichers must use these protocols at each exposed wire location, not only define unused components.
    manifest, native = native_case
    saved = native_restore.validate_target(native, manifest, "source-vm")
    kubevirt = kubevirt_case[1]
    request = document["components"]["schemas"]["RestoreCreateRequest"]
    for field, value in (("native_target", native), ("kubevirt_target", kubevirt)):
        validate(request, {"backup_id": "b", field: value}, document)
        reject(
            request,
            {"backup_id": "b", field: {**value, "unknown_protocol_field": True}},
            document,
        )
    reject(request, {"backup_id": "b", "native_target": saved}, document)
    created = document["paths"]["/api/v1/restores"]["post"]["responses"]["201"][
        "content"
    ]["application/json"]["schema"]
    base = {
        "id": "r",
        "backup_id": "b",
        "status": "pending",
        "progress": 0,
        "restore_to_original": False,
        "target_vm_name": None,
        "message": "pending",
        "request_id": "00000000-0000-4000-8000-000000000001",
    }
    for field, value in (("native_target", saved), ("kubevirt_target", kubevirt)):
        validate(created, {**base, field: value}, document)
        reject(
            created,
            {**base, field: {**value, "unknown_protocol_field": True}},
            document,
        )
    listed = document["paths"]["/api/v1/restores"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["properties"]["items"]["items"]
    detail = document["paths"]["/api/v1/restores/{restore_id}"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    for record in (listed, detail):
        for field, value in (
            ("native_target", saved),
            ("kubevirt_target", kubevirt),
            ("result", native_result("restore-id", saved)),
            ("result", kubevirt_result(kubevirt)),
        ):
            field_schema = record["properties"][field]
            validate(field_schema, value, document)
            reject(field_schema, {**value, "unknown_protocol_field": True}, document)
    backup = document["paths"]["/api/v1/backups/{backup_id}"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    field = backup["properties"]["scheduler_decision"]
    validate(field, decision(), document)
    reject(field, {**decision(), "unknown_protocol_field": True}, document)
