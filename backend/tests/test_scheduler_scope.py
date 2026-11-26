"""Canonical scope grammar and drift policy, without execution permission."""

from copy import deepcopy
import json
import uuid

import pytest
from core.scheduler_scope import compile_scope, digest, validate_drift, ScopeRefused


def uid():
    return str(uuid.uuid4())


@pytest.fixture
def scope():
    return dict(
        schema=1,
        org_id=uid(),
        schedule_id=uid(),
        revision=1,
        configuration_sha256="a" * 64,
        members=[
            dict(
                vm_id=uid(),
                agent_id=uid(),
                provider="kubevirt",
                vm_uid=uid(),
                namespace="fixture",
                source_sha256="b" * 64,
            )
        ],
        target=dict(
            endpoint="https://store.invalid",
            bucket="backup",
            region="",
            prefix="",
            capability_profile="db-rooted-consumer-verified/1",
        ),
        encryption=dict(format="none", key_ref=None),
        options=dict(
            backup_type="full", retention_days=30, exclude_disks=[], workers=None
        ),
    )


def test_canonical_roundtrip_and_set_order(scope):
    second = deepcopy(scope["members"][0])
    second["vm_id"] = uid()
    scope["members"].append(second)
    scope["options"]["exclude_disks"] = ["vdb", "vda"]
    compiled = compile_scope(scope)
    reordered = deepcopy(scope)
    reordered["members"].reverse()
    reordered["options"]["exclude_disks"].reverse()
    assert compile_scope(json.dumps(scope).encode()) == compiled
    assert digest(compile_scope(reordered)) == digest(compiled)
    assert validate_drift(scope, reordered) == compiled


@pytest.mark.parametrize(
    "change",
    [
        "schema_bool",
        "revision_bool",
        "uuid",
        "unknown",
        "duplicate_member",
        "digest",
        "namespace",
        "provider",
        "workers_bool",
        "retention_bool",
        "duplicate_disk",
        "differential",
        "key",
        "url",
        "size",
        "empty",
    ],
)
def test_strict_scope_refusals(scope, change):
    if change == "schema_bool":
        scope["schema"] = True
    if change == "revision_bool":
        scope["revision"] = True
    if change == "uuid":
        scope["org_id"] = scope["org_id"].upper()
    if change == "unknown":
        scope["guessed_admin"] = uid()
    if change == "duplicate_member":
        scope["members"] *= 2
    if change == "digest":
        scope["configuration_sha256"] = "x" * 64
    if change == "namespace":
        scope["members"][0]["namespace"] = ""
    if change == "provider":
        scope["members"][0]["provider"] = "mock"
    if change == "workers_bool":
        scope["options"]["workers"] = True
    if change == "retention_bool":
        scope["options"]["retention_days"] = True
    if change == "duplicate_disk":
        scope["options"]["exclude_disks"] = ["vdb", "vdb"]
    if change == "differential":
        scope["options"]["backup_type"] = "differential"
    if change == "key":
        scope["encryption"]["key_ref"] = "guessed"
    if change == "url":
        scope["target"]["endpoint"] = "https://user:secret@store.invalid"
    if change == "size":
        scope["target"]["prefix"] = "x" * 65537
    if change == "empty":
        scope["members"] = []
    with pytest.raises((ValueError, RuntimeError)):
        compile_scope(scope)


@pytest.mark.parametrize(
    "body",
    ['{"schema":1,"schema":1}', '{"schema":NaN}', "[]", '{"schema":1.0}', '"opaque"'],
)
def test_raw_json_refused(body):
    with pytest.raises(ScopeRefused):
        compile_scope(body)


def test_incremental_schedule_scope(scope):
    scope["options"]["backup_type"] = "incremental"
    assert compile_scope(scope)["options"]["backup_type"] == "incremental"


def test_automatic_scope_seals_explicit_policy(scope):
    automatic = deepcopy(scope)
    automatic["options"].update(
        backup_type="automatic",
        backup_policy={"schema": 1, "full_every_days": 7, "max_incrementals": 6},
    )
    compiled = compile_scope(automatic)
    assert compiled["options"]["backup_policy"]["max_incrementals"] == 6
    assert digest(compiled) != digest(compile_scope(scope))
    changed = deepcopy(automatic)
    changed["options"]["backup_policy"]["max_incrementals"] = 5
    with pytest.raises(ScopeRefused, match="scope_drift"):
        validate_drift(automatic, changed)


def test_fixed_grant_cannot_acquire_policy_or_automatic_authority(scope):
    scope["options"]["backup_policy"] = {
        "schema": 1,
        "full_every_days": 7,
        "max_incrementals": 6,
    }
    with pytest.raises(ScopeRefused):
        compile_scope(scope)
    del scope["options"]["backup_policy"]
    scope["options"]["backup_type"] = "automatic"
    with pytest.raises(ScopeRefused):
        compile_scope(scope)


@pytest.mark.parametrize(
    "change",
    [
        "addition",
        "removal",
        "missing",
        "replacement",
        "foreign_org",
        "target",
        "rules",
        "encryption",
    ],
)
def test_whole_occurrence_drift(scope, change):
    observed = deepcopy(scope)
    if change == "addition":
        observed["members"].append(dict(scope["members"][0], vm_id=uid()))
    elif change == "removal":
        observed["members"] = []
    elif change == "missing":
        observed["members"][0]["source_sha256"] = "c" * 64
    elif change == "replacement":
        observed["members"][0]["vm_uid"] = uid()
    elif change == "foreign_org":
        observed["org_id"] = uid()
    elif change == "target":
        observed["target"]["prefix"] = "new/"
    elif change == "rules":
        observed["configuration_sha256"] = "c" * 64
    else:
        observed["encryption"] = dict(
            format="vnbu1-aes256gcm-chunk5242880", key_ref=f"kek:{uid()}:{'c'*64}"
        )
    with pytest.raises(ScopeRefused):
        validate_drift(scope, observed)


def source_vm():
    from types import SimpleNamespace

    return SimpleNamespace(
        id=uid(),
        agent_id=uid(),
        provider="kubevirt",
        uuid=uid(),
        vm_uid=uid(),
        namespace="fixture",
        inventory_present=True,
        disks=[
            dict(
                target="root",
                source_type="persistentVolumeClaim",
                pvc_namespace="fixture",
                pvc_name="root",
                pvc_uid=uid(),
                pvc_resource_version="10",
                capacity_bytes=1024,
                mapping="filesystem",
                backup_eligible=True,
            )
        ],
    )


@pytest.mark.parametrize("source_type", ["persistentVolumeClaim", "dataVolume"])
def test_scheduler_semantic_identity_ignores_only_pvc_observation_version(source_type):
    from core.scheduler_scope import source_member
    from core.backup_monitor import source_identity

    vm = source_vm()
    vm.disks[0]["source_type"] = source_type
    member, monitor = source_member(vm), source_identity(vm)
    vm.disks[0]["pvc_resource_version"] = "11"
    assert source_member(vm) == member
    assert source_identity(vm) != monitor  # Shared monitor remains strict.
    assert vm.disks[0]["pvc_resource_version"] == "11"  # No inventory mutation.


@pytest.mark.parametrize(
    "change",
    [
        "pvc_uid",
        "mapping",
        "capacity_bytes",
        "provider",
        "agent_id",
        "vm_uid",
        "namespace",
        "backup_eligible",
        "pvc_name",
        "source_type",
    ],
)
def test_scheduler_semantic_identity_preserves_security_drift(change):
    from core.scheduler_scope import source_member

    vm = source_vm()
    before = source_member(vm)
    if change in ("provider", "agent_id", "vm_uid", "namespace"):
        setattr(vm, change, "libvirt" if change == "provider" else uid())
    else:
        vm.disks[0][change] = {"capacity_bytes": 2048, "backup_eligible": False}.get(
            change, "changed"
        )
    assert source_member(vm) != before


@pytest.mark.parametrize(
    "provider,source_type",
    [("libvirt", "persistentVolumeClaim"), ("kubevirt", "unsupported")],
)
def test_observation_exclusion_is_only_kubevirt_pvc(provider, source_type):
    from core.scheduler_scope import source_member

    vm = source_vm()
    vm.provider = provider
    vm.disks[0]["source_type"] = source_type
    before = source_member(vm)
    vm.disks[0]["pvc_resource_version"] = "11"
    assert source_member(vm) != before
