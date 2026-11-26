"""Strict, non-secret scheduler scope; compilation grants no execution authority."""

import hashlib
import json
import re
import uuid
from copy import deepcopy
from types import SimpleNamespace

LIMIT = 65536
MAX_MEMBERS = 256


class ScopeRefused(ValueError):
    pass


def refuse(reason="invalid_scope"):
    raise ScopeRefused(reason)


def canonical(value):
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        if len(result.encode()) > LIMIT:
            refuse("scope_too_large")
        return result
    except (TypeError, ValueError, RecursionError):
        refuse()


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            refuse()
    except (ValueError, AttributeError):
        refuse()
    return value


def fields(value, expected):
    if type(value) is not dict or set(value) != set(expected.split()):
        refuse()


def string(value, *, empty=False):
    if (
        type(value) is not str
        or len(value) > 2048
        or (not empty and not value)
        or "\x00" in value
    ):
        refuse()


def sha(value):
    if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value):
        refuse()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate_key")
        result[key] = value
    return result


def compile_scope(value):
    if isinstance(value, (str, bytes)):
        if len(value) > LIMIT:
            refuse("scope_too_large")
        try:
            value = json.loads(
                value, object_pairs_hook=_pairs, parse_constant=lambda _: refuse()
            )
        except (ValueError, UnicodeError, RecursionError):
            refuse()
    canonical(value)
    fields(
        value,
        "schema org_id schedule_id revision configuration_sha256 members target encryption options",
    )
    if type(value["schema"]) is not int or value["schema"] != 1:
        refuse()
    for key in ("org_id", "schedule_id"):
        identifier(value[key])
    if type(value["revision"]) is not int or not 0 < value["revision"] <= 2**63 - 1:
        refuse()
    sha(value["configuration_sha256"])
    members = value["members"]
    if type(members) is not list or not 0 < len(members) <= MAX_MEMBERS:
        refuse()
    ids = set()
    for member in members:
        fields(member, "vm_id agent_id provider vm_uid namespace source_sha256")
        for key in ("vm_id", "agent_id", "vm_uid"):
            identifier(member[key])
        if member["vm_id"] in ids or member["provider"] not in ("libvirt", "kubevirt"):
            refuse()
        ids.add(member["vm_id"])
        string(member["namespace"], empty=member["provider"] == "libvirt")
        from core.storage_semantics import NAME

        if member["provider"] == "libvirt":
            if member["namespace"] != "":
                refuse()
        elif (
            len(member["namespace"]) > 63 or NAME.fullmatch(member["namespace"]) is None
        ):
            refuse()
        sha(member["source_sha256"])
    target = value["target"]
    fields(target, "endpoint bucket region prefix capability_profile")
    for key, item in target.items():
        string(item, empty=key in ("region", "prefix"))
    from core.s3_ownership import storage_identity
    from core.storage_wire import Profile
    from typing import get_args

    endpoint, bucket = storage_identity(target)
    if (
        endpoint != target["endpoint"]
        or bucket != target["bucket"]
        or not endpoint.startswith("https://")
    ):
        refuse()
    if target["capability_profile"] not in get_args(Profile):
        refuse()
    from core.storage_semantics import validate_target

    validate_target(
        SimpleNamespace(
            endpoint=target["endpoint"],
            bucket=target["bucket"],
            region=target["region"],
            configuration_prefix=target["prefix"],
        ),
        lambda ok: None if ok else refuse(),
    )
    encryption = value["encryption"]
    fields(encryption, "format key_ref")
    if encryption["format"] == "none":
        if encryption["key_ref"] is not None:
            refuse()
    else:
        from core.storage_encryption import FORMAT

        if encryption["format"] != FORMAT or type(encryption["key_ref"]) is not str:
            refuse()
        parts = encryption["key_ref"].split(":")
        if len(parts) != 3 or parts[0] != "kek":
            refuse()
        identifier(parts[1])
        if not re.fullmatch("[0-9a-f]{16}|[0-9a-f]{64}", parts[2]):
            refuse()
    options = value["options"]
    if type(options) is not dict:
        refuse()
    automatic = options.get("backup_type") == "automatic"
    fields(
        options,
        "backup_type retention_days exclude_disks workers"
        + (" backup_policy" if automatic else ""),
    )
    if options["backup_type"] not in ("full", "incremental", "automatic"):
        refuse("unsupported_backup_type")
    if automatic:
        from core.scheduler_policy import BackupPolicyError, validate_policy

        try:
            validate_policy(options["backup_policy"])
        except BackupPolicyError:
            refuse("invalid_automatic_backup_policy")
    if (
        type(options["retention_days"]) is not int
        or not 1 <= options["retention_days"] <= 36500
    ):
        refuse()
    if options["workers"] is not None and (
        type(options["workers"]) is not int or not 1 <= options["workers"] <= 256
    ):
        refuse()
    disks = options["exclude_disks"]
    if type(disks) is not list or len(disks) > 256:
        refuse()
    for disk in disks:
        string(disk)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", disk) is None:
            refuse()
    if len(set(disks)) != len(disks):
        refuse()
    result = deepcopy(value)
    result["members"].sort(key=lambda m: m["vm_id"])
    result["options"]["exclude_disks"].sort()
    return result


def validate_drift(enrolled, observed):
    """Before occurrence creation ANY membership difference rejects the whole set."""
    enrolled, observed = compile_scope(enrolled), compile_scope(observed)
    if enrolled["members"] != observed["members"]:
        refuse("membership_drift")
    if enrolled != observed:
        refuse("scope_drift")
    return enrolled


def semantic_source_fingerprint(vm):
    """Enrollment identity, separate from per-attempt observation evidence.

    Retain every disk field except the KubeVirt PVC resource-version counter.
    The shared monitor and frozen request validators keep their own contracts.
    """
    disks = deepcopy(vm.disks)
    if type(disks) is not list or any(type(disk) is not dict for disk in disks):
        refuse("invalid_source_inventory")
    if vm.provider == "kubevirt":
        for disk in disks:
            if disk.get("source_type") in {"persistentVolumeClaim", "dataVolume"}:
                disk.pop("pvc_resource_version", None)
    return digest(
        dict(
            schema=1,
            vm_id=vm.id,
            agent_id=vm.agent_id,
            provider=vm.provider,
            uuid=vm.uuid,
            vm_uid=vm.vm_uid,
            namespace=vm.namespace,
            disks=disks,
        )
    )


def source_member(vm):
    if vm.inventory_present is not True:
        refuse("source_unavailable")
    return dict(
        vm_id=vm.id,
        agent_id=vm.agent_id,
        provider=vm.provider,
        vm_uid=vm.vm_uid,
        namespace=vm.namespace or "",
        source_sha256=semantic_source_fingerprint(vm),
    )
