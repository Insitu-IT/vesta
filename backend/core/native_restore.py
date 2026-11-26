"""Tenant-enrolled fresh native restore, retaining custody until inactive VM."""

import base64
from copy import deepcopy
import re
import uuid

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.native_restore_bundle import build_native_bundle
from core.s3_ownership import StorageOwnershipError
from models import Backup, Organization, S3Publication, User, VM

SCHEMA = "vnbui-native-vm-restore/1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class NetworkTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_mac: str
    network: str


class NativeTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    vm_name: str
    disks: list[str] = Field(min_length=1, max_length=128)
    drop_excluded_disks: list[str] = Field(max_length=128)
    networks: list[NetworkTarget] = Field(max_length=128)


def validate_target(value, manifest, source_name):
    try:
        target = NativeTarget.model_validate(value).model_dump()
    except ValidationError:
        raise StorageOwnershipError(
            "Explicit fresh native VM mappings are required"
        ) from None
    if (
        not NAME.fullmatch(target["vm_name"])
        or target["vm_name"] == source_name
        or target["disks"] != [disk["target"] for disk in manifest["disks"]]
        or target["drop_excluded_disks"] != manifest["exclusions"]
    ):
        raise StorageOwnershipError(
            "Fresh name, all protected disks and explicit excluded-disk removal are required"
        )
    seen = set()
    for network in target["networks"]:
        if (
            not MAC.fullmatch(network["source_mac"])
            or not NAME.fullmatch(network["network"])
            or network["source_mac"] in seen
        ):
            raise StorageOwnershipError(
                "Explicit unique source MAC to destination libvirt network mappings are required"
            )
        seen.add(network["source_mac"])
    target["vm_uuid"] = str(uuid.uuid4())
    return target


def build_plan(db, *, backup_id, org_id, actor_id, restore_id, target):
    org = db.query(Organization).filter_by(id=org_id).with_for_update().one_or_none()
    actor = db.query(User).filter_by(id=actor_id, org_id=org_id).one_or_none()
    if (
        org is None
        or org.enabled is not True
        or actor is None
        or actor.is_active is not True
        or actor.role not in {"admin", "operator"}
    ):
        raise StorageOwnershipError("Restore principal is unavailable")
    selected = db.query(Backup).filter_by(id=backup_id, org_id=org_id).one_or_none()
    if selected is None:
        raise StorageOwnershipError("Accepted backup is unavailable")
    vm = (
        db.query(VM)
        .filter_by(id=selected.vm_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if vm is None or vm.provider != "libvirt":
        raise StorageOwnershipError("Accepted native source is required")
    bundle = build_native_bundle(db, backup_id, org_id)
    ids = [member["request"]["backup_id"] for member in bundle["members"]]
    locked = (
        db.query(Backup)
        .filter(Backup.org_id == org_id, Backup.id.in_(ids))
        .order_by(Backup.id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    if len(locked) != len(ids) or any(
        member.status != "completed" or member.vm_id != vm.id for member in locked
    ):
        raise StorageOwnershipError("Restore chain changed during admission")
    selected = bundle["members"][-1]
    if selected["request"]["agent_id"] != vm.agent_id:
        raise StorageOwnershipError("Source agent ownership changed")
    target = validate_target(target, selected["push_result"]["manifest"], vm.name)
    if (
        db.query(VM)
        .filter_by(
            org_id=org_id,
            agent_id=vm.agent_id,
            name=target["vm_name"],
            inventory_present=True,
        )
        .first()
        is not None
    ):
        raise StorageOwnershipError("Destination VM already exists")
    return dict(
        schema=SCHEMA,
        org_id=org_id,
        agent_id=vm.agent_id,
        restore_id=restore_id,
        target=target,
        bundle=bundle,
    )


def hydrate_request(db, restore):
    from core.settings_service import SettingsService
    from core.storage_attempt_key import unwrap_retained_attempt_key

    plan = deepcopy(restore.native_plan)
    if (
        not isinstance(plan, dict)
        or plan.get("schema") != SCHEMA
        or plan.get("org_id") != restore.org_id
        or plan.get("restore_id") != restore.id
    ):
        raise StorageOwnershipError("Native restore plan unavailable")
    bundle = build_native_bundle(db, restore.backup_id, restore.org_id)
    if plan["bundle"] != bundle:
        raise StorageOwnershipError("Accepted restore ancestry changed")
    cfg = SettingsService(db).get_s3_config()
    target = bundle["members"][0]["request"]["plan"]["target"]
    if (
        not cfg
        or any(cfg.get(key) != target[key] for key in ("endpoint", "bucket", "region"))
        or not target["region"]
        or not cfg.get("access_key")
        or not cfg.get("secret_key")
    ):
        raise StorageOwnershipError(
            "Configured S3 read credentials must match the accepted target and region"
        )
    plan["s3"] = {
        key: cfg[key]
        for key in ("endpoint", "bucket", "region", "access_key", "secret_key")
    }
    if cfg.get("session_token"):
        plan["s3"]["session_token"] = cfg["session_token"]
    plan["keys"] = {}
    for member in bundle["members"]:
        request = member["request"]
        if (
            request["org_id"] != restore.org_id
            or request["agent_id"] != plan["agent_id"]
        ):
            raise StorageOwnershipError("Restore member owner differs")
        claim = (
            db.query(S3Publication)
            .filter_by(
                id=request["reservation_id"],
                org_id=restore.org_id,
                backup_id=request["backup_id"],
                kind="payload",
                state="published",
            )
            .one_or_none()
        )
        if claim is None:
            raise StorageOwnershipError("Retained native member custody unavailable")
        dek = unwrap_retained_attempt_key(db, claim, request)
        if dek is not None:
            plan["keys"][request["backup_id"]] = base64.b64encode(dek).decode("ascii")
    return dict(restore_id=restore.id, native=plan)


def apply_progress(restore, response):
    if not isinstance(response, dict) or response.get("restore_id") != restore.id:
        raise StorageOwnershipError("Restore progress identity differs")
    state, progress = response.get("status"), response.get("progress_percent")
    if (
        state not in {"running", "completed", "cleanup_required"}
        or type(progress) is not int
        or not 0 <= progress <= 100
    ):
        raise StorageOwnershipError("Invalid native restore progress")
    if state == "completed":
        result, target = response.get("result"), restore.native_plan["target"]
        if (
            not isinstance(result, dict)
            or any(result.get(key) != target[key] for key in ("vm_name", "vm_uuid"))
            or result.get("state") != "shutoff"
            or not isinstance(result.get("plan_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", result["plan_sha256"])
        ):
            raise StorageOwnershipError(
                "Completed native restore lacks inactive destination identity"
            )
        disks = result.get("disks")
        protected = {
            d["target"]: d
            for d in restore.native_plan["bundle"]["members"][-1]["push_result"][
                "manifest"
            ]["disks"]
        }
        if not isinstance(disks, list) or len(disks) != len(protected):
            raise StorageOwnershipError(
                "Completed native restore lacks exact disk identities"
            )
        seen = set()
        for disk in disks:
            if not isinstance(disk, dict) or set(disk) != {
                "target",
                "path",
                "size_bytes",
                "sha256",
            }:
                raise StorageOwnershipError("Invalid restored disk result")
            name = disk["target"]
            if (
                not isinstance(name, str)
                or name not in protected
                or name in seen
                or type(disk["size_bytes"]) is not int
                or disk["size_bytes"] != protected[name]["virtual_size"]
                or not isinstance(disk["path"], str)
                or not disk["path"].endswith(
                    "/" + restore.id + "/disks/" + name + ".raw"
                )
                or not disk["path"].startswith("/")
                or any(part in {".", ".."} for part in disk["path"].split("/"))
                or not isinstance(disk["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", disk["sha256"])
            ):
                raise StorageOwnershipError(
                    "Restored disk membership or identity differs"
                )
            seen.add(name)
        restore.native_result = {
            key: result[key]
            for key in ("vm_name", "vm_uuid", "state", "disks", "plan_sha256")
        }
    restore.status, restore.progress = state, progress
    restore.error_message = (
        "Restore held; inspect private native journal and fresh destination. Do not use partial images."
        if state == "cleanup_required"
        else None
    )
