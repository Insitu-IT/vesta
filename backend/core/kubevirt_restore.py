"""Tenant-authorized fresh KubeVirt restore planning and credential delivery.

The durable plan is nonsecret. It selects accepted catalog ancestry, never
bucket listings or today's VM definition. The agent verifies receipt-bound VM
metadata and every disk object before creating a new Halted VM.
"""

from copy import deepcopy
import base64
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.s3_ownership import StorageOwnershipError
from core.storage_restore import build_restore_bundle
from models import Agent, Backup, Organization, S3Publication, User, VM

SCHEMA = "vnbui-kubevirt-vm-restore/1"
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
SELECTED_DISK_PROFILE = "kubevirt-selected-disks/1"


def require_restore_capability(agent, bundle):
    """Refuse schema-2 work before credential delivery to an older/downgraded agent."""
    if not any(
        member["request"]["plan"]["source"]["schema"] == 2
        for member in bundle["members"]
    ):
        return
    capabilities = agent.capabilities if agent is not None else None
    profiles = (
        capabilities.get("kubevirt_restore_profiles")
        if type(capabilities) is dict
        else None
    )
    if (
        type(profiles) is not list
        or not 1 <= len(profiles) <= 8
        or any(type(profile) is not str for profile in profiles)
        or len(set(profiles)) != len(profiles)
        or capabilities.get("provider") != "kubevirt"
        or SELECTED_DISK_PROFILE not in profiles
    ):
        raise StorageOwnershipError(
            "Schema-2 KubeVirt restore requires kubevirt-selected-disks/1 agent capability"
        )


class DiskTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    volume_name: str
    pvc_name: str
    storage_class: str
    access_mode: str
    volume_mode: str
    capacity_bytes: int = Field(gt=0)


class NetworkTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str
    type: str
    network_name: str


class RestoreTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    namespace: str
    vm_name: str
    disks: list[DiskTarget] = Field(min_length=1, max_length=32)
    networks: list[NetworkTarget] = Field(max_length=32)
    dependencies: dict[str, str]


def _name(value):
    return isinstance(value, str) and 0 < len(value) <= 63 and NAME.fullmatch(value)


def validate_target(data, source, vm_name):
    try:
        target = RestoreTarget.model_validate(data).model_dump()
    except ValidationError:
        raise StorageOwnershipError(
            "Explicit fresh-VM target mappings are required"
        ) from None
    if not _name(target["namespace"]) or not _name(target["vm_name"]):
        raise StorageOwnershipError("Target namespace and VM name must be DNS labels")
    if target["namespace"] == source["namespace"] and target["vm_name"] == vm_name:
        raise StorageOwnershipError("The source VM cannot be a restore destination")
    volumes = {v["name"]: v for v in source["volumes"]}
    seen, claims = set(), set()
    for disk in target["disks"]:
        volume = volumes.get(disk["volume_name"])
        if (
            volume is None
            or disk["volume_name"] in seen
            or disk["pvc_name"] in claims
            or not _name(disk["pvc_name"])
            or not _name(disk["storage_class"])
            or disk["access_mode"] not in {"ReadWriteOnce", "ReadWriteMany"}
            or disk["volume_mode"] not in {"Filesystem", "Block"}
            or disk["capacity_bytes"] < volume["capacity_bytes"]
            or (
                target["namespace"] == source["namespace"]
                and disk["pvc_name"]
                in {
                    v["pvc_name"]
                    for v in source.get("native_volumes", source["volumes"])
                }
            )
        ):
            raise StorageOwnershipError(
                "Invalid, duplicate, source or undersized PVC mapping"
            )
        seen.add(disk["volume_name"])
        claims.add(disk["pvc_name"])
    if seen != set(volumes):
        raise StorageOwnershipError(
            "Every protected disk must have a fresh PVC mapping"
        )
    networks, pods = set(), 0
    for network in target["networks"]:
        if not _name(network["name"]) or network["name"] in networks:
            raise StorageOwnershipError("Invalid or duplicate network mapping")
        networks.add(network["name"])
        if network["type"] == "pod" and network["network_name"] == "":
            pods += 1
        elif network["type"] != "multus" or not _name(network["network_name"]):
            raise StorageOwnershipError(
                "Map networks to pod or target-namespace Multus NADs"
            )
    if pods > 1:
        raise StorageOwnershipError("Only one pod network is supported")
    for key, value in target["dependencies"].items():
        kind, _, name = key.partition("/")
        if kind not in {"secret", "configMap"} or not _name(name) or not _name(value):
            raise StorageOwnershipError(
                "Dependencies require explicit secret/name or configMap/name mappings"
            )
    return target


def build_plan(db, *, backup_id, org_id, actor_id, restore_id, target):
    """Lock in retention's org→source VM→backup order before recording custody."""
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
    if vm is None or vm.provider != "kubevirt":
        raise StorageOwnershipError("Accepted KubeVirt source is required")
    bundle = build_restore_bundle(db, backup_id, org_id)
    ids = [m["request"]["backup_id"] for m in bundle["members"]]
    locked = (
        db.query(Backup)
        .filter(Backup.org_id == org_id, Backup.id.in_(ids))
        .order_by(Backup.id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    if len(locked) != len(ids) or any(
        b.status != "completed" or b.vm_id != vm.id for b in locked
    ):
        raise StorageOwnershipError("Restore chain changed during admission")
    request = bundle["members"][-1]["request"]
    if request["agent_id"] != vm.agent_id:
        raise StorageOwnershipError("Source agent ownership changed")
    agent = db.query(Agent).filter_by(id=vm.agent_id, org_id=org_id).one_or_none()
    require_restore_capability(agent, bundle)
    mapped = validate_target(
        target, request["plan"]["source"], request["plan"]["vm_name"]
    )
    existing = (
        db.query(VM)
        .filter_by(
            org_id=org_id,
            agent_id=vm.agent_id,
            namespace=mapped["namespace"],
            name=mapped["vm_name"],
            inventory_present=True,
        )
        .first()
    )
    if existing is not None:
        raise StorageOwnershipError("Target VM already exists")
    return dict(
        schema=SCHEMA,
        org_id=org_id,
        agent_id=vm.agent_id,
        restore_id=restore_id,
        target=mapped,
        bundle=deepcopy(bundle),
    )


def hydrate_request(db, restore):
    """Resolve exact retained member DEKs only after dispatch admission.

    Nothing returned here may enter logs, activities or the durable backend plan.
    Agent TLS and its private journal/Secret are required at the sending boundary.
    """
    from core.settings_service import SettingsService
    from core.storage_attempt_key import unwrap_retained_attempt_key

    plan = deepcopy(restore.kubevirt_plan)
    if (
        not isinstance(plan, dict)
        or plan.get("schema") != SCHEMA
        or (
            plan.get("restore_id") != restore.id or plan.get("org_id") != restore.org_id
        )
    ):
        raise StorageOwnershipError("Persisted restore plan is unavailable")
    selected = build_restore_bundle(db, restore.backup_id, restore.org_id)
    if selected != plan["bundle"]:
        raise StorageOwnershipError("Accepted restore ancestry changed")
    agent = (
        db.query(Agent)
        .filter_by(id=plan["agent_id"], org_id=restore.org_id)
        .one_or_none()
    )
    require_restore_capability(agent, selected)
    cfg = SettingsService(db).get_s3_config()
    target = selected["members"][0]["request"]["plan"]["target"]
    if not cfg or any(
        cfg.get(key) != target[key] for key in ("endpoint", "bucket", "region")
    ):
        raise StorageOwnershipError(
            "Configured S3 read credentials must match the accepted target"
        )
    if not cfg.get("access_key") or not cfg.get("secret_key") or not target["region"]:
        raise StorageOwnershipError(
            "Explicit signing region and read credentials are required"
        )
    plan["s3"] = {
        key: cfg[key]
        for key in ("endpoint", "bucket", "region", "access_key", "secret_key")
    }
    if cfg.get("session_token"):
        plan["s3"]["session_token"] = cfg["session_token"]
    plan["keys"] = {}
    for member in selected["members"]:
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
            raise StorageOwnershipError("Retained member custody is unavailable")
        dek = unwrap_retained_attempt_key(db, claim, request)
        if dek is not None:
            plan["keys"][request["backup_id"]] = base64.b64encode(dek).decode("ascii")
    return {"restore_id": restore.id, "kubevirt": plan}


def apply_progress(restore, response):
    if not isinstance(response, dict) or response.get("restore_id") != restore.id:
        raise StorageOwnershipError("Restore progress identity differs")
    state = response.get("status")
    progress = response.get("progress_percent")
    if (
        state not in {"running", "completed", "cleanup_required"}
        or type(progress) is not int
        or not 0 <= progress <= 100
    ):
        raise StorageOwnershipError("Invalid restore progress")
    result = response.get("result")
    if state == "completed":
        target = restore.kubevirt_plan["target"]
        if (
            not isinstance(result, dict)
            or result.get("namespace") != target["namespace"]
            or result.get("vm_name") != target["vm_name"]
            or result.get("run_strategy") != "Halted"
            or not isinstance(result.get("pvc_uids"), dict)
            or set(result["pvc_uids"]) != {d["pvc_name"] for d in target["disks"]}
            or any(not isinstance(v, str) or not v for v in result["pvc_uids"].values())
            or any(
                not isinstance(result.get(k), str) or not result[k]
                for k in ("vm_uid", "job_uid", "job_name", "plan_sha256")
            )
        ):
            raise StorageOwnershipError(
                "Completed restore lacks exact target resource identities"
            )
        restore.kubevirt_result = {
            k: result[k]
            for k in (
                "namespace",
                "vm_name",
                "vm_uid",
                "pvc_uids",
                "job_uid",
                "job_name",
                "plan_sha256",
                "run_strategy",
            )
        }
    restore.status, restore.progress = state, progress
    restore.error_message = (
        "Restore held; inspect agent journal and recorded PVC/Job identities. Partial PVCs must not be used."
        if state == "cleanup_required"
        else None
    )
    if state == "cleanup_required":
        reason = response.get("error_message")
        if isinstance(reason, str) and reason.startswith("restore held:"):
            restore.error_message = reason[:1024]
