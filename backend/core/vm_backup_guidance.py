"""Read-only advice from the caller's VM inventory, agent heartbeat and catalog."""

from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field
from sqlalchemy import func
from sqlalchemy.orm import Load

from core.agent_scope import source_allowed
from core.native_lineage import require_parent_after_fence
from core.native_inventory import native_source_disks
from core.native_manifest import HASH
from core.s3_ownership import StorageOwnershipError
from core.storage_lineage import stable_source
from core.storage_semantics import validate_volume_set, IDENTITY, digest
from core.storage_source import supports_native_disks
from core.storage_wire import Volume, validate_transaction
from models import Backup, StorageLineageGeneration, StorageLineageHead


class CapacityObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["journal", "native_capture", "unknown"] = "unknown"
    state: Literal["unknown", "measured", "low", "at_limit"] = "unknown"
    observed_at: datetime | None = None
    free_bytes: int | None = None
    total_bytes: int | None = None
    used_percent: float | None = None
    admission_used_percent: float | None = None


class BackupGuidance(BaseModel):
    """Candidate modes still require normal source, checkpoint, target, key and capacity admission."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["full", "incremental", "blocked", "unknown"] = "unknown"
    reason: Literal[
        "inventory_unknown",
        "inventory_stale",
        "vm_absent",
        "provider_unknown",
        "provider_offline",
        "scope_unconfirmed",
        "identity_unknown",
        "domain_inactive",
        "vmi_stopped",
        "vmi_not_ready",
        "vmi_paused",
        "vmi_io_paused",
        "cbt_disabled",
        "cbt_pending",
        "cbt_pending_restart",
        "cbt_unknown",
        "invalid_selection",
        "exclude_unsupported",
        "no_persistent_disks",
        "no_qcow2_disks",
        "persistent_disk_unavailable",
        "disk_profile_required",
        "storage_at_limit",
        "storage_unmeasured",
        "agent_full_only",
        "checkpoint_missing",
        "backup_api_missing",
        "backup_api_unknown",
        "checkpoint_changed",
        "checkpoint_recorded",
        "tracker_unobserved",
        "tracker_conflict",
        "tracker_missing",
        "tracker_changed",
        "native_checkpoint_unverified",
    ] = "inventory_unknown"
    inventory_observed_at: datetime | None = None
    cbt_state: Literal[
        "enabled", "disabled", "pending", "pending_restart", "unknown", "not_applicable"
    ] = "unknown"
    cbt_source: Literal["vm", "vmi"] | None = None
    cbt_history_capacity: Literal["unmeasured"] = "unmeasured"
    storage: CapacityObservation
    affected_disks: list[str] = Field(default_factory=list)
    missing_apis: list[
        Literal[
            "virtualmachinebackups",
            "virtualmachinebackuptrackers",
            "virtualmachineexports",
        ]
    ] = Field(default_factory=list)
    persistent_disks: list[str] = Field(default_factory=list)
    volume_snapshot_statuses: dict[str, bool] = Field(
        default_factory=dict,
        description="VM controller snapshot observations by disk target. Omitted targets have no usable report.",
        json_schema_extra={
            "x-open-schema-reason": "Property names are the VM's observed persistent disk targets."
        },
    )
    group_snapshot_api: Literal["served", "not_served", "unknown"] = "unknown"
    storage_group_snapshot: Literal["unverified"] = "unverified"
    group_snapshot_execution: Literal["unavailable"] = "unavailable"

    @computed_field
    @property
    def documentation_url(self) -> str:
        if self.reason.startswith(
            ("cbt_", "checkpoint_", "tracker_", "native_checkpoint")
        ):
            return "https://vestabackup.com/docs/storage-compatibility/#check-changed-block-tracking"
        if self.reason.startswith("storage_"):
            return "https://vestabackup.com/docs/manuals/backup-safety/"
        if self.reason in (
            "exclude_unsupported",
            "no_persistent_disks",
            "no_qcow2_disks",
            "persistent_disk_unavailable",
            "disk_profile_required",
            "invalid_selection",
        ):
            return "https://vestabackup.com/docs/storage-compatibility/"
        return "https://vestabackup.com/docs/installation-requirements/"


def _instant(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _fresh(value, now, minutes):
    return value is not None and timedelta() <= now - value < timedelta(minutes=minutes)


def _confirmed_scope(agent, namespace):
    config = agent.config or {}
    scope = agent.metrics.get("scope")
    if not isinstance(config, dict) or not isinstance(namespace, str) or not namespace:
        return False
    if "selected_source_namespaces" in config and not isinstance(
        config["selected_source_namespaces"], list
    ):
        return False
    if scope is not None and (
        not isinstance(scope, dict)
        or any(
            not isinstance(scope.get(k), list)
            for k in ("source_namespaces", "selected_source_namespaces")
        )
    ):
        return False
    return source_allowed(agent, namespace)


def _capacity(metrics, capabilities, now):
    role = metrics.get("storage_role")
    result = CapacityObservation(
        role=role if role in ("journal", "native_capture") else "unknown",
        observed_at=_instant(metrics.get("updated_at")),
    )
    free, total = metrics.get("backup_storage_free_bytes"), metrics.get(
        "backup_storage_total_bytes"
    )
    used = metrics.get("disk_usage_percent")
    if (
        result.role == "unknown"
        or not _fresh(result.observed_at, now, 5)
        or metrics.get("storage_measurement_error")
        or type(free) is not int
        or type(total) is not int
        or not 0 <= free <= total
        or not 0 < total < 2**63
        or type(used) not in (float, int)
        or not 0 <= used <= 100
    ):
        return result
    result.free_bytes, result.total_bytes, result.used_percent = free, total, used
    limit = capabilities.get("storage_admission_used_percent")
    if type(limit) in (float, int) and 0 < limit <= 100:
        result.admission_used_percent = limit
    reasons = metrics.get("health_reasons")
    result.state = (
        "low" if isinstance(reasons, list) and "storage_low" in reasons else "measured"
    )
    if (
        result.admission_used_percent is not None
        and used >= result.admission_used_percent
    ):
        result.state = "at_limit"
    return result


def _disk_advice(vm, excluded, result):
    disks = vm.disks
    limit = 256 if vm.provider == "kubevirt" else 128
    if type(disks) is not list or not 0 < len(disks) <= limit:
        return "unknown", "inventory_unknown"
    if any(
        type(d) is not dict
        or type(d.get("target")) is not str
        or not IDENTITY.fullmatch(d["target"])
        for d in disks
    ):
        return "unknown", "inventory_unknown"
    targets = {d["target"] for d in disks}
    if len(targets) != len(disks):
        return "unknown", "inventory_unknown"
    if not excluded <= targets:
        return "blocked", "invalid_selection"
    if vm.provider == "libvirt":
        try:
            disks = native_source_disks(disks)
        except StorageOwnershipError:
            return "unknown", "inventory_unknown"
        if any(
            not d["source"].startswith("/") or d["format"] not in ("qcow2", "raw")
            for d in disks
        ):
            return "unknown", "inventory_unknown"
        unsupported = {d["target"] for d in disks if d["format"] != "qcow2"}
        if unsupported == targets:
            return "blocked", "no_qcow2_disks"
        if not targets - unsupported - excluded:
            return "blocked", "invalid_selection"
    else:
        if any(
            d.get("source_type")
            not in ("persistentVolumeClaim", "dataVolume", "unsupported")
            for d in disks
        ):
            return "unknown", "inventory_unknown"
        native = [d for d in disks if d["source_type"] != "unsupported"]
        if not native:
            return "blocked", "no_persistent_disks"
        result.persistent_disks = sorted(d["target"] for d in native)
        if not set(result.persistent_disks) - excluded:
            return "blocked", "invalid_selection"
        apis = (vm.vm_metadata or {}).get("backup_apis")
        apis = apis if isinstance(apis, dict) else {}
        if apis.get("group_snapshot") in ("served", "not_served"):
            result.group_snapshot_api = apis["group_snapshot"]
        reported = (vm.vm_metadata or {}).get("volume_snapshot_statuses")
        if type(reported) is dict:
            result.volume_snapshot_statuses = {
                name: reported[name]
                for name in result.persistent_disks
                if type(reported.get(name)) is bool
            }
        required = (
            "virtualmachinebackups",
            "virtualmachinebackuptrackers",
            "virtualmachineexports",
        )
        result.missing_apis = [
            name for name in required if apis.get(name) == "not_served"
        ]
        if result.missing_apis:
            return "blocked", "backup_api_missing"
        if result.cbt_state != "enabled":
            if result.cbt_state == "unknown":
                return "unknown", "cbt_unknown"
            return "blocked", "cbt_" + result.cbt_state
        if any(apis.get(name) != "served" for name in required):
            return "unknown", "backup_api_unknown"
        result.affected_disks = [
            d["target"]
            for d in native
            if d.get("backup_eligible") is False or d.get("source_error")
        ]
        if result.affected_disks:
            return "blocked", "persistent_disk_unavailable"
        if native:
            try:

                def require(valid):
                    if not valid:
                        raise ValueError("Incomplete disk observation")

                require(
                    all(
                        d.get("backup_eligible") is True
                        and d.get("pvc_namespace") == vm.namespace
                        for d in native
                    )
                )
                validate_volume_set(
                    [Volume.model_validate(_volume(d)) for d in native], require
                )
            except ValueError:
                return "unknown", "inventory_unknown"
        unsupported = targets - set(result.persistent_disks)
        if excluded.intersection(result.persistent_disks):
            try:
                if not supports_native_disks(vm.agent):
                    return "blocked", "disk_profile_required"
            except StorageOwnershipError:
                return "unknown", "inventory_unknown"
    result.affected_disks = sorted(unsupported - excluded)
    if result.affected_disks:
        return "blocked", "exclude_unsupported"
    return None


def _volume(disk):
    return {
        "name": disk["target"],
        **{
            key: disk.get(key)
            for key in (
                "pvc_name",
                "pvc_uid",
                "pvc_resource_version",
                "capacity_bytes",
                "mapping",
            )
        },
    }


def _checkpoint(db, vm, excluded, supports_incremental):
    # Observe the latest accepted head only. Avoid traversing or locking a
    # potentially large chain on every selection change in the backup dialog.
    tracker = None
    if vm.provider == "kubevirt":
        tracker = (vm.vm_metadata or {}).get("backup_tracker")
        if not isinstance(tracker, dict) or tracker.get("state") not in (
            "absent",
            "observed",
            "source_mismatch",
        ):
            return "unknown", "tracker_unobserved"
        if tracker["state"] == "source_mismatch":
            return "blocked", "tracker_conflict"
        if tracker["state"] == "observed" and any(
            type(tracker.get(key)) is not str or not HASH.fullmatch(tracker[key])
            for key in ("uid_sha256", "checkpoint_sha256")
        ):
            return "unknown", "tracker_unobserved"
    if supports_incremental is not True:
        return (
            ("full", "agent_full_only")
            if supports_incremental is False
            else ("unknown", "provider_unknown")
        )
    row = (
        db.query(StorageLineageGeneration, Backup)
        .options(
            Load(StorageLineageGeneration).load_only(
                StorageLineageGeneration.accepted_request,
                StorageLineageGeneration.tracker_uid,
                StorageLineageGeneration.checkpoint,
            ),
            Load(Backup).load_only(
                Backup.id, Backup.native_job_intent, Backup.native_execution
            ),
        )
        .join(
            StorageLineageHead,
            StorageLineageHead.generation_id == StorageLineageGeneration.id,
        )
        .join(Backup, Backup.id == StorageLineageGeneration.backup_id)
        .filter(
            StorageLineageHead.org_id == vm.org_id,
            StorageLineageHead.vm_id == vm.id,
            StorageLineageHead.state == "current",
            StorageLineageGeneration.org_id == vm.org_id,
            StorageLineageGeneration.vm_id == vm.id,
            StorageLineageGeneration.state == "accepted",
            Backup.org_id == vm.org_id,
            Backup.vm_id == vm.id,
            Backup.status == "completed",
            *(
                getattr(StorageLineageHead, k) == getattr(StorageLineageGeneration, k)
                for k in (
                    "root_backup_id",
                    "tracker_uid",
                    "checkpoint",
                    "manifest_receipt_sha256",
                )
            ),
        )
        .one_or_none()
    )
    if row is None:
        return "full", "checkpoint_missing"
    generation, parent = row
    if tracker is not None:
        if tracker["state"] == "absent":
            return "full", "tracker_missing"
        if tracker["uid_sha256"] != digest(generation.tracker_uid) or tracker[
            "checkpoint_sha256"
        ] != digest(generation.checkpoint):
            return "full", "tracker_changed"
    try:
        request = validate_transaction(generation.accepted_request)
    except (ValueError, StorageOwnershipError):
        return "full", "checkpoint_changed"
    plan = request["plan"]
    if (
        request.get("agent_id") != vm.agent_id
        or request.get("org_id") != vm.org_id
        or request.get("backup_id") != parent.id
        or plan.get("provider") != vm.provider
        or plan.get("exclusions") != sorted(excluded)
    ):
        return "full", "checkpoint_changed"
    if vm.provider == "libvirt":
        source = (
            parent.native_job_intent.get("source")
            if type(parent.native_job_intent) is dict
            else None
        )
        if (
            type(source) is not dict
            or source.get("domain_uuid") != vm.uuid
            or plan["source"]["vm_id"] != vm.id
            or plan["source"]["inventory"]["domain_uuid"] != vm.uuid
            or generation.tracker_uid != vm.uuid
            or source.get("disks") != native_source_disks(vm.disks)
        ):
            return "full", "checkpoint_changed"
        last_fence = (
            db.query(func.max(Backup.native_fenced_failure_xid))
            .filter_by(org_id=vm.org_id, vm_id=vm.id)
            .scalar()
        )
        try:
            require_parent_after_fence(parent, last_fence)
        except StorageOwnershipError:
            return "full", "checkpoint_changed"
        return "unknown", "native_checkpoint_unverified"
    else:
        source = plan["source"]
        native = [_volume(d) for d in vm.disks if d["source_type"] != "unsupported"]
        observed = dict(
            schema=source["schema"],
            vm_id=vm.id,
            agent_id=vm.agent_id,
            vm_uid=vm.vm_uid,
            namespace=vm.namespace,
            volumes=[v for v in native if v["name"] not in excluded],
        )
        if source["schema"] == 2:
            observed["native_volumes"] = native
        elif len(native) != len(observed["volumes"]):
            return "full", "checkpoint_changed"
        if plan["vm_name"] != vm.name or stable_source(source) != stable_source(
            observed
        ):
            return "full", "checkpoint_changed"
    return "incremental", "checkpoint_recorded"


def backup_guidance(db, vm, exclude_disks, *, now=None):
    now = now or datetime.now(timezone.utc)
    agent = vm.agent
    if agent is None or agent.org_id != vm.org_id:
        return BackupGuidance(reason="provider_unknown", storage=CapacityObservation())
    metrics = agent.metrics if agent and isinstance(agent.metrics, dict) else {}
    capabilities = (
        agent.capabilities if agent and isinstance(agent.capabilities, dict) else {}
    )
    observation = _instant(vm.last_observed_at)
    expected_role = {"libvirt": "native_capture", "kubevirt": "journal"}.get(
        vm.provider
    )
    storage = (
        _capacity(metrics, capabilities, now)
        if metrics.get("storage_role") == expected_role
        else CapacityObservation()
    )
    result = BackupGuidance(storage=storage, inventory_observed_at=observation)
    if vm.provider == "libvirt":
        result.cbt_state = "not_applicable"
    if vm.inventory_present is False:
        result.mode, result.reason = "blocked", "vm_absent"
    elif not _fresh(observation, now, 10):  # Two five-minute inventory reconciliations.
        result.reason = (
            "inventory_stale"
            if observation and observation <= now
            else "inventory_unknown"
        )
    elif vm.provider not in ("kubevirt", "libvirt"):
        result.reason = "provider_unknown"
    elif metrics.get("provider_accessible") is not True or not _fresh(
        _instant(metrics.get("updated_at")), now, 5
    ):
        result.reason = "provider_offline"
    elif (
        metrics.get("provider") != vm.provider
        or capabilities.get("provider") != vm.provider
        or metrics.get("backup_method")
        != {"kubevirt": "kubevirt_pull_transaction", "libvirt": "native_push"}[
            vm.provider
        ]
    ):
        result.reason = "provider_unknown"
    elif (
        not vm.vm_uid
        or vm.vm_uid != vm.uuid
        or (vm.provider == "kubevirt" and vm.state == "running" and not vm.vmi_uid)
    ):
        result.reason = "identity_unknown"
    elif vm.provider == "kubevirt" and not _confirmed_scope(agent, vm.namespace):
        result.reason = "scope_unconfirmed"
    elif vm.provider == "libvirt" and vm.state != "running":
        result.reason = "domain_inactive"
    else:
        if vm.provider == "kubevirt":
            metadata = vm.vm_metadata if isinstance(vm.vm_metadata, dict) else {}
            cbt = metadata.get("changed_block_tracking")
            source = "vmi" if vm.vmi_uid else "vm"
            if isinstance(cbt, dict) and cbt.get("source") == source:
                result.cbt_source = source
                state = cbt.get("state")
                if state in ("Enabled", "Disabled"):
                    result.cbt_state = state.lower()
                elif state == "PendingRestart":
                    result.cbt_state = "pending_restart"
                elif state in ("Pending", "Initializing"):
                    result.cbt_state = "pending"
            if vm.state in ("stopped", "shutoff"):
                result.mode, result.reason = "blocked", "vmi_stopped"
                return result
            readiness = metadata.get("backup_instance_readiness")
            if readiness in ("paused", "io_paused") or vm.state == "paused":
                result.mode, result.reason = "blocked", (
                    "vmi_io_paused" if readiness == "io_paused" else "vmi_paused"
                )
                return result
            if not vm.vmi_uid or vm.state != "running" or readiness != "ready":
                result.reason = "vmi_not_ready"
                return result
        excluded = set(exclude_disks)
        if len(excluded) != len(exclude_disks):
            result.mode, result.reason = "blocked", "invalid_selection"
            return result
        decision = _disk_advice(vm, excluded, result)
        if decision:
            result.mode, result.reason = decision
        elif result.storage.state == "at_limit":
            result.mode, result.reason = "blocked", "storage_at_limit"
        elif result.storage.state == "unknown" and metrics.get(
            "storage_measurement_error"
        ):
            result.reason = "storage_unmeasured"
        else:
            result.mode, result.reason = _checkpoint(
                db, vm, excluded, metrics.get("supports_incremental")
            )
    return result
