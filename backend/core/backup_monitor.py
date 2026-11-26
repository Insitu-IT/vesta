"""Scoped polling authority. Progress is not publication or recovery authority."""

from dataclasses import dataclass
import json

from models import Agent, Backup, Organization, OrganizationDefault, User, VM
from core.tenant_context import commercial_mode


class MonitorRefused(ValueError):
    pass


def stale_backup_candidates(db):
    """Lock only jobs whose liveness still belongs to the legacy sweep.

    Reserved capacity is durable producer custody, not an expiring heartbeat
    lease. Failing that row would disable an otherwise recoverable transaction.
    Skip rows being admitted; a concurrent reservation cannot race this sweep's
    decision once its row lock is held.
    """
    return (
        db.query(Backup)
        .filter(
            Backup.status.in_(["running", "pending"]),
            Backup.capacity_state.in_(["unreserved", "released"]),
        )
        .populate_existing()
        .with_for_update(skip_locked=True)
        .all()
    )


@dataclass(frozen=True)
class MonitorBinding:
    backup_id: str
    org_id: str
    actor_id: str
    agent_id: str
    source: str
    endpoint: str


def source_identity(vm):
    return json.dumps(
        [vm.id, vm.agent_id, vm.provider, vm.uuid, vm.vm_uid, vm.namespace, vm.disks],
        sort_keys=True,
        separators=(",", ":"),
    )


def admit(db, binding, endpoint):
    from core.upload_retry import _identifier

    if not all(
        _identifier(value)
        for value in (
            binding.backup_id,
            binding.org_id,
            binding.actor_id,
            binding.agent_id,
        )
    ):
        raise MonitorRefused("Monitor identity unavailable")

    def locked(model, **fields):
        return (
            db.query(model)
            .filter_by(**fields)
            .populate_existing()
            .with_for_update(nowait=True)
            .one_or_none()
        )

    if not commercial_mode():
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None or assignment.org_id != binding.org_id:
            raise MonitorRefused("Monitor authority unavailable")
    org = locked(Organization, id=binding.org_id)
    actor = locked(User, id=binding.actor_id, org_id=binding.org_id)
    backup = locked(Backup, id=binding.backup_id, org_id=binding.org_id)
    if (
        org is None
        or org.enabled is not True
        or actor is None
        or actor.is_active is not True
        or actor.role not in {"admin", "operator"}
        or backup is None
        or backup.initiating_user_id != binding.actor_id
        or backup.status not in {"pending", "running", "uploading"}
    ):
        raise MonitorRefused("Monitor authority unavailable")
    vm = locked(VM, id=backup.vm_id, org_id=binding.org_id)
    agent = locked(Agent, id=binding.agent_id, org_id=binding.org_id)
    if (
        vm is None
        or vm.inventory_present is not True
        or vm.agent_id != binding.agent_id
        or source_identity(vm) != binding.source
        or agent is None
        or agent.status != "online"
        or endpoint(agent) != binding.endpoint
    ):
        raise MonitorRefused("Monitor source unavailable")
    return backup


def progress_observation(backup, data):
    """Bounded progress or a conservative hold, never completion/release authority.

    In particular, checkpoint_committed/s3_location from a status response are
    not accepted receipt, checkpoint proof or publication facts.
    """
    if (
        type(data) is not dict
        or data.get("backup_id") != backup.id
        or data.get("status")
        not in {
            "pending",
            "running",
            "uploading",
            "completed",
            "failed",
            "cleanup_required",
            "cancelled",
        }
    ):
        raise MonitorRefused("Monitor response unavailable")
    if data["status"] == "cleanup_required":
        # A source-bound authenticated observation can stop new work and make
        # retained custody visible. It cannot publish data, acknowledge a
        # checkpoint, release capacity, or grant cleanup authority. Ignoring
        # this negative result strands a durably held runner as "running".
        backup.status = "cleanup_required"
        tags = dict(backup.tags or {})
        tags["cleanup_required"] = True
        tags.setdefault("error", "Agent retained this attempt for reconciliation")
        backup.tags = tags
        return {
            "backup_id": backup.id,
            "status": "cleanup_required",
            "progress": backup.progress,
        }
    if data["status"] in {"completed", "failed", "cancelled"}:
        return None
    value = data.get("progress_percent")
    if type(value) is not int or not 0 <= value <= 100:
        raise MonitorRefused("Monitor progress unavailable")
    backup.progress = value
    return {"backup_id": backup.id, "status": "progress", "progress": value}
