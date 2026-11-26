"""Terminalize only pristine human admissions, without releasing any custody."""

from datetime import datetime

from sqlalchemy import text

from core.tenant_context import identity, is_demo
from models import (
    ActivityLog,
    Backup,
    BackupQueue,
    Organization,
    OrganizationDefault,
    S3Publication,
    StorageLineageGeneration,
    User,
)


class UnreservedCloseRefused(RuntimeError):
    pass


def close_unreserved_flush(
    db, backup_id, *, requester_id=None, allow_human_queue=False
):
    """Owner-first locks serialize proof against reservation and effect admission.

    This does not create a capacity release or alter accepted operator receipts.
    The caller owns the single commit, including its mutation receipt and audit.
    """
    org_id, actor_id, platform = identity()
    if (
        platform
        or is_demo.get()
        or not actor_id
        or db.get_bind().dialect.name != "postgresql"
    ):
        raise UnreservedCloseRefused("original_tenant_required")
    if db.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
        raise UnreservedCloseRefused("read_committed_required")
    # Community HTTP authentication supplies the actor while SQL resolves the
    # installation's persisted default organization. Use that same assignment;
    # a token's organization claim must not select another tenant here.
    if org_id in (None, "default"):
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        org_id = assignment.org_id if assignment else None
        if not org_id:
            raise UnreservedCloseRefused("original_tenant_required")

    def locked(model, **where):
        return (
            db.query(model)
            .filter_by(**where)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )

    org = locked(Organization, id=org_id)
    candidate = (
        db.query(Backup)
        .filter_by(id=backup_id, org_id=org_id)
        .populate_existing()
        .one_or_none()
    )
    if candidate is None:
        raise UnreservedCloseRefused("backup_unavailable")
    original_id = candidate.initiating_user_id
    original_vm = candidate.vm_id
    if (
        org is None
        or not org.enabled
        or candidate.authority_kind != "human"
        or not original_id
    ):
        raise UnreservedCloseRefused("original_human_required")
    requester_id = requester_id or original_id
    if actor_id != requester_id:
        raise UnreservedCloseRefused("requester_unavailable")
    for user_id in sorted({original_id, requester_id}):
        user = locked(User, id=user_id, org_id=org_id)
        if user is None or not user.is_active or user.role not in {"admin", "operator"}:
            raise UnreservedCloseRefused("original_human_required")
    queues = (
        db.query(BackupQueue)
        .filter_by(started_backup_id=backup_id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    queue = None
    if queues:
        if not allow_human_queue or len(queues) != 1:
            raise UnreservedCloseRefused("unreserved_no_effect_proof_required")
        queue = queues[0]
        if (
            queue.authority_kind != "human"
            or queue.status != "started"
            or queue.vm_id != original_vm
            or queue.initiating_user_id != original_id
            or queue.created_by != original_id
            or queue.started_at is None
            or any(
                getattr(queue, key) is not None
                for key in (
                    "scheduler_occurrence_id",
                    "claim_id",
                    "claimed_at",
                    "hold_reason",
                )
            )
        ):
            raise UnreservedCloseRefused("unreserved_no_effect_proof_required")
    backup = locked(Backup, id=backup_id, org_id=org_id)
    if (
        backup is None
        or backup.initiating_user_id != original_id
        or backup.authority_kind != "human"
        or backup.vm_id != original_vm
    ):
        raise UnreservedCloseRefused("original_human_required")
    absent = (
        "capacity_id",
        "capacity_reserved_at",
        "capacity_policy_revision",
        "capacity_release",
        "capacity_terminal_evidence",
        "capacity_terminal_xid",
        "native_job_intent",
        "native_job_transaction_id",
        "native_inventory",
        "native_inventory_transaction_id",
        "native_no_effect",
        "native_closed_failure",
        "native_execution",
        "native_fenced_failure",
        "native_fenced_failure_xid",
        "wrapped_dek",
        "storage_progress",
        "size_bytes",
        "completed_at",
        "scheduler_occurrence_id",
    )
    if (
        backup.status != "pending"
        or backup.capacity_state != "unreserved"
        or backup.progress != 0
        or any(getattr(backup, key) is not None for key in absent)
        or backup.capacity_legacy_reviews
        or backup.capacity_modern_reviews
        or backup.checkpoints
        or db.query(S3Publication.id).filter_by(backup_id=backup_id).first()
        or db.query(StorageLineageGeneration.id).filter_by(backup_id=backup_id).first()
        or db.query(BackupQueue.id).filter_by(started_backup_id=backup_id).count()
        != len(queues)
    ):
        raise UnreservedCloseRefused("unreserved_no_effect_proof_required")
    backup.status = "failed"
    backup.completed_at = datetime.utcnow()
    backup.tags = dict(backup.tags or {}, error="pre_dispatch_refused")
    if queue is not None:
        queue.status = "failed"
    db.add(
        ActivityLog(
            user_id=requester_id,
            action="backup_unreserved_closed",
            resource_type="backup",
            resource_id=backup_id,
            details={
                "org_id": org_id,
                "initiating_user_id": original_id,
                "reason": "pre_dispatch_no_effect",
                "capacity_state": "unreserved",
                "queue_id": queue.id if queue else None,
            },
        )
    )
    db.flush()
    return dict(
        backup_id=backup_id,
        status="failed",
        reason="pre_dispatch_no_effect",
        capacity_state="unreserved",
    )


def close_unreserved(factory, backup_id):
    """Automatic provider refusal uses exactly the explicit closeout proof."""
    with factory() as db:
        result = close_unreserved_flush(db, backup_id, allow_human_queue=True)
        db.commit()
        return result
