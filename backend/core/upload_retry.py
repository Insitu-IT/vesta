"""Upload handoff/retry admission, not authority to replay an uncertain producer.

First upload belongs to the source-specific transaction handshake. Recovery of
an already dispatched producer requires D07 evidence, not a status/path test.
"""

from fastapi import HTTPException
from uuid import UUID

from models import ActivityLog, Agent, Backup, Organization, S3Publication, User, VM


def inspect_upload_handoff(db, backup_id, org_id, initiating_user_id, origin):
    """Read-admit a delayed handoff; never mint producer or recovery authority.

    The caller carries identity, not permission. All principals are re-read under
    locks. No audit/queue/custody is created by this inspection, including on a
    periodic retry scan. D05 first dispatch and D07 recovery remain distinct.
    """
    if origin not in {"first_upload", "automatic_retry"} or not all(
        _identifier(value) for value in (backup_id, org_id, initiating_user_id)
    ):
        return "delivery_provenance_required"

    def locked(model, **fields):
        return (
            db.query(model)
            .filter_by(**fields)
            .populate_existing()
            .with_for_update(nowait=True)
            .one_or_none()
        )

    org = locked(Organization, id=org_id)
    actor = locked(User, id=initiating_user_id, org_id=org_id)
    if (
        org is None
        or org.enabled is not True
        or actor is None
        or actor.is_active is not True
        or actor.role not in {"admin", "operator"}
    ):
        return "initiating_authority_unavailable"
    backup = locked(Backup, id=backup_id, org_id=org_id)
    if backup is not None and backup.authority_kind == "scheduler":
        return "scheduler_execution_dormant"
    if backup is None or backup.initiating_user_id != initiating_user_id:
        return "delivery_provenance_required"
    if backup.status in {"cancelled", "cancelling", "deleted", "cleanup_required"}:
        return "terminal_lifecycle"
    vm = locked(VM, id=backup.vm_id, org_id=org_id)
    agent = locked(Agent, id=vm.agent_id, org_id=org_id) if vm else None
    if (
        vm is None
        or vm.inventory_present is not True
        or agent is None
        or agent.status != "online"
    ):
        return "source_authority_unavailable"
    claim = locked(S3Publication, backup_id=backup.id, org_id=org_id, kind="payload")
    reason = retry_boundary(backup, claim)
    # Custody takes precedence over the label supplied by the caller: even a
    # local-completion notification cannot turn an existing producer into first use.
    if reason == "producer_reconciliation_required":
        return reason
    if origin == "automatic_retry":
        return "automatic_retry_authority_required"
    if backup.status != "completed":
        return "local_completion_evidence_required"
    if not backup.native_job_intent or not backup.native_inventory:
        return "closed_native_inventory_required"
    # A closed file-set alone has no literal artifact-key/custody compiler yet.
    # D05 must supply that interface; never call the path-only legacy endpoint.
    return reason


def _identifier(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def record_retry_hold(db, backup_id, org_id, caller_id):
    """Atomically attribute a refused replay without changing original custody.

    No background job is admitted: consequently there is no delayed authority
    snapshot that could outlive this locked check. Audit is not a work queue.
    """

    def locked(model, **fields):
        return (
            db.query(model)
            .filter_by(**fields)
            .populate_existing()
            .with_for_update(nowait=True)
            .one_or_none()
        )

    try:
        org = locked(Organization, id=org_id)
        caller = locked(User, id=caller_id, org_id=org_id)
        if (
            org is None
            or org.enabled is not True
            or caller is None
            or caller.is_active is not True
            or caller.role not in {"admin", "operator"}
        ):
            raise HTTPException(403, "Upload retry refused")
        backup = locked(Backup, id=backup_id, org_id=org_id)
        if backup is None:
            raise HTTPException(404, "Backup not found")
        initiator = locked(User, id=backup.initiating_user_id, org_id=org_id)
        if (
            initiator is None
            or initiator.is_active is not True
            or initiator.role not in {"admin", "operator"}
        ):
            raise HTTPException(409, "Upload retry authority unavailable")
        vm = locked(VM, id=backup.vm_id, org_id=org_id)
        agent = locked(Agent, id=vm.agent_id, org_id=org_id) if vm else None
        if (
            vm is None
            or vm.inventory_present is not True
            or agent is None
            or agent.status != "online"
        ):
            raise HTTPException(409, "Upload retry source unavailable")
        claim = locked(
            S3Publication, backup_id=backup.id, org_id=org_id, kind="payload"
        )
        reason = retry_boundary(backup, claim)
        db.add(
            ActivityLog(
                user_id=caller.id,
                action="upload_retry_held",
                resource_type="backup",
                resource_id=backup.id,
                details={
                    "origin": "manual_retry",
                    "initiating_user_id": initiator.id,
                    "retry_caller_id": caller.id,
                    "reason": reason,
                    "reservation_id": claim.id if claim else None,
                },
            )
        )
        db.flush()
        db.commit()
        return reason
    except BaseException:
        db.rollback()
        raise


def retry_boundary(backup, claim):
    """Finite missing prerequisites, never a claim that an upload is safe."""
    if backup.status in {"cancelled", "cancelling", "deleted"}:
        return "terminal_lifecycle"
    if claim is not None and (
        claim.dispatch_token or claim.provider_control or claim.prepared_receipt
    ):
        return "producer_reconciliation_required"
    if (
        claim is None
        or not claim.expected_plan
        or claim.expected_plan.get("schema") != 3
    ):
        return "committed_upload_plan_required"
    # A never-dispatched plan is not a failed producer and must not be sent to
    # the old path-only /upload endpoint. Its first dispatch belongs to D02/D05.
    return "first_upload_transaction_handoff_required"
