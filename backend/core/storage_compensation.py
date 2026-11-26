"""Exact pre-finalize payload compensation; native custody remains held."""

from copy import deepcopy
from types import SimpleNamespace

from core.backup_authority import HumanAuthority, read_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_attempt_key import _credential
from core.storage_receipt_v2 import validate
from core.tenant_context import identity
from models import (
    Agent,
    Backup,
    BackupQueue,
    Organization,
    S3Publication,
    Schedule,
    ScheduleOccurrence,
    SchedulerGrant,
    StorageLineageGeneration,
    User,
    VM,
)

REASON = "original_native_identity_lost"


def refuse():
    raise StorageOwnershipError("Pre-finalize compensation unavailable; retain custody")


def _lock(db, model, **fields):
    row = (
        db.query(model)
        .filter_by(**fields)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if row is None:
        refuse()
    return row


def _admit(db, backup_id, agent_id, body, proof):
    org_id, actor_id, platform = identity()
    if (
        platform
        or not org_id
        or actor_id is not None
        or db.new
        or db.dirty
        or db.deleted
    ):
        refuse()
    _lock(db, Organization, id=org_id)
    candidate = db.query(Backup).filter_by(id=backup_id, org_id=org_id).one_or_none()
    if candidate is None:
        refuse()
    authority = read_authority(candidate)
    queue = None
    # Match forward admission's lock order, but consume recorded cleanup custody.
    # Revocation cannot strand or redirect the original agent's exact attempt.
    if isinstance(authority, HumanAuthority):
        _lock(db, User, id=authority.user_id, org_id=org_id)
    else:
        occurrence = (
            db.query(ScheduleOccurrence)
            .filter_by(id=authority.occurrence_id, org_id=org_id)
            .one_or_none()
        )
        if occurrence is None:
            refuse()
        _lock(db, Schedule, id=occurrence.schedule_id, org_id=org_id)
        _lock(db, SchedulerGrant, id=occurrence.grant_id, org_id=org_id)
        queue = _lock(
            db,
            BackupQueue,
            started_backup_id=backup_id,
            scheduler_occurrence_id=occurrence.id,
            vm_id=candidate.vm_id,
        )
        if (
            queue.claim_id is None
            or queue.claimed_at is None
            or queue.status not in {"claimed", "held_claimed"}
        ):
            refuse()
    backup = _lock(db, Backup, id=backup_id, org_id=org_id)
    if read_authority(backup) != authority:
        refuse()
    _lock(db, VM, id=backup.vm_id, org_id=org_id)
    _lock(db, Agent, id=agent_id, org_id=org_id)
    _credential(db, agent_id, proof)
    claim = _lock(db, S3Publication, backup_id=backup_id, org_id=org_id, kind="payload")
    if (
        backup.capacity_state != "reserved"
        or not backup.capacity_id
        or backup.status not in {"pending", "running", "uploading", "cleanup_required"}
        or claim.state not in {"reserved", "cleanup_required"}
        or not claim.dispatch_token
        or not claim.dispatch_transaction_id
        or not claim.receipt_transaction_id
        or not claim.prepared_receipt
        or claim.finalize_intent is not None
        or claim.checkpoint_proof is not None
        or db.query(S3Publication.id)
        .filter_by(backup_id=backup_id, org_id=org_id, kind="chain_manifest")
        .first()
        or db.query(StorageLineageGeneration.id)
        .filter_by(backup_id=backup_id, org_id=org_id)
        .first()
    ):
        refuse()
    from core.callback_intents import require_no_intent_consumer

    require_no_intent_consumer(claim)
    # validate() requires reserved state: never reopen the actual aborting claim.
    view = SimpleNamespace(
        id=claim.id,
        backup_id=claim.backup_id,
        org_id=claim.org_id,
        endpoint=claim.endpoint,
        bucket=claim.bucket,
        state="reserved",
        dispatch_token=claim.dispatch_token,
        expected_plan=claim.expected_plan,
    )
    request, receipt, receipt_hash = validate(view, claim.prepared_receipt["receipt"])
    saved = claim.prepared_receipt
    from core.storage_deletion import _require_immutable_versions

    _require_immutable_versions(receipt["objects"])
    if (
        request["agent_id"] != agent_id
        or request["plan"]["provider"] != "kubevirt"
        or request["plan"]["capability_profile"] != "db-rooted-consumer-verified/1"
        or "capability_evidence" in request["plan"]
        or saved.get("receipt_sha256") != receipt_hash
        or saved.get("plan_sha256") != request["plan_sha256"]
        or saved.get("attempt_id") != request["plan"]["attempt_id"]
        or saved.get("agent_id") != agent_id
        or saved.get("response", {}).get("accepted") is not True
    ):
        refuse()
    binding = dict(
        reservation_id=claim.id,
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        key_ref=request["plan"]["encryption"]["key_ref"],
    )
    args = body["args"]
    if (
        body["binding"] != binding
        or body["artifact_key"] != ""
        or not isinstance(args, dict)
        or set(args) != {"abort_id", "receipt_sha256", "acceptance_id", "reason"}
        or args["abort_id"] != "abort:" + claim.id
        or args["receipt_sha256"] != receipt_hash
        or args["acceptance_id"] != saved["response"].get("acceptance_id")
        or args["reason"] != REASON
    ):
        refuse()
    intent = dict(
        schema=1,
        intent_id=args["abort_id"],
        backup_id=backup.id,
        org_id=org_id,
        agent_id=agent_id,
        reservation_id=claim.id,
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        receipt_sha256=receipt_hash,
        acceptance_id=args["acceptance_id"],
        capacity_id=str(backup.capacity_id),
        reason=REASON,
    )
    if claim.cleanup_intent is not None and claim.cleanup_intent != intent:
        refuse()
    if claim.cleanup_intent is None and claim.state != "reserved":
        refuse()
    return backup, claim, request, receipt, intent, queue


def compensate_pre_finalize(db, backup_id, agent_id, body, proof, *, client=None):
    """Commit abort before exact conditional deletes; never release native custody."""
    owned = None
    try:
        backup, claim, request, receipt, intent, queue = _admit(
            db, backup_id, agent_id, body, proof
        )
        if claim.cleanup_intent is None:
            claim.cleanup_intent = deepcopy(intent)
            claim.state = "cleanup_required"
            backup.status = "cleanup_required"
            backup.tags = dict(backup.tags or {}, cleanup_required=True)
        # An irreversible abort must not leave its original scheduled producer
        # claim executable. Preserve the claim/occurrence IDs and options; a
        # custody-only hold remains valid after grant revocation.
        if queue is not None and queue.status == "claimed":
            queue.status, queue.hold_reason = "held_claimed", "recovery_required"
        db.commit()
        # Recheck identity/capacity after intent durability; retain ordered locks
        # through bounded provider IO so a concurrent release cannot race it.
        backup, claim, request, receipt, intent, queue = _admit(
            db, backup_id, agent_id, body, proof
        )
        response = dict(
            schema=1,
            intent_id=intent["intent_id"],
            s3_absent=False,
            cleanup_required=True,
            capacity_state="reserved",
        )
        if claim.cleanup_result is not None:
            db.commit()
            return dict(response, s3_absent=True)
        if client is None:
            from core.storage_transaction import _recorded_target_client

            owned = client = _recorded_target_client(db, claim)
        from core.storage_deletion import _delete_object

        try:
            for item in receipt["objects"]:
                _delete_object(client, request["plan"]["target"]["bucket"], item)
        except Exception:
            db.rollback()
            return response
        claim.cleanup_result = dict(schema=1, s3_absent=True)
        db.commit()
        return dict(response, s3_absent=True)
    except Exception:
        db.rollback()
        raise
    finally:
        if owned is not None:
            owned.close()
