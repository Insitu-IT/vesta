"""Checkpoint-A first intent custody. No key, signing, provider or send consumer."""

from copy import deepcopy
import json
import uuid

from sqlalchemy import text

from core.callback_identity import validate_identity
from core.scheduler_admission import lock_original_authority
from core.s3_ownership import StorageOwnershipError
from core.tenant_context import TenantContext
from models import Backup, BackupQueue, S3Publication

KINDS = frozenset(
    ("receipt_verification", "attempt_key_preparation", "attempt_key_disclosure")
)


def _digest(db, value):
    return db.scalar(
        text("SELECT encode(sha256(convert_to(CAST(:v AS jsonb)::text,'UTF8')),'hex')"),
        {"v": json.dumps(value, allow_nan=False)},
    )


def _claim(db, backup_id, identity):
    # Caller must establish original tenant before this non-platform lookup.
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, org_id=identity.org_id, kind="payload")
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if claim is None or claim.expected_plan is None:
        raise StorageOwnershipError("Callback custody unavailable")
    request = claim.expected_plan.get("transaction", {})
    if request.get("agent_id") != identity.agent_id:
        raise StorageOwnershipError("Callback original agent mismatch")
    return claim, request


def lookup_intent(factory, identity, backup_id, kind):
    """Authenticated original custody only, including after org/grant fencing."""
    if kind not in KINDS:
        raise StorageOwnershipError("Unknown callback operation")
    with TenantContext(identity.org_id), factory() as db:
        validate_identity(db, identity)
        claim, _ = _claim(db, backup_id, identity)
        return deepcopy(getattr(claim, kind + "_intent"))


def require_preparation_order(claim):
    if any(
        value is not None
        for value in (
            claim.receipt_verification_intent,
            claim.prepared_receipt,
            claim.provider_control,
            claim.attempt_key_disclosure_intent,
        )
    ):
        raise StorageOwnershipError("Key preparation order unavailable")


def require_committed_key(db, claim, request):
    if request["plan"]["encryption"]["format"] == "none":
        return
    wrapped = claim.wrapped_attempt_key
    encryption = request["plan"]["encryption"]
    expected = dict(
        org_id=claim.org_id,
        backup_id=claim.backup_id,
        reservation_id=claim.id,
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        key_ref=encryption["key_ref"],
        format=encryption["format"],
    )
    if (
        not isinstance(wrapped, dict)
        or any(wrapped.get(k) != v for k, v in expected.items())
        or claim.wrapped_attempt_key_xid is None
        or claim.wrapped_attempt_key_xid == db.scalar(text("SELECT txid_current()"))
    ):
        raise StorageOwnershipError("Committed exact key required")


def admit_intent(factory, identity, backup_id, kind, details):
    """Commit one immutable intent. Existing/conflict never recreates permission.

    Even a created result is custody, not a callable IO capability. Checkpoint B
    must add a creator-only process-local consumer after its own review.
    """
    if kind not in KINDS or type(details) is not dict:
        raise StorageOwnershipError("Invalid callback operation")
    with TenantContext(identity.org_id), factory() as db:
        if db.in_transaction() or db.new or db.dirty or db.deleted:
            raise StorageOwnershipError("Fresh callback transaction required")
        if db.get_bind().dialect.name != "postgresql":
            raise StorageOwnershipError("PostgreSQL callback authority required")
        db.connection(execution_options={"isolation_level": "READ COMMITTED"})
        lock_original_authority(db, backup_id, callback=True)
        validate_identity(db, identity)
        claim, request = _claim(db, backup_id, identity)
        old = getattr(claim, kind + "_intent")
        if old is not None:
            disposition = (
                "existing_custody"
                if all(old.get(k) == v for k, v in details.items())
                and set(details) == _detail_fields(kind)
                else "conflict"
            )
            return dict(disposition=disposition, intent=deepcopy(old))
        if set(details) != _detail_fields(kind):
            raise StorageOwnershipError("Invalid callback details")
        if kind == "attempt_key_preparation":
            require_preparation_order(claim)
        elif kind == "receipt_verification":
            require_committed_key(db, claim, request)
        backup = db.get(Backup, backup_id)
        queue = (
            db.query(BackupQueue)
            .filter_by(
                started_backup_id=backup_id,
                scheduler_occurrence_id=backup.scheduler_occurrence_id,
                vm_id=backup.vm_id,
            )
            .one_or_none()
        )
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        intent = dict(
            schema=1,
            operation=kind,
            nonce=str(uuid.uuid4()),
            org_id=identity.org_id,
            agent_id=identity.agent_id,
            backup_id=backup_id,
            reservation_id=claim.id,
            attempt_id=request["plan"]["attempt_id"],
            claim_id=queue.claim_id if queue else None,
            capacity_id=str(backup.capacity_id),
            plan_sha256=request["plan_sha256"],
            dispatch_sha256=_digest(db, claim.dispatch_admission),
            target_sha256=_digest(db, request["plan"]["target"]),
            credential_kind=identity.credential_kind,
            credential_id=identity.credential_id,
            created_at=now,
            expires_at=now + 60,
            **deepcopy(details)
        )
        setattr(claim, kind + "_intent", intent)
        db.flush()
        db.refresh(claim)
        result = deepcopy(getattr(claim, kind + "_intent"))
        # No result on failed or uncertain commit. No IO consumer exists here.
        db.commit()
        return dict(disposition="created", intent=result)


def _detail_fields(kind):
    if kind == "receipt_verification":
        return {"receipt_sha256", "objects"}
    fields = {"key_ref", "format"}
    return fields | (
        {"wrapped_key_sha256"} if kind == "attempt_key_disclosure" else set()
    )


def require_no_intent_consumer(claim):
    """Old IO services cannot consume or bypass the new dormant contracts."""
    if any(getattr(claim, kind + "_intent") is not None for kind in KINDS):
        raise StorageOwnershipError("Callback intent consumer remains dormant")
