"""Atomic operator admission receipts; never a cache of secret responses."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID, uuid4

from fastapi import Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy.dialects.postgresql import insert

from models import OperatorRequest, OperatorDispatch

CONTRACT_VERSION = 1
MAX_BULK_TARGETS = 200
ACTION_ROLES = {
    "backup.close_unreserved": {"admin", "operator"},
    "backup.create": {"admin", "operator"},
    "queue.create": {"admin", "operator"},
    "restore.create": {"admin", "operator"},
    "backup.bulk_create": {"admin", "operator"},
    "credential.orchestrator.create": {"admin"},
    "credential.registration.create": {"admin"},
    "credential.agent.rotate": {"admin"},
    "encryption.create": {"admin"},
    "encryption.rotate": {"admin"},
}


def request_identity(
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    """Optional only for legacy callers; recovery clients must supply a UUID."""
    if idempotency_key is None:
        return None
    try:
        value = str(UUID(idempotency_key))
    except (ValueError, AttributeError):
        raise HTTPException(422, detail={"code": "invalid_request_identity"}) from None
    if value != idempotency_key.lower():
        raise HTTPException(422, detail={"code": "invalid_request_identity"})
    return value


def fingerprint(action, intent):
    encoded = json.dumps(
        {
            "contract": CONTRACT_VERSION,
            "action": action,
            "intent": jsonable_encoder(intent),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise HTTPException(413, detail={"code": "operator_intent_too_large"})
    return hashlib.sha256(encoded).hexdigest()


def authorize_action(user, action):
    if action not in ACTION_ROLES or user.role not in ACTION_ROLES[action]:
        raise HTTPException(403, detail={"code": "operator_action_not_authorized"})


def dispatch_metadata(db, kind, resource_ids):
    """Batch projection for job lists; admission/dispatch is separate from progress."""
    if not resource_ids:
        return {}
    rows = (
        db.query(OperatorDispatch, OperatorRequest.request_id)
        .join(
            OperatorRequest,
            OperatorRequest.id == OperatorDispatch.request_record_id,
        )
        .filter(
            OperatorDispatch.kind == kind,
            OperatorDispatch.resource_id.in_(resource_ids),
        )
        .all()
    )
    return {
        work.resource_id: {
            "state": work.state,
            "reason": work.reason,
            "request_id": request_id,
        }
        for work, request_id in rows
    }


class Admission:
    def __init__(self, db, row, replay):
        self.db, self.row, self.replay = db, row, replay

    def response(self):
        """Replay the immutable, nonsecret admission receipt, not current state."""
        if not self.replay or self.row.completed_at is None:
            raise HTTPException(409, detail={"code": "operator_outcome_unresolved"})
        body = deepcopy(self.row.response_body)
        if self.row.secret_delivery:
            body["secret_delivery"] = "unavailable"
        return JSONResponse(
            status_code=self.row.response_status,
            content=body,
            headers={
                "Idempotency-Replayed": "true",
                "Idempotency-Key": self.row.request_id,
                "Cache-Control": "no-store",
            },
        )

    def dispatch(self, kind, resource_id):
        work = OperatorDispatch(
            org_id=self.row.org_id,
            request_record_id=self.row.id,
            kind=kind,
            resource_id=resource_id,
            actor_id=self.row.actor_id,
            state="pending",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.db.add(work)
        self.db.flush()
        return work.id

    def finish(self, body, status=200, *, secret_fields=()):
        """Caller has flushed resource and audit; this is the sole admission commit."""
        if self.replay:
            raise RuntimeError("A replay cannot admit work")
        body = jsonable_encoder(dict(body, request_id=self.row.request_id))
        receipt = deepcopy(body)
        for field in secret_fields:
            receipt.pop(field, None)
        if secret_fields:
            body["secret_delivery"] = "one_time"
            receipt["secret_delivery"] = "unavailable"
        self.row.response_body = receipt
        self.row.response_status = status
        if self.row.secret_delivery != bool(secret_fields):
            raise RuntimeError(
                "Credential delivery classification differs from admission"
            )
        self.row.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        return JSONResponse(
            status_code=status,
            content=body,
            headers={
                "Idempotency-Replayed": "false",
                "Idempotency-Key": self.row.request_id,
                "Cache-Control": "no-store",
            },
        )


def begin_admission(db, user, action, intent, request_id=None):
    """Unique insertion serializes duplicates with the admitting transaction.

    No claim is committed separately: failures roll back both claim and work.
    The schema also rejects an incomplete claim at transaction end. A concurrent
    winner is visible after INSERT ... ON CONFLICT waits for its commit.
    """
    authorize_action(user, action)
    request_id = request_id or str(uuid4())
    digest = fingerprint(action, intent)
    identity = str(uuid4())
    inserted = db.execute(
        insert(OperatorRequest)
        .values(
            id=identity,
            org_id=user.org_id,
            request_id=request_id,
            actor_id=user.id,
            action=action,
            fingerprint=digest,
            contract_version=CONTRACT_VERSION,
            created_at=datetime.now(timezone.utc),
            secret_delivery=action.startswith("credential."),
        )
        .on_conflict_do_nothing(index_elements=["org_id", "request_id"])
        .returning(OperatorRequest.id)
    ).scalar_one_or_none()
    row = (
        db.query(OperatorRequest)
        .filter_by(
            org_id=user.org_id,
            request_id=request_id,
        )
        .one()
    )
    if row.actor_id != user.id or row.action != action or row.fingerprint != digest:
        raise HTTPException(409, detail={"code": "request_identity_conflict"})
    if row.contract_version != CONTRACT_VERSION:
        raise HTTPException(409, detail={"code": "request_contract_retired"})
    return Admission(db, row, inserted is None)
