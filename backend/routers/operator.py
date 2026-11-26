"""Read-only recovery of a caller's original operator admission."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from uuid import UUID

from database import get_db
from deps import get_current_user, iso_utc
from models import (
    OperatorRequest,
    OperatorDispatch,
    Backup,
    Restore,
    BackupQueue,
    AgentKeyRotation,
    OrchestratorAPIKey,
    AgentRegistrationKey,
    EncryptionKey,
)
from core.operator_requests import (
    ACTION_ROLES,
    CONTRACT_VERSION,
    MAX_BULK_TARGETS,
    authorize_action,
)

router = APIRouter(prefix="/api/v1/operator", tags=["operator-recovery"])


@router.get("/capabilities")
def operator_capabilities(current_user=Depends(get_current_user)):
    return {
        "contract_version": CONTRACT_VERSION,
        "request_header": "Idempotency-Key",
        "request_identity": "uuid",
        "caller_identity_required_for_lost_reply_recovery": True,
        "scope": "organization-and-original-principal",
        "actions": sorted(
            action
            for action, roles in ACTION_ROLES.items()
            if current_user.role in roles
        ),
        "encryption_admission_provider": "local",
        "retention": "permanent-no-reuse",
        "secret_replay": False,
        "max_bulk_targets": MAX_BULK_TARGETS,
        "agent_key_rotation": "staged-candidate-activation",
        "polling_contract": 2,
        "external_effects": "original-attempt-reconciliation",
    }


@router.get("/requests/{request_id}")
def operator_request_outcome(
    request_id: str,
    response: Response,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    try:
        request_id = str(UUID(request_id))
    except (ValueError, AttributeError):
        raise HTTPException(
            404, detail={"code": "request_not_found", "outcome": "unknown"}
        ) from None
    row = (
        db.query(OperatorRequest)
        .filter_by(
            org_id=current_user.org_id,
            actor_id=current_user.id,
            request_id=request_id,
        )
        .one_or_none()
    )
    if row is None:
        # This is a point-in-time observation, not permission to use a new ID.
        raise HTTPException(
            404, detail={"code": "request_not_found", "outcome": "unknown"}
        )
    authorize_action(current_user, row.action)
    deliveries = []
    for work in (
        db.query(OperatorDispatch)
        .filter_by(request_record_id=row.id)
        .order_by(OperatorDispatch.id)
    ):
        model = Backup if work.kind == "backup" else Restore
        resource = (
            db.query(model)
            .filter_by(id=work.resource_id, org_id=row.org_id)
            .one_or_none()
        )
        deliveries.append(
            {
                "kind": work.kind,
                "resource_id": work.resource_id,
                "state": work.state,
                "reason": work.reason,
                "resource_status": resource.status if resource else None,
                "resource_present": resource is not None,
            }
        )
    current = None
    receipt = row.response_body or {}
    if row.action == "credential.agent.rotate":
        from core.agent_key_rotation import metadata

        rotation = (
            db.query(AgentKeyRotation).filter_by(request_record_id=row.id).one_or_none()
        )
        current = (
            metadata(rotation) if rotation is not None else {"resource_present": False}
        )
    elif row.action in {
        "credential.orchestrator.create",
        "credential.registration.create",
    }:
        model = (
            OrchestratorAPIKey
            if row.action == "credential.orchestrator.create"
            else AgentRegistrationKey
        )
        key = db.get(model, receipt.get("id"))
        current = {"id": receipt.get("id"), "resource_present": key is not None}
        if key is not None:
            current.update(
                enabled=key.enabled,
                is_valid=key.is_valid(),
                expires_at=iso_utc(key.expires_at),
            )
    elif row.action in {"encryption.create", "encryption.rotate"}:
        key = db.get(EncryptionKey, receipt.get("id"))
        current = {"id": receipt.get("id"), "resource_present": key is not None}
        if key is not None:
            current.update(status=key.status, replaced_by_id=key.replaced_by_id)
    elif row.action == "queue.create" or receipt.get("queue_id"):
        queue_id = receipt.get("queue_id") or receipt.get("id")
        queue = db.get(BackupQueue, queue_id)
        current = {"id": queue_id, "resource_present": queue is not None}
        if queue is not None:
            current.update(
                status=queue.status,
                hold_reason=queue.hold_reason
                or ("queue_held" if queue.status == "held" else None),
                started_backup_id=queue.started_backup_id,
            )
    return {
        "request_id": row.request_id,
        "action": row.action,
        "contract_version": row.contract_version,
        "state": "admitted" if row.completed_at is not None else "unresolved",
        "created_at": iso_utc(row.created_at),
        "completed_at": iso_utc(row.completed_at),
        "response_status": row.response_status,
        "receipt": row.response_body,
        "secret_delivery": "unavailable" if row.secret_delivery else "not_applicable",
        "dispatches": deliveries,
        "current_resource": current,
        "retention": "permanent-no-reuse",
    }
