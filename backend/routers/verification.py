"""
Backup verification endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import and_, case, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from typing import Literal, Optional

from core import backup_verification as scrub
from core.s3_ownership import StorageOwnershipError
from core.verification_executor import verification_executor
from database import get_db
from models import Backup, BackupVerification, VM, User
from deps import get_current_user, get_operator_or_admin, iso_utc

router = APIRouter(prefix="/api/v1", tags=["verification"])

_SIMULATED_MESSAGES = (
    "Checksum verified successfully",
    "Backup integrity verified successfully",
)
_SIMULATED_TYPES = ("checksum", "mount_test", "integrity")


def _evidence_status():
    """Only the guarded scrub format can carry a positive historical result."""
    bound = and_(
        BackupVerification.verification_type == scrub.TYPE,
        func.length(BackupVerification.verification_plan_canonical) > 0,
        func.length(BackupVerification.verification_plan_sha256) == 64,
        func.length(BackupVerification.verification_authority_canonical) > 0,
        func.length(BackupVerification.verification_worker_id) == 36,
        BackupVerification.completed_at.is_not(None),
        BackupVerification.verification_result["schema"].as_string()
        == scrub.RESULT_SCHEMA,
    )
    return case(
        (
            and_(
                BackupVerification.status == "passed",
                bound.is_not(True),
            ),
            "unverified",
        ),
        else_=BackupVerification.status,
    )


def _evidence_fields(record):
    bound = (
        record.verification_type == scrub.TYPE
        and bool(record.verification_plan_canonical)
        and len(record.verification_plan_sha256 or "") == 64
        and bool(record.verification_authority_canonical)
        and len(record.verification_worker_id or "") == 36
        and record.completed_at is not None
        and isinstance(record.verification_result, dict)
        and record.verification_result.get("schema") == scrub.RESULT_SCHEMA
    )
    unverified = record.status == "passed" and not bound
    simulated = (
        record.status == "passed"
        and record.verification_type in _SIMULATED_TYPES
        and record.result_message in _SIMULATED_MESSAGES
    )
    return {
        "status": "unverified" if unverified else record.status,
        "recorded_status": record.status,
        "created_by": record.created_by,
        "read_attempts": record.verification_read_attempts,
        "read_limit": record.verification_read_limit,
        "cancel_requested": record.verification_cancel_requested,
        "result_message": (
            "Historical simulated checksum result; no backup artifacts were verified."
            if simulated
            else (
                "Historical result has no receipt-bound artifact verification evidence."
                if unverified
                else record.result_message
            )
        ),
    }


class VerificationCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    verification_id: str
    action: Literal["start", "resume", "cancel"] = "start"

    @field_validator("verification_id")
    @classmethod
    def canonical_id(cls, value):
        if not scrub._id(value):
            raise ValueError("A canonical nonzero verification UUID is required")
        return value


@router.post("/backups/{backup_id}/verify", status_code=202)
def verify_backup(
    backup_id: str,
    command: VerificationCommand,
    response: Response,
    current_user=Depends(get_operator_or_admin),
    db: Session = Depends(get_db),
):
    """Admit original-ID read-only work; an acknowledgement is never proof."""
    response.headers["Cache-Control"] = "no-store"
    backup = (
        db.query(Backup).filter_by(id=backup_id, org_id=current_user.org_id).first()
    )
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    if backup.status != "completed":
        raise HTTPException(status_code=400, detail="Can only verify completed backups")

    try:
        if command.action == "start":
            row = scrub.enroll(
                db,
                backup_id=backup_id,
                org_id=current_user.org_id,
                actor_id=current_user.id,
                verification_id=command.verification_id,
            )
        else:
            row = (
                db.query(BackupVerification)
                .filter_by(
                    id=command.verification_id,
                    org_id=current_user.org_id,
                    backup_id=backup_id,
                    verification_type=scrub.TYPE,
                )
                .one_or_none()
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Verification not found")
            if command.action == "resume":
                scrub.grant_readmission(db, row, current_user.id)
            elif row.status not in scrub.TERMINAL:
                db.refresh(row, with_for_update=True)
                if row.status in scrub.TERMINAL:
                    return {
                        "id": row.id,
                        "backup_id": row.backup_id,
                        **_evidence_fields(row),
                    }
                # Operators may stop reads; this does not delegate the original
                # creator's positive admission authority to the cancelling user.
                row.verification_cancel_requested = True
                row.status = "held"
                row.result_message = "Verification cancellation awaiting reader stop"
                row.verification_next_poll_at = datetime.utcnow()
        db.commit()
        result = {
            "id": row.id,
            "backup_id": row.backup_id,
            "verification_type": row.verification_type,
            **_evidence_fields(row),
        }
    except (StorageOwnershipError, IntegrityError):
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Verification admission refused: original authority, accepted "
            "catalog, queue capacity or resumable custody is unavailable",
        ) from None
    verification_executor.notify()
    return result


@router.get("/backups/{backup_id}/verifications")
def list_backup_verifications(
    backup_id: str,
    response: Response,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List verification history for a backup"""
    response.headers["Cache-Control"] = "no-store"
    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    verifications = (
        db.query(BackupVerification)
        .filter(BackupVerification.backup_id == backup_id)
        .order_by(BackupVerification.created_at.desc())
        .all()
    )

    return [
        {
            "id": v.id,
            **_evidence_fields(v),
            "verification_type": v.verification_type,
            "started_at": iso_utc(v.started_at),
            "completed_at": iso_utc(v.completed_at),
            "created_at": iso_utc(v.created_at),
        }
        for v in verifications
    ]


@router.get("/verifications")
def list_all_verifications(
    response: Response,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    status: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all verification records"""
    response.headers["Cache-Control"] = "no-store"
    query = db.query(BackupVerification)
    if status:
        query = query.filter(_evidence_status() == status)

    total = query.count()
    verifications = (
        query.order_by(BackupVerification.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "items": [
            {
                "id": v.id,
                "backup_id": v.backup_id,
                **_evidence_fields(v),
                "verification_type": v.verification_type,
                "created_at": iso_utc(v.created_at),
                "started_at": iso_utc(v.started_at),
                "completed_at": iso_utc(v.completed_at),
            }
            for v in verifications
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/verifications/{verification_id}")
def get_verification(
    verification_id: str,
    response: Response,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get details of a specific verification"""
    response.headers["Cache-Control"] = "no-store"
    verification = (
        db.query(BackupVerification)
        .filter(BackupVerification.id == verification_id)
        .first()
    )

    if not verification:
        raise HTTPException(status_code=404, detail="Verification not found")

    # Get related data
    backup = db.query(Backup).filter(Backup.id == verification.backup_id).first()
    vm = db.query(VM).filter(VM.id == backup.vm_id).first() if backup else None
    user = (
        db.query(User).filter(User.id == verification.created_by).first()
        if verification.created_by
        else None
    )

    return {
        "id": verification.id,
        "backup_id": verification.backup_id,
        **_evidence_fields(verification),
        "verification_type": verification.verification_type,
        "started_at": iso_utc(verification.started_at),
        "completed_at": iso_utc(verification.completed_at),
        "created_at": iso_utc(verification.created_at),
        "result": verification.verification_result,
        "backup": (
            {
                "id": backup.id,
                "vm_id": backup.vm_id,
                "vm_name": vm.name if vm else "Unknown",
                "status": backup.status,
                "size_bytes": backup.size_bytes,
                "created_at": iso_utc(backup.created_at),
            }
            if backup
            else None
        ),
        "created_by_user": (
            {"id": user.id, "username": user.username, "role": user.role}
            if user
            else None
        ),
    }
