"""
Backup management endpoints: create, list, get, delete, cleanup.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, Annotated
import asyncio
import logging

from config import settings

from database import get_db
from models import Backup, BackupQueue, VM, User
from deps import (
    get_current_user,
    get_operator_or_admin,
    get_admin_user,
    log_activity,
    iso_utc,
)
from schemas import BackupCreate
from schemas.models import BackupCloseUnreservedRequest, BackupCloseUnreservedResponse

# Import core services
from core.backup_service import BackupService
from core.legacy_recovery import legacy_s3_unverified
from core.storage_hold_observation import public_safety_diagnostic
from core.backup_executor import backup_executor
from core.backup_queue_processor import _add_to_queue_flush
from core.operator_requests import begin_admission, request_identity, dispatch_metadata
from core.retention import retention_enforcer
from core.settings_reader import get_default_retention_days
from core.backup_deletion import (
    BackupDeletionError,
    BackupDependencyError,
    backup_deletion_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["backups"])

# Unit doubles may replace this binding; deployment configuration cannot disable it.
USE_REAL_BACKUP_EXECUTOR = settings.use_real_backup_executor


async def simulate_backup_execution(backup_id: str):
    """
    Simulate backup execution with progress updates.
    In production: This would call virtnbdbackup via subprocess.
    """
    import asyncio
    import random
    from database import SessionLocal

    db = SessionLocal()
    try:
        backup = db.query(Backup).filter(Backup.id == backup_id).first()
        if not backup:
            return

        # Simulate backup stages with realistic timing
        stages = [
            (10, 2),  # 10% - Connecting to VM
            (30, 3),  # 30% - Reading disk metadata
            (50, 4),  # 50% - Transferring data
            (70, 5),  # 70% - Continuing transfer
            (90, 3),  # 90% - Finalizing
            (100, 1),  # 100% - Complete
        ]

        for progress_value, sleep_seconds in stages:
            await asyncio.sleep(sleep_seconds)

            backup.progress = progress_value
            backup.status = "running"
            db.commit()
            db.refresh(backup)

        # Mark as completed with random size
        backup.status = "completed"
        backup.progress = 100
        backup.size_bytes = random.randint(1_000_000_000, 10_000_000_000)  # 1-10 GB
        backup.completed_at = datetime.utcnow()
        db.commit()

        logger.info(f"Mock backup {backup_id} completed")

    except Exception as e:
        logger.error(f"Error in mock backup {backup_id}: {e}")
        # Mark as failed
        backup = db.query(Backup).filter(Backup.id == backup_id).first()
        if backup:
            backup.status = "failed"
            db.commit()
    finally:
        db.close()


@router.post("/backups", response_model=dict)
def create_backup(
    backup_data: BackupCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
    request_id: Optional[str] = Depends(request_identity),
):
    """
    Create a new backup job for a VM (operator or admin only).
    Triggers async backup execution.
    """
    admission = begin_admission(
        db, current_user, "backup.create", backup_data, request_id
    )
    if admission.replay:
        return admission.response()
    service = BackupService(db)
    result = service._create_backup_flush(
        vm_id=backup_data.vm_id,
        retention_days=backup_data.retention_days,
        backup_type=backup_data.backup_type or "full",
        tags=backup_data.tags,
        exclude_disks=backup_data.exclude_disks,
        workers=backup_data.workers,
    )

    if not result.success:
        if result.error_code == 429:
            # At capacity — auto-queue instead of rejecting
            queue_item = _add_to_queue_flush(
                db,
                vm_id=backup_data.vm_id,
                retention_days=(
                    backup_data.retention_days
                    if backup_data.retention_days is not None
                    else get_default_retention_days(db)
                ),
                backup_type=backup_data.backup_type or "full",
                tags=backup_data.tags,
                exclude_disks=backup_data.exclude_disks,
                workers=backup_data.workers,
                created_by=current_user.id if current_user else None,
            )
            vm_name = service.get_vm_name(backup_data.vm_id)
            logger.info(f"Queued backup for VM {vm_name} (at capacity)")
            log_activity(
                db,
                current_user,
                "backup_queued",
                "backup_queue",
                queue_item.id,
                {"vm_id": backup_data.vm_id},
                commit=False,
            )
            return admission.finish(
                {
                    "status": "queued",
                    "queue_id": queue_item.id,
                    "vm_id": backup_data.vm_id,
                    "vm_name": vm_name,
                    "message": f"All backup slots in use. Queued for VM {vm_name}.",
                }
            )
        raise HTTPException(status_code=result.error_code, detail=result.error)

    backup = result.backup
    vm_name = service.get_vm_name(backup_data.vm_id)

    # Persist delivery before any asynchronous executor can observe the attempt.
    admission.dispatch("backup", backup.id)

    # Log activity
    log_activity(
        db,
        current_user,
        action="backup_created",
        resource_type="backup",
        resource_id=backup.id,
        details={"vm_name": vm_name, "vm_id": backup_data.vm_id},
        commit=False,
    )

    return admission.finish(
        {
            "id": backup.id,
            "vm_id": backup_data.vm_id,
            "vm_name": vm_name,
            "status": backup.status,
            "message": f"Backup started for {vm_name}",
            "executor": "real" if USE_REAL_BACKUP_EXECUTOR else "mock",
        }
    )


@router.get("/backups/{backup_id}/restore-bundle")
def get_restore_bundle(
    backup_id: str,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Export accepted chain metadata for vnbui-restore; no keys or credentials."""
    from core.storage_restore import build_restore_bundle
    from core.s3_ownership import StorageOwnershipError

    try:
        bundle = build_restore_bundle(db, backup_id, current_user.org_id)
    except StorageOwnershipError:
        raise HTTPException(
            status_code=409, detail="An intact accepted backup chain is required"
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return bundle


@router.get("/backups/{backup_id}")
def get_backup(
    backup_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get backup status and details."""
    from core.recovery_publication import publication_status

    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    queue = None
    if backup.authority_kind == "scheduler":
        queue = (
            db.query(BackupQueue)
            .filter_by(
                started_backup_id=backup.id,
                scheduler_occurrence_id=backup.scheduler_occurrence_id,
                vm_id=backup.vm_id,
            )
            .one_or_none()
        )
    return {
        "id": backup.id,
        "vm_id": backup.vm_id,
        "vm_name": backup.vm.name,
        "status": backup.status,
        "progress": backup.progress,
        "storage_progress": backup.storage_progress,
        "safety_diagnostic": public_safety_diagnostic(backup),
        "unverified_legacy_s3": legacy_s3_unverified(backup),
        "size_bytes": backup.size_bytes,
        "retention_days": backup.retention_days,
        "backup_type": backup.backup_type or "full",
        "scheduler_decision": queue.backup_decision if queue is not None else None,
        "recovery_publication": publication_status(db, backup),
        "operator_dispatch": dispatch_metadata(db, "backup", [backup.id]).get(
            backup.id
        ),
        "storage_path": backup.storage_path,
        "tags": backup.tags if backup.tags else {},
        "created_at": iso_utc(backup.created_at),
        "completed_at": iso_utc(backup.completed_at),
    }


@router.get("/backups")
def list_backups(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    vm_id: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    tag_key: Optional[str] = None,
    tag_value: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List backups with pagination and optional filters.

    - skip: Number of records to skip (default: 0)
    - limit: Maximum number of records to return (default: 50, max: 100)
    - vm_id: Filter by specific VM
    - status: Filter by status (pending, running, completed, failed)
    - search: Search by VM name (partial match, case-insensitive)
    - date_from: Filter backups created after this date (ISO format: 2025-01-01)
    - date_to: Filter backups created before this date (ISO format: 2025-12-31)
    - tag_key: Filter by tag key (requires tag_value)
    - tag_value: Filter by tag value (requires tag_key)
    """
    # Enforce max limit
    limit = min(limit, 100)

    # Build base query with join to VM for search
    query = db.query(Backup).join(VM)

    # Apply filters
    if vm_id:
        query = query.filter(Backup.vm_id == vm_id)
    if status:
        query = query.filter(Backup.status == status)

    # Apply search filter (search VM name)
    if search:
        query = query.filter(VM.name.ilike(f"%{search}%"))

    # Apply date range filters
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            query = query.filter(Backup.created_at >= from_date)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date_from format. Use ISO format: 2025-01-01",
            )

    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            # Add one day to include the entire to_date day
            to_date = to_date + timedelta(days=1)
            query = query.filter(Backup.created_at < to_date)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date_to format. Use ISO format: 2025-01-01",
            )

    # Apply tag filters (JSONB query)
    if tag_key and tag_value:
        # Filter backups where tags contain the specified key-value pair
        query = query.filter(Backup.tags[tag_key].astext == tag_value)
    elif tag_key or tag_value:
        raise HTTPException(
            status_code=400,
            detail="Both tag_key and tag_value must be provided together",
        )

    # Get total count (with filters applied)
    total = query.count()

    # Order by most recent first and apply pagination
    backups = (
        query.order_by(Backup.created_at.desc(), Backup.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    deliveries = dispatch_metadata(db, "backup", [backup.id for backup in backups])

    # Build response items
    items = [
        {
            "id": backup.id,
            "vm_id": backup.vm_id,
            "vm_name": backup.vm.name,
            "status": backup.status,
            "progress": backup.progress,
            "storage_progress": backup.storage_progress,
            "safety_diagnostic": public_safety_diagnostic(backup),
            "unverified_legacy_s3": legacy_s3_unverified(backup),
            "size_bytes": backup.size_bytes,
            "retention_days": backup.retention_days,
            "backup_type": backup.backup_type or "full",
            "capacity_state": backup.capacity_state,
            "operator_dispatch": deliveries.get(backup.id),
            "storage_path": backup.storage_path,
            "tags": backup.tags if backup.tags else {},
            "created_at": iso_utc(backup.created_at),
            "completed_at": iso_utc(backup.completed_at),
        }
        for backup in backups
    ]

    # Return paginated response
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@router.post("/backups/{backup_id}/retry-upload")
def retry_upload(
    backup_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Attribute manual retry without converting uncertainty to send authority."""
    from core.upload_retry import record_retry_hold

    reason = record_retry_hold(db, backup_id, current_user.org_id, current_user.id)
    raise HTTPException(423, detail={"status": "held", "reason": reason})


@router.post(
    "/backups/{backup_id}/close-unreserved",
    response_model=BackupCloseUnreservedResponse,
    responses={
        404: {"description": "Backup unavailable"},
        409: {"description": "No-effect proof refused; all custody retained"},
    },
)
def close_unreserved_attempt(
    backup_id: str,
    close_data: BackupCloseUnreservedRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
    request_id: Optional[str] = Depends(request_identity),
):
    """Close a pristine pending human request; preserve its original receipts.

    No provider effects, deletion, capacity release or replacement attempt occurs.
    Supply a new Idempotency-Key for this separately audited closeout action.
    """
    from core.backup_unreserved import UnreservedCloseRefused, close_unreserved_flush

    admission = begin_admission(
        db,
        current_user,
        "backup.close_unreserved",
        {"backup_id": backup_id, "options": close_data.model_dump()},
        request_id,
    )
    if admission.replay:
        return admission.response()
    try:
        result = close_unreserved_flush(db, backup_id, requester_id=current_user.id)
    except UnreservedCloseRefused as error:
        db.rollback()
        raise HTTPException(
            404 if str(error) == "backup_unavailable" else 409,
            detail={"code": str(error)},
            headers={"Cache-Control": "no-store"},
        ) from None
    return admission.finish(result)


@router.post("/backups/{backup_id}/resume", status_code=202)
async def resume_attempt(
    backup_id: str,
    response: Response,
    current_user: User = Depends(get_operator_or_admin),
):
    """Redeliver only this backup's original durable attempt; never replace it."""
    from database import SessionLocal
    from core.backup_recovery import RecoveryHeld, resume_backup_attempt

    response.headers["Cache-Control"] = "no-store"
    try:
        result = await resume_backup_attempt(
            SessionLocal,
            backup_executor,
            backup_id,
            current_user.org_id,
            current_user.id,
        )
    except RecoveryHeld as error:
        raise HTTPException(
            423,
            detail={
                "status": "held",
                "backup_id": backup_id,
                "reason": error.reason,
                "capacity_retained": True,
            },
            headers={"Cache-Control": "no-store"},
        ) from None
    if result["status"] == "completed":
        response.status_code = 200
    return result


@router.delete("/backups/{backup_id}")
def delete_backup(
    backup_id: str,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Delete exact owned payload, retaining its attributable tombstone."""
    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    # Force never bypasses uncertain producer custody.
    if backup.capacity_state in {"reserved", "legacy_held"}:
        raise HTTPException(
            status_code=409,
            detail="Backup holds producer custody; resume or reconcile its original attempt before deletion",
        )
    if backup.status == "running" and not force:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a running backup; inspect its original attempt first",
        )

    vm_name = backup.vm.name
    vm_id = backup.vm_id

    try:
        # Exact-object provider IO belongs on the request worker, not the API loop.
        deleted_bytes = asyncio.run(backup_deletion_service.delete_payload(db, backup))
        if backup.status != "deleted":
            raise BackupDeletionError(
                "Deletion did not preserve a deleted catalog tombstone"
            )
    except BackupDependencyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDeletionError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Payload deletion failed; backup record retained: {exc}",
        ) from exc

    # Accepted lineage, receipts and the catalog tombstone remain attributable.
    log_activity(
        db,
        current_user,
        action="backup_deleted",
        resource_type="backup",
        resource_id=backup_id,
        details={"vm_name": vm_name, "vm_id": vm_id},
    )
    db.commit()

    return {
        "message": f"Backup {backup_id} for {vm_name} deleted",
        "deleted_id": backup_id,
        "deleted_bytes": deleted_bytes,
    }


@router.post("/backups/cleanup")
def cleanup_expired_backups(
    dry_run: bool = False, admin_user: User = Depends(get_admin_user)
):
    """
    Clean up expired backups based on retention policies (admin only).

    - dry_run: If True, return what would be deleted without actually deleting

    Uses RetentionPolicyEnforcer which:
    - Deletes from storage (S3 or filesystem)
    - Retains accepted-generation catalog tombstones and original custody
    - Logs all deletions
    """
    # The scheduled pass already runs on a scheduler worker. Manual invocation
    # must likewise keep synchronous S3/DB calls off the serving API loop.
    result = asyncio.run(retention_enforcer.enforce_all(dry_run=dry_run))
    return {
        "deleted_count": result["deleted_count"],
        "deleted_bytes": result["deleted_bytes"],
        "deleted_gb": round(result["deleted_bytes"] / (1024**3), 2),
        "dry_run": result["dry_run"],
    }
