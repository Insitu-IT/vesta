"""
Backup queue endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import VM, Backup, BackupQueue
from deps import get_current_user, get_operator_or_admin, log_activity, iso_utc
from schemas import BackupQueueCreate
from core.settings_reader import get_max_concurrent_backups
from core.backup_queue_processor import (
    _add_to_queue_flush,
    get_queue_position,
    cancel_queue_item,
)
from core.operator_requests import begin_admission, request_identity

router = APIRouter(prefix="/api/v1", tags=["queue"])


@router.get("/backups/queue")
async def get_backup_queue(
    db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """
    Get the current backup queue status.
    """
    total_queued = db.query(BackupQueue).filter(BackupQueue.status == "queued").count()

    processing = (
        db.query(BackupQueue).filter(BackupQueue.status == "processing").count()
    )

    queued_items = (
        db.query(BackupQueue)
        .filter(BackupQueue.status == "queued")
        .order_by(
            BackupQueue.priority.desc(), BackupQueue.queued_at.asc(), BackupQueue.id
        )
        .all()
    )

    queue_list = []
    for idx, item in enumerate(queued_items):
        queue_list.append(
            {
                "id": item.id,
                "vm_id": item.vm_id,
                "vm_name": item.vm.name if item.vm else "Unknown",
                "priority": item.priority,
                "position": idx + 1,
                "queued_at": iso_utc(item.queued_at),
                "schedule_id": item.schedule_id,
                "created_by": item.user.username if item.user else None,
                "status": item.status,
                "hold_reason": item.hold_reason
                or ("queue_held" if item.status == "held" else None),
                "started_backup_id": item.started_backup_id,
            }
        )

    running_count = db.query(Backup).filter(Backup.status == "running").count()
    max_concurrent = get_max_concurrent_backups(db)

    return {
        "queue": queue_list,
        "total_queued": total_queued,
        "processing": processing,
        "running_backups": running_count,
        "max_concurrent": max_concurrent,
        "available_slots": max(0, max_concurrent - running_count),
    }


@router.post("/backups/queue")
def add_backup_to_queue(
    queue_data: BackupQueueCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
    request_id: str | None = Depends(request_identity),
):
    """
    Add a backup to the queue instead of starting immediately.
    """
    admission = begin_admission(
        db, current_user, "queue.create", queue_data, request_id
    )
    if admission.replay:
        return admission.response()
    vm = db.query(VM).filter(VM.id == queue_data.vm_id).with_for_update().first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    existing_backup = (
        db.query(Backup)
        .filter(
            Backup.vm_id == queue_data.vm_id, Backup.status.in_(["running", "pending"])
        )
        .first()
    )

    if existing_backup:
        raise HTTPException(
            status_code=409,
            detail=f"Backup already {existing_backup.status} for VM {vm.name}",
        )

    existing_queue = (
        db.query(BackupQueue)
        .filter(BackupQueue.vm_id == queue_data.vm_id, BackupQueue.status == "queued")
        .first()
    )

    if existing_queue:
        raise HTTPException(
            status_code=409,
            detail=f"VM {vm.name} is already in queue at position {get_queue_position(db, existing_queue.id)}",
        )

    queue_item = _add_to_queue_flush(
        db=db,
        vm_id=queue_data.vm_id,
        retention_days=queue_data.retention_days,
        backup_type=queue_data.backup_type,
        tags=queue_data.tags,
        exclude_disks=queue_data.exclude_disks,
        workers=queue_data.workers,
        priority=queue_data.priority,
        created_by=current_user.id,
    )

    position = get_queue_position(db, queue_item.id)
    vm_id = queue_data.vm_id

    log_activity(
        db,
        current_user,
        action="backup_queued",
        resource_type="backup_queue",
        resource_id=queue_item.id,
        details={
            "vm_name": vm.name,
            "position": position,
            "priority": queue_item.priority,
        },
        commit=False,
    )

    return admission.finish(
        {
            "id": queue_item.id,
            "vm_id": vm_id,
            "vm_name": vm.name,
            "position": position,
            "priority": queue_item.priority,
            "queued_at": iso_utc(queue_item.queued_at),
            "status": queue_item.status,
            "hold_reason": queue_item.hold_reason,
            "started_backup_id": queue_item.started_backup_id,
            "message": f"Backup queued for {vm.name} at position {position}",
        }
    )


@router.get("/backups/queue/{queue_id}")
def get_backup_queue_item(
    queue_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """A durable queue identity remains readable after it leaves the active list."""
    item = db.query(BackupQueue).filter_by(id=queue_id).first()
    if item is None:
        raise HTTPException(404, "Queue item not found")
    backup = db.get(Backup, item.started_backup_id) if item.started_backup_id else None
    return {
        "id": item.id,
        "vm_id": item.vm_id,
        "status": item.status,
        "hold_reason": item.hold_reason
        or ("queue_held" if item.status == "held" else None),
        "started_backup_id": item.started_backup_id,
        "backup_status": backup.status if backup else None,
        "position": get_queue_position(db, item.id),
        "priority": item.priority,
        "queued_at": iso_utc(item.queued_at),
        "started_at": iso_utc(item.started_at),
    }


@router.delete("/backups/queue/{queue_id}")
async def cancel_queued_backup(
    queue_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """
    Cancel a queued backup.
    """
    item = db.query(BackupQueue).filter(BackupQueue.id == queue_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Queue item not found")

    vm_name = item.vm.name if item.vm else "Unknown"

    if not cancel_queue_item(db, queue_id):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel queue item with status: {item.status}",
        )

    log_activity(
        db,
        current_user,
        action="backup_queue_cancelled",
        resource_type="backup_queue",
        resource_id=queue_id,
        details={"vm_name": vm_name},
    )

    return {"message": f"Queued backup for {vm_name} cancelled"}
