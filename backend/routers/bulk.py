"""
Bulk operations endpoints for backups.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
import asyncio
import logging

from config import settings

from database import get_db
from models import Backup, VM
from deps import get_operator_or_admin, log_activity
from schemas import BulkBackupCreate, BulkBackupDelete, BulkBackupTag
from core.backup_service import BackupService
from core.operator_requests import begin_admission, request_identity, MAX_BULK_TARGETS
from core.backup_deletion import BackupDeletionError, backup_deletion_service

logger = logging.getLogger(__name__)

USE_REAL_BACKUP_EXECUTOR = settings.use_real_backup_executor

router = APIRouter(prefix="/api/v1", tags=["bulk"])


# Import mock backup execution (will be defined in app.py or a shared module)
async def simulate_backup_execution(backup_id: str):
    """Mock backup execution placeholder - imported from main app"""
    pass


def _resolve_bulk_vm_ids(db: Session, bulk_data: BulkBackupCreate) -> list:
    """Resolve VM IDs from either explicit list or filter."""
    if bulk_data.vm_ids:
        return sorted(set(bulk_data.vm_ids))

    if bulk_data.filter:
        from routers.agents import _build_vm_query

        query = _build_vm_query(
            db,
            search=bulk_data.filter.get("search"),
            agent_id=bulk_data.filter.get("agent_id"),
            state=bulk_data.filter.get("state"),
            group_id=bulk_data.filter.get("group_id"),
        )
        return [
            vm.id
            for vm in query.with_entities(VM.id)
            .order_by(VM.id)
            .limit(MAX_BULK_TARGETS + 1)
            .all()
        ]

    return []


@router.post("/backups/bulk-create")
def bulk_create_backups(
    bulk_data: BulkBackupCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
    request_id: str | None = Depends(request_identity),
):
    """Atomically freeze targets, per-target outcomes and original dispatches."""
    intent = bulk_data.model_dump(mode="json")
    if intent.get("vm_ids"):
        intent["vm_ids"] = sorted(set(intent["vm_ids"]))
    admission = begin_admission(
        db, current_user, "backup.bulk_create", intent, request_id
    )
    if admission.replay:
        return admission.response()
    vm_ids = _resolve_bulk_vm_ids(db, bulk_data)
    if not vm_ids:
        raise HTTPException(400, "vm_ids list or a matching filter is required")
    if len(vm_ids) > MAX_BULK_TARGETS:
        raise HTTPException(
            422,
            detail={"code": "bulk_admission_limit", "max_targets": MAX_BULK_TARGETS},
        )
    results = {"created": [], "skipped": [], "failed": []}
    service = BackupService(db)
    for vm_id in vm_ids:
        try:
            with db.begin_nested():
                result = service._create_backup_flush(
                    vm_id=vm_id,
                    retention_days=bulk_data.retention_days,
                    tags=bulk_data.tags,
                    is_bulk_operation=True,
                    check_concurrent=False,
                )
                if not result.success:
                    category = "skipped" if result.error_code == 409 else "failed"
                    results[category].append({"vm_id": vm_id, "reason": result.error})
                    continue
                backup = result.backup
                vm_name = service.get_vm_name(vm_id)
                log_activity(
                    db,
                    current_user,
                    "backup_created",
                    "backup",
                    backup.id,
                    {
                        "vm_name": vm_name,
                        "bulk_operation": True,
                        "retention_days": backup.retention_days,
                    },
                    commit=False,
                )
                admission.dispatch("backup", backup.id)
                created = {"backup_id": backup.id, "vm_id": vm_id, "vm_name": vm_name}
            results["created"].append(created)
        except Exception:
            # Savepoint failure cannot commit half of this request or disclose
            # database/provider diagnostics in a permanently retained receipt.
            logger.warning("Bulk admission failed for a target", exc_info=False)
            results["failed"].append({"vm_id": vm_id, "reason": "admission_failed"})
    return admission.finish(
        {
            "targets": vm_ids,
            "summary": {
                "total": len(vm_ids),
                **{key: len(value) for key, value in results.items()},
            },
            "details": results,
        }
    )


@router.post("/backups/bulk-delete")
def bulk_delete_backups(
    bulk_data: BulkBackupDelete,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """
    Delete multiple backups at once (operator or admin only)
    """
    if not bulk_data.backup_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="backup_ids list cannot be empty",
        )

    results = {"deleted": [], "skipped": [], "failed": []}

    for backup_id in bulk_data.backup_ids:
        try:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if not backup:
                results["failed"].append(
                    {"backup_id": backup_id, "reason": "Backup not found"}
                )
                continue

            if backup.capacity_state in {"reserved", "legacy_held"}:
                results["skipped"].append(
                    {
                        "backup_id": backup_id,
                        "vm_name": backup.vm.name,
                        "reason": (
                            "Backup holds producer custody; resume or reconcile "
                            "its original attempt before deletion"
                        ),
                    }
                )
                continue

            if backup.status == "running":
                results["skipped"].append(
                    {
                        "backup_id": backup_id,
                        "vm_name": backup.vm.name,
                        "reason": "Cannot delete running backup",
                    }
                )
                continue

            vm_name = backup.vm.name
            vm_id = backup.vm_id

            # Provider IO and synchronous SQL belong on this request worker,
            # never on the API loop that serves health and other requests.
            deleted_bytes = asyncio.run(
                backup_deletion_service.delete_payload(db, backup)
            )

            if backup.status != "deleted":
                raise BackupDeletionError(
                    "Deletion did not preserve a deleted catalog tombstone"
                )

            log_activity(
                db,
                current_user,
                action="backup_deleted",
                resource_type="backup",
                resource_id=backup_id,
                details={"vm_name": vm_name, "vm_id": vm_id, "bulk_operation": True},
            )
            db.commit()

            results["deleted"].append(
                {
                    "backup_id": backup_id,
                    "vm_name": vm_name,
                    "deleted_bytes": deleted_bytes,
                }
            )

        except Exception as e:
            db.rollback()
            results["failed"].append({"backup_id": backup_id, "reason": str(e)})

    return {
        "summary": {
            "total": len(bulk_data.backup_ids),
            "deleted": len(results["deleted"]),
            "skipped": len(results["skipped"]),
            "failed": len(results["failed"]),
        },
        "details": results,
    }


@router.post("/backups/bulk-tag")
def bulk_tag_backups(
    bulk_data: BulkBackupTag,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """
    Add or update tags on multiple backups at once (operator or admin only)
    """
    if not bulk_data.backup_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="backup_ids list cannot be empty",
        )

    if not bulk_data.tags:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="tags cannot be empty"
        )

    results = {"updated": [], "failed": []}

    for backup_id in bulk_data.backup_ids:
        try:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if not backup:
                results["failed"].append(
                    {"backup_id": backup_id, "reason": "Backup not found"}
                )
                continue

            old_tags = backup.tags.copy() if backup.tags else {}

            if bulk_data.overwrite:
                backup.tags = bulk_data.tags.copy()
            else:
                if not backup.tags:
                    backup.tags = {}
                backup.tags.update(bulk_data.tags)

            log_activity(
                db,
                current_user,
                action="backup_tagged",
                resource_type="backup",
                resource_id=backup_id,
                details={
                    "vm_name": backup.vm.name,
                    "bulk_operation": True,
                    "overwrite": bulk_data.overwrite,
                    "tags": bulk_data.tags,
                },
            )

            results["updated"].append(
                {
                    "backup_id": backup_id,
                    "vm_name": backup.vm.name,
                    "old_tags": old_tags,
                    "new_tags": backup.tags,
                }
            )

        except Exception as e:
            db.rollback()
            results["failed"].append({"backup_id": backup_id, "reason": str(e)})

    return {
        "summary": {
            "total": len(bulk_data.backup_ids),
            "updated": len(results["updated"]),
            "failed": len(results["failed"]),
        },
        "details": results,
    }
