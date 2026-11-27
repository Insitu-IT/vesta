"""
Restore operations endpoints.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Annotated
import uuid
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from database import get_db
from models import Backup, Restore, VM
from deps import get_current_user, check_role, log_activity, iso_utc
from core.restore_executor import restore_executor
from core.bucket_recovery import public_point
from core.legacy_recovery import (
    LEGACY_RECOVERY_REFUSAL,
    legacy_s3_unverified,
    recorded_legacy_local_path,
)
from core.operator_requests import begin_admission, request_identity, dispatch_metadata

router = APIRouter(prefix="/api/v1", tags=["restores"])


class RestoreCreateRequest(BaseModel):
    """Normalize defaults before identity matching; refuse ignored intent."""

    model_config = ConfigDict(extra="forbid")
    backup_id: str = Field(min_length=1)
    restore_to_original: StrictBool = True
    target_vm_name: Optional[str] = None
    until_checkpoint: Optional[str] = None
    auto_define: StrictBool = False
    adjust_config: StrictBool = False
    selected_disks: list[str] = Field(default_factory=list)
    native_target: Optional[dict] = None
    kubevirt_target: Optional[dict] = None


@router.post("/restores", status_code=status.HTTP_201_CREATED)
def create_restore(
    restore_data: RestoreCreateRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: str | None = Depends(request_identity),
):
    """Create a restore operation from a backup"""
    check_role(current_user, ["admin", "operator"])
    restore_data = RestoreCreateRequest.model_validate(restore_data).model_dump(
        mode="json"
    )
    admission = begin_admission(
        db, current_user, "restore.create", restore_data, request_id
    )
    if admission.replay:
        return admission.response()

    backup = (
        db.query(Backup)
        .filter_by(id=restore_data.get("backup_id"), org_id=current_user.org_id)
        .first()
    )
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    if legacy_s3_unverified(backup):
        raise HTTPException(409, LEGACY_RECOVERY_REFUSAL)

    if backup.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot restore from backup with status: {backup.status}",
        )

    if backup.vm and backup.vm.provider == "kubevirt":
        return _create_kubevirt_restore(
            restore_data, backup, background_tasks, current_user, db, admission
        )
    if backup.vm and backup.vm.provider == "libvirt":
        return _create_native_restore(
            restore_data, backup, background_tasks, current_user, db, admission
        )

    if recorded_legacy_local_path(backup) is None:
        raise HTTPException(409, LEGACY_RECOVERY_REFUSAL)

    restore_to_original = restore_data.get("restore_to_original", True)
    target_vm_name = restore_data.get("target_vm_name")
    until_checkpoint = restore_data.get("until_checkpoint")
    auto_define = restore_data.get("auto_define", False)
    adjust_config = restore_data.get("adjust_config", False)
    selected_disks = restore_data.get("selected_disks", [])

    if not restore_to_original and not target_vm_name:
        raise HTTPException(
            status_code=400,
            detail="target_vm_name is required when restore_to_original is false",
        )

    target_vm_id = None
    if not restore_to_original:
        existing_vm = db.query(VM).filter(VM.name == target_vm_name).first()
        if existing_vm:
            raise HTTPException(
                status_code=400,
                detail=f"VM with name '{target_vm_name}' already exists",
            )
    else:
        target_vm_id = backup.vm_id

    restore = Restore(
        backup_id=backup.id,
        target_vm_id=target_vm_id,
        restore_to_original=restore_to_original,
        target_vm_name=target_vm_name if not restore_to_original else None,
        status="pending",
        progress=0,
        created_by=current_user.id,
        until_checkpoint=until_checkpoint,
        auto_define=auto_define,
        adjust_config=adjust_config,
        selected_disks=selected_disks or [],
    )

    db.add(restore)
    db.flush()

    log_activity(
        db,
        current_user,
        action="restore_created",
        resource_type="restore",
        resource_id=restore.id,
        details={
            "backup_id": backup.id,
            "vm_name": backup.vm.name if backup.vm else "Unknown",
            "restore_to_original": restore_to_original,
            "target_vm_name": target_vm_name,
            "encrypted": backup.tags.get("encrypted", False) if backup.tags else False,
        },
        commit=False,
    )

    # Execute restore via agent (v3.0.3: supports encrypted backups)
    admission.dispatch("restore", restore.id)

    return admission.finish(
        {
            "id": restore.id,
            "backup_id": restore.backup_id,
            "status": restore.status,
            "progress": restore.progress,
            "restore_to_original": restore.restore_to_original,
            "target_vm_name": restore.target_vm_name,
            "target_vm_id": restore.target_vm_id,
            "created_at": iso_utc(restore.created_at),
            "message": "Restore operation started",
        },
        status=201,
    )


def _create_native_restore(data, backup, background_tasks, current_user, db, admission):
    from core.native_restore import build_plan
    from core.s3_ownership import StorageOwnershipError

    if data.get("restore_to_original") is not False or any(
        data.get(key) for key in ("selected_disks", "until_checkpoint", "adjust_config")
    ):
        raise HTTPException(
            422, "Native restore requires a fresh VM and all protected disks"
        )
    identity = str(uuid.uuid4())
    try:
        plan = build_plan(
            db,
            backup_id=backup.id,
            org_id=current_user.org_id,
            actor_id=current_user.id,
            restore_id=identity,
            target=data.get("native_target"),
        )
        if data.get("target_vm_name") not in (None, plan["target"]["vm_name"]):
            raise StorageOwnershipError("Target VM names disagree")
        restore = Restore(
            id=identity,
            org_id=current_user.org_id,
            backup_id=backup.id,
            restore_to_original=False,
            target_vm_name=plan["target"]["vm_name"],
            target_vm_id=None,
            status="pending",
            progress=0,
            created_by=current_user.id,
            selected_disks=[],
            auto_define=True,
            adjust_config=False,
            native_plan=plan,
        )
        db.add(restore)
        db.flush()
    except StorageOwnershipError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None
    log_activity(
        db,
        current_user,
        action="restore_created",
        resource_type="restore",
        resource_id=identity,
        details={
            "backup_id": backup.id,
            "target_vm_name": restore.target_vm_name,
            "state": "shutoff",
        },
        commit=False,
    )
    admission.dispatch("restore", identity)
    return admission.finish(
        {
            "id": identity,
            "backup_id": backup.id,
            "status": "pending",
            "progress": 0,
            "restore_to_original": False,
            "target_vm_name": restore.target_vm_name,
            "native_target": plan["target"],
            "message": "Fresh inactive native VM restore queued",
        },
        status=201,
    )


def _create_kubevirt_restore(
    data, backup, background_tasks, current_user, db, admission
):
    from core.kubevirt_restore import build_plan
    from core.s3_ownership import StorageOwnershipError

    if data.get("restore_to_original") is not False or any(
        data.get(key) for key in ("selected_disks", "until_checkpoint", "adjust_config")
    ):
        raise HTTPException(
            422, "KubeVirt restore requires a fresh VM and all protected disks"
        )
    identity = str(uuid.uuid4())
    try:
        plan = build_plan(
            db,
            backup_id=backup.id,
            org_id=current_user.org_id,
            actor_id=current_user.id,
            restore_id=identity,
            target=data.get("kubevirt_target"),
        )
        if data.get("target_vm_name") not in (None, plan["target"]["vm_name"]):
            raise StorageOwnershipError("Target VM names disagree")
        restore = Restore(
            id=identity,
            org_id=current_user.org_id,
            backup_id=backup.id,
            restore_to_original=False,
            target_vm_name=plan["target"]["vm_name"],
            target_vm_id=None,
            status="pending",
            progress=0,
            created_by=current_user.id,
            selected_disks=[],
            auto_define=True,
            adjust_config=False,
            kubevirt_plan=plan,
        )
        db.add(restore)
        db.flush()
    except StorageOwnershipError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None
    log_activity(
        db,
        current_user,
        action="restore_created",
        resource_type="restore",
        resource_id=identity,
        details={
            "backup_id": backup.id,
            "namespace": plan["target"]["namespace"],
            "target_vm_name": plan["target"]["vm_name"],
            "run_strategy": "Halted",
        },
        commit=False,
    )
    admission.dispatch("restore", identity)
    return admission.finish(
        {
            "id": identity,
            "backup_id": backup.id,
            "status": "pending",
            "progress": 0,
            "restore_to_original": False,
            "target_vm_name": restore.target_vm_name,
            "kubevirt_target": plan["target"],
            "message": "Fresh Halted VM restore queued",
        },
        status=201,
    )


@router.get("/restores")
def get_restores(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    status: Optional[str] = None,
    backup_id: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get list of restore operations"""
    limit = min(limit, 100)
    query = db.query(Restore).filter_by(org_id=current_user.org_id)

    if status:
        query = query.filter(Restore.status == status)
    if backup_id:
        query = query.filter(Restore.backup_id == backup_id)

    query = query.order_by(Restore.created_at.desc(), Restore.id.desc())
    total = query.count()
    restores = query.offset(skip).limit(limit).all()
    deliveries = dispatch_metadata(db, "restore", [restore.id for restore in restores])

    items = []
    for restore in restores:
        item = {
            "id": restore.id,
            "backup_id": restore.backup_id,
            "status": restore.status,
            "progress": restore.progress,
            "restore_to_original": restore.restore_to_original,
            "target_vm_name": restore.target_vm_name,
            "target_vm_id": restore.target_vm_id,
            "created_by": restore.created_by,
            "created_at": iso_utc(restore.created_at),
            "started_at": iso_utc(restore.started_at),
            "completed_at": iso_utc(restore.completed_at),
            "error_message": restore.error_message,
            "operator_dispatch": deliveries.get(restore.id),
            "kubevirt_target": (restore.kubevirt_plan or {}).get("target"),
            "native_target": (restore.native_plan or {}).get("target"),
            "result": restore.kubevirt_result or restore.native_result,
        }

        if restore.s3_recovery:
            item["recovery_source"] = public_point(restore.s3_recovery["point"])

        if restore.backup:
            item["backup"] = {
                "id": restore.backup.id,
                "vm_name": restore.backup.vm.name if restore.backup.vm else "Unknown",
                "created_at": iso_utc(restore.backup.created_at),
                "size_bytes": restore.backup.size_bytes,
            }

        if restore.user:
            item["created_by_user"] = {
                "username": restore.user.username,
                "role": restore.user.role,
            }

        items.append(item)

    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get("/restores/{restore_id}")
def get_restore(
    restore_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get restore operation details"""
    restore = (
        db.query(Restore).filter_by(id=restore_id, org_id=current_user.org_id).first()
    )
    if not restore:
        raise HTTPException(status_code=404, detail="Restore not found")

    result = {
        "id": restore.id,
        "backup_id": restore.backup_id,
        "status": restore.status,
        "progress": restore.progress,
        "restore_to_original": restore.restore_to_original,
        "target_vm_name": restore.target_vm_name,
        "target_vm_id": restore.target_vm_id,
        "created_by": restore.created_by,
        "created_at": iso_utc(restore.created_at),
        "started_at": iso_utc(restore.started_at),
        "completed_at": iso_utc(restore.completed_at),
        "error_message": restore.error_message,
        "operator_dispatch": dispatch_metadata(db, "restore", [restore.id]).get(
            restore.id
        ),
        "kubevirt_target": (restore.kubevirt_plan or {}).get("target"),
        "native_target": (restore.native_plan or {}).get("target"),
        "result": restore.kubevirt_result or restore.native_result,
    }

    if restore.s3_recovery:
        result["recovery_source"] = public_point(restore.s3_recovery["point"])

    if restore.backup:
        result["backup"] = {
            "id": restore.backup.id,
            "vm_id": restore.backup.vm_id,
            "vm_name": restore.backup.vm.name if restore.backup.vm else "Unknown",
            "created_at": iso_utc(restore.backup.created_at),
            "size_bytes": restore.backup.size_bytes,
            "status": restore.backup.status,
        }

    if restore.target_vm:
        result["target_vm"] = {
            "id": restore.target_vm.id,
            "name": restore.target_vm.name,
            "state": restore.target_vm.state,
            "agent_hostname": (
                restore.target_vm.agent.hostname if restore.target_vm.agent else None
            ),
        }

    if restore.user:
        result["created_by_user"] = {
            "username": restore.user.username,
            "role": restore.user.role,
        }

    return result


@router.post("/restores/{restore_id}/resume", status_code=status.HTTP_202_ACCEPTED)
def resume_kubevirt_restore(
    restore_id: str,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Resume backend monitoring/uncertain dispatch using the same durable plan.

    The agent independently reopens its local journal after restart; this never
    allocates a new restore ID or overwrites failed/uncertain destinations.
    """
    check_role(current_user, ["admin", "operator"])
    restore = (
        db.query(Restore).filter_by(id=restore_id, org_id=current_user.org_id).first()
    )
    if restore is None:
        raise HTTPException(404, "Restore not found")
    if restore.created_by != current_user.id:
        raise HTTPException(
            403, "The enrolled restore principal must resume this operation"
        )
    if not (restore.kubevirt_plan or restore.native_plan) or restore.status not in {
        "pending",
        "dispatching",
        "running",
    }:
        raise HTTPException(409, "This restore cannot be automatically resumed")
    background_tasks.add_task(
        restore_executor.execute_restore, restore.id, restore.org_id, current_user.id
    )
    return {
        "id": restore.id,
        "status": restore.status,
        "message": "Original restore reconciliation queued",
    }


@router.patch("/restores/{restore_id}/cancel")
def cancel_restore(
    restore_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cancel a running restore operation"""
    check_role(current_user, ["admin", "operator"])

    restore = (
        db.query(Restore).filter_by(id=restore_id, org_id=current_user.org_id).first()
    )
    if not restore:
        raise HTTPException(status_code=404, detail="Restore not found")

    if restore.kubevirt_plan or restore.native_plan:
        raise HTTPException(
            409,
            "Fresh restore cancellation requires fencing its recorded worker; "
            "destinations are retained and must not be marked cancelled while writes may continue",
        )

    if restore.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel restore with status: {restore.status}",
        )

    previous_status = restore.status
    restore.status = "cancelled"
    restore.completed_at = datetime.utcnow()
    db.commit()

    log_activity(
        db,
        current_user,
        action="restore_cancelled",
        resource_type="restore",
        resource_id=restore.id,
        details={"backup_id": restore.backup_id, "previous_status": previous_status},
    )

    return {
        "message": "Restore cancelled",
        "restore_id": restore.id,
        "status": restore.status,
    }
