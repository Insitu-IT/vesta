"""
Schedule management endpoints: list, create, get, update, delete, run-now.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
import logging
from uuid import UUID
from pydantic import BaseModel, Field

from database import get_db
from models import Schedule, VM, VMGroup, SchedulerGrant, Organization
from deps import (
    get_current_user,
    get_operator_or_admin,
    get_admin_user,
    log_activity,
    iso_utc,
)
from schemas import ScheduleCreate, ScheduleUpdate
from core.scheduler_scope import ScopeRefused
from core.scheduler_policy import BackupPolicyError, validate_mode
from core.scheduler_grants import (
    preview_grant,
    enroll_grant,
    revoke_grant_flush,
    require_current_grant,
)

# Import scheduler functions - these will be provided by a scheduler module
from scheduler import (
    calculate_next_run,
    add_schedule_to_scheduler,
    remove_schedule_from_scheduler,
    execute_scheduled_backup,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["schedules"])


def _authority(db, schedule):
    from core.backup_authority import schedule_authority_state

    grant = (
        db.get(SchedulerGrant, schedule.current_grant_id)
        if schedule.current_grant_id
        else None
    )
    organization = db.get(Organization, schedule.org_id)
    return {
        "authority_revision": schedule.authority_revision,
        "current_grant_id": schedule.current_grant_id,
        "authority_state": schedule_authority_state(schedule, grant, organization),
    }


class GrantEnrollment(BaseModel):
    request_id: UUID
    expected_revision: int = Field(gt=0)
    scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replace_grant_id: Optional[UUID] = None
    enable: bool = True


@router.get("/schedules/{schedule_id}/grant")
def get_schedule_grant(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    schedule = db.query(Schedule).filter_by(id=schedule_id).one_or_none()
    if schedule is None:
        raise HTTPException(404, "Schedule not found")
    try:
        return {**preview_grant(db, schedule), **_authority(db, schedule)}
    except ScopeRefused as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/schedules/{schedule_id}/grant")
def enroll_schedule_grant(
    schedule_id: str,
    data: GrantEnrollment,
    db: Session = Depends(get_db),
    current_user=Depends(get_admin_user),
):
    try:
        grant = enroll_grant(
            db,
            schedule_id,
            request_id=str(data.request_id),
            expected_revision=data.expected_revision,
            scope_sha256=data.scope_sha256,
            replace_grant_id=(
                str(data.replace_grant_id) if data.replace_grant_id else None
            ),
            enable=data.enable,
        )
        schedule = db.get(Schedule, schedule_id)
        if schedule.enabled:
            add_schedule_to_scheduler(
                schedule.id, schedule.cron_expression, schedule.org_id
            )
        else:
            remove_schedule_from_scheduler(schedule.id)
        log_activity(
            db,
            current_user,
            action="scheduler_grant_enrolled",
            resource_type="schedule",
            resource_id=schedule.id,
            details={"grant_id": grant.id, "scope_sha256": grant.scope_sha256},
        )
        return {
            "grant_id": grant.id,
            "enabled": schedule.enabled,
            **_authority(db, schedule),
        }
    except ScopeRefused as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.delete("/schedules/{schedule_id}/grant")
def revoke_schedule_grant(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_admin_user),
):
    from core.scheduler_grants import _actor, _lock

    try:
        org, actor = _actor(db, admin=True)
        schedule = _lock(db, Schedule, id=schedule_id, org_id=org.id)
        revoke_grant_flush(db, schedule, actor.id, "revoked_by_administrator")
        schedule.enabled = False
        db.commit()
        remove_schedule_from_scheduler(schedule.id)
        log_activity(
            db,
            current_user,
            action="scheduler_grant_revoked",
            resource_type="schedule",
            resource_id=schedule.id,
        )
        return {"enabled": False, **_authority(db, schedule)}
    except ScopeRefused as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.get("/schedules")
def list_schedules(
    skip: int = 0,
    limit: int = 50,
    enabled: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List all backup schedules"""
    # Enforce max limit
    limit = min(limit, 100)

    # Build query
    query = db.query(Schedule).filter(Schedule.retired_at.is_(None))

    # Filter by enabled status if specified
    if enabled is not None:
        query = query.filter(Schedule.enabled == enabled)

    # Get total count
    total = query.count()

    # Order by most recent first and apply pagination
    schedules = (
        query.order_by(Schedule.created_at.desc()).offset(skip).limit(limit).all()
    )

    # Build response items
    items = []
    for schedule in schedules:
        item = {
            **_authority(db, schedule),
            "id": schedule.id,
            "name": schedule.name,
            "vm_id": schedule.vm_id,
            "vm_name": schedule.vm.name if schedule.vm else None,
            "vm_group_id": schedule.vm_group_id,
            "vm_group_name": schedule.vm_group.name if schedule.vm_group else None,
            "cron_expression": schedule.cron_expression,
            "backup_type": schedule.backup_type or "full",
            "backup_policy": schedule.backup_policy,
            "exclude_disks": schedule.exclude_disks or [],
            "workers": schedule.workers,
            "retention_days": schedule.retention_days,
            "tags": schedule.tags if schedule.tags else {},
            "enabled": schedule.enabled,
            "last_run_at": iso_utc(schedule.last_run_at),
            "next_run_at": iso_utc(schedule.next_run_at),
            "created_at": iso_utc(schedule.created_at),
            "updated_at": iso_utc(schedule.updated_at),
        }
        items.append(item)

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(
    schedule_data: ScheduleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """Create a new backup schedule (operator or admin only)"""
    if schedule_data.enabled:
        raise HTTPException(
            409,
            "Create the schedule paused, then an organization admin must enroll its grant",
        )
    try:
        backup_policy = validate_mode(
            schedule_data.backup_type, schedule_data.backup_policy
        )
    except BackupPolicyError as exc:
        raise HTTPException(422, str(exc)) from exc

    # Validate that either vm_id or vm_group_id is provided, but not both
    if not schedule_data.vm_id and not schedule_data.vm_group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either vm_id or vm_group_id must be provided",
        )

    if schedule_data.vm_id and schedule_data.vm_group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot specify both vm_id and vm_group_id",
        )

    # Validate VM exists if vm_id provided
    if schedule_data.vm_id:
        vm = db.query(VM).filter(VM.id == schedule_data.vm_id).first()
        if not vm:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="VM not found"
            )

    # Validate VM Group exists if vm_group_id provided
    if schedule_data.vm_group_id:
        vm_group = (
            db.query(VMGroup).filter(VMGroup.id == schedule_data.vm_group_id).first()
        )
        if not vm_group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="VM Group not found"
            )

    # Validate cron expression
    try:
        next_run = calculate_next_run(schedule_data.cron_expression)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Create schedule
    schedule = Schedule(
        name=schedule_data.name,
        vm_id=schedule_data.vm_id,
        vm_group_id=schedule_data.vm_group_id,
        cron_expression=schedule_data.cron_expression,
        backup_type=schedule_data.backup_type,
        backup_policy=backup_policy,
        exclude_disks=schedule_data.exclude_disks,
        workers=schedule_data.workers,
        retention_days=schedule_data.retention_days,
        tags=schedule_data.tags,
        enabled=schedule_data.enabled,
        next_run_at=next_run,
    )

    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Add to scheduler if enabled
    if schedule.enabled:
        add_schedule_to_scheduler(schedule.id, schedule.cron_expression)

    # Log activity
    log_activity(
        db,
        current_user,
        action="schedule_created",
        resource_type="schedule",
        resource_id=schedule.id,
        details={
            "name": schedule.name,
            "cron": schedule.cron_expression,
            "vm_id": schedule.vm_id,
            "vm_group_id": schedule.vm_group_id,
        },
    )

    return {
        **_authority(db, schedule),
        "id": schedule.id,
        "name": schedule.name,
        "vm_id": schedule.vm_id,
        "vm_group_id": schedule.vm_group_id,
        "cron_expression": schedule.cron_expression,
        "backup_type": schedule.backup_type or "full",
        "backup_policy": schedule.backup_policy,
        "exclude_disks": schedule.exclude_disks or [],
        "workers": schedule.workers,
        "retention_days": schedule.retention_days,
        "tags": schedule.tags,
        "enabled": schedule.enabled,
        "next_run_at": iso_utc(schedule.next_run_at),
        "created_at": iso_utc(schedule.created_at),
    }


@router.get("/schedules/{schedule_id}")
def get_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get schedule details"""
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found"
        )

    return {
        **_authority(db, schedule),
        "id": schedule.id,
        "name": schedule.name,
        "vm_id": schedule.vm_id,
        "vm_name": schedule.vm.name if schedule.vm else None,
        "vm_group_id": schedule.vm_group_id,
        "vm_group_name": schedule.vm_group.name if schedule.vm_group else None,
        "cron_expression": schedule.cron_expression,
        "backup_type": schedule.backup_type or "full",
        "backup_policy": schedule.backup_policy,
        "exclude_disks": schedule.exclude_disks or [],
        "workers": schedule.workers,
        "retention_days": schedule.retention_days,
        "tags": schedule.tags if schedule.tags else {},
        "enabled": schedule.enabled,
        "last_run_at": iso_utc(schedule.last_run_at),
        "next_run_at": iso_utc(schedule.next_run_at),
        "created_at": iso_utc(schedule.created_at),
        "updated_at": iso_utc(schedule.updated_at),
    }


@router.put("/schedules/{schedule_id}")
def update_schedule(
    schedule_id: str,
    schedule_data: ScheduleUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """Update schedule (operator or admin only)"""
    from core.scheduler_grants import _actor

    _actor(db)
    schedule = (
        db.query(Schedule)
        .filter(Schedule.id == schedule_id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found"
        )

    if schedule.retired_at is not None:
        raise HTTPException(409, "Schedule is retired")
    mode = schedule_data.backup_type or schedule.backup_type
    policy_present = "backup_policy" in schedule_data.model_fields_set
    try:
        backup_policy = validate_mode(
            mode,
            schedule_data.backup_policy if policy_present else schedule.backup_policy,
        )
    except BackupPolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    # Execution-affecting edits revoke the previous scope. Editing remains an
    # operator action; only an organization administrator can issue its successor.
    scope_changed = any(
        getattr(schedule_data, name) is not None
        and getattr(schedule_data, name) != getattr(schedule, name)
        for name in (
            "cron_expression",
            "retention_days",
            "backup_type",
            "tags",
            "exclude_disks",
        )
    ) or (policy_present and backup_policy != schedule.backup_policy)
    if scope_changed:
        revoke_grant_flush(db, schedule, current_user.id, "schedule_options_changed")
        schedule.authority_revision += 1
        schedule.enabled = False
    if schedule_data.enabled is True and not scope_changed:
        try:
            require_current_grant(db, schedule)
        except ScopeRefused as exc:
            db.rollback()
            raise HTTPException(409, str(exc)) from exc

    changes = {}

    # Update name if provided
    if schedule_data.name:
        changes["name"] = f"{schedule.name} -> {schedule_data.name}"
        schedule.name = schedule_data.name

    # Update cron expression if provided
    if schedule_data.cron_expression:
        # Validate new cron expression
        try:
            next_run = calculate_next_run(schedule_data.cron_expression)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        changes["cron_expression"] = (
            f"{schedule.cron_expression} -> {schedule_data.cron_expression}"
        )
        schedule.cron_expression = schedule_data.cron_expression
        schedule.next_run_at = next_run

    # Update retention_days if provided
    if schedule_data.retention_days is not None:
        changes["retention_days"] = (
            f"{schedule.retention_days} -> {schedule_data.retention_days}"
        )
        schedule.retention_days = schedule_data.retention_days

    if schedule_data.backup_type is not None:
        changes["backup_type"] = (
            f"{schedule.backup_type or 'full'} -> {schedule_data.backup_type}"
        )
        schedule.backup_type = schedule_data.backup_type

    if policy_present:
        schedule.backup_policy = backup_policy
        changes["backup_policy"] = "updated"

    if schedule_data.exclude_disks is not None:
        schedule.exclude_disks = schedule_data.exclude_disks
        changes["exclude_disks"] = "updated"

    # Legacy stored worker values remain part of existing grant scope. Null or
    # omitted API values do not change them; new overrides fail schema validation.

    # Update tags if provided
    if schedule_data.tags is not None:
        schedule.tags = schedule_data.tags
        changes["tags"] = "updated"

    # Update enabled if provided
    if schedule_data.enabled is not None and not scope_changed:
        old_enabled = schedule.enabled
        schedule.enabled = schedule_data.enabled
        changes["enabled"] = f"{old_enabled} -> {schedule_data.enabled}"

    schedule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(schedule)
    if schedule.enabled:
        add_schedule_to_scheduler(
            schedule.id, schedule.cron_expression, schedule.org_id
        )
    else:
        remove_schedule_from_scheduler(schedule.id)

    # Log activity
    log_activity(
        db,
        current_user,
        action="schedule_updated",
        resource_type="schedule",
        resource_id=schedule.id,
        details={"name": schedule.name, "changes": changes},
    )

    return {
        **_authority(db, schedule),
        "id": schedule.id,
        "name": schedule.name,
        "vm_id": schedule.vm_id,
        "vm_group_id": schedule.vm_group_id,
        "cron_expression": schedule.cron_expression,
        "backup_type": schedule.backup_type or "full",
        "backup_policy": schedule.backup_policy,
        "exclude_disks": schedule.exclude_disks or [],
        "workers": schedule.workers,
        "retention_days": schedule.retention_days,
        "tags": schedule.tags,
        "enabled": schedule.enabled,
        "last_run_at": iso_utc(schedule.last_run_at),
        "next_run_at": iso_utc(schedule.next_run_at),
        "created_at": iso_utc(schedule.created_at),
        "updated_at": iso_utc(schedule.updated_at),
    }


@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """Delete schedule (operator or admin only)"""
    from core.scheduler_grants import _actor

    _actor(db)
    schedule = (
        db.query(Schedule)
        .filter(Schedule.id == schedule_id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found"
        )

    schedule_name = schedule.name

    # Remove from scheduler
    remove_schedule_from_scheduler(schedule.id)

    # Grant/occurrence audit is retained. Retirement cannot cascade away the
    # original authority behind completed or still uncertain backups.
    revoke_grant_flush(db, schedule, current_user.id, "schedule_retired")
    schedule.enabled = False
    schedule.retired_at = datetime.utcnow()
    db.commit()

    # Log activity
    log_activity(
        db,
        current_user,
        action="schedule_deleted",
        resource_type="schedule",
        resource_id=schedule_id,
        details={"name": schedule_name},
    )

    return {"message": f"Schedule '{schedule_name}' deleted successfully"}


@router.post("/schedules/{schedule_id}/run-now")
def run_schedule_now(
    schedule_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(get_operator_or_admin),
):
    """Manually trigger a schedule to run immediately (operator or admin only)"""
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found"
        )

    # Execute schedule in background
    background_tasks.add_task(
        execute_scheduled_backup,
        schedule_id,
        str(current_user.org_id),
        str(current_user.id),
    )

    # Log activity
    log_activity(
        db,
        current_user,
        action="schedule_triggered",
        resource_type="schedule",
        resource_id=schedule_id,
        details={"name": schedule.name, "triggered_by": "manual"},
    )

    return {
        "message": f"Schedule '{schedule.name}' triggered successfully",
        "schedule_id": schedule_id,
    }
