"""Typed, organization-scoped API for full backups of host-declared file sets."""

from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from config import settings
from core.file_backups import (
    FILE_SET_PATTERN,
    AdmissionRefused,
    admit_manual,
    advertised_file_sets,
    bind_storage,
    storage_binding,
    clock,
    file_storage,
    locked_actor,
    require_target,
)
from database import get_db
from deps import get_admin_user, get_current_user, get_operator_or_admin, log_activity
from models import Agent, FileBackup, FileSchedule, Organization
from scheduler import calculate_next_run


def enabled():
    if settings.demo_mode:
        raise HTTPException(404, "Managed file backup is unavailable")


router = APIRouter(
    prefix="/api/v1", tags=["file backups"], dependencies=[Depends(enabled)]
)
FileSetName = Annotated[str, Field(pattern=FILE_SET_PATTERN)]


class FileContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FileSetTarget(FileContract):
    kind: Literal["file_set"]
    agent_id: UUID
    file_set: FileSetName


class FileStorage(FileContract):
    endpoint: str
    region: str
    bucket: str
    prefix: str
    recipient_sha256: str


class FileSetItem(FileContract):
    target: FileSetTarget
    host_name: str
    host_status: str
    last_success_at: datetime | None
    storage: FileStorage | None


class FileSetList(FileContract):
    items: list[FileSetItem]


class FileBackupBody(FileContract):
    target: FileSetTarget


class FileBackupItem(FileContract):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target: FileSetTarget
    status: Literal["pending", "running", "completed", "failed"]
    schedule_id: UUID | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    files: int | None
    directories: int | None
    bytes: int | None
    error: str | None
    s3_path: str | None
    s3_version_id: str | None
    archive_format: str | None
    archive_size_bytes: int | None
    storage: FileStorage
    archive_sha256: str | None
    recipient_sha256: str | None


class FileBackupList(FileContract):
    items: list[FileBackupItem]


class FileScheduleBody(FileContract):
    name: str = Field(min_length=1, max_length=255)
    target: FileSetTarget
    cron_expression: str = Field(min_length=1, max_length=100)
    enabled: bool = True


class FileScheduleUpdate(FileContract):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    cron_expression: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool | None = None

    @model_validator(mode="after")
    def require_changes(self):
        if not self.model_fields_set or any(
            getattr(self, name) is None for name in self.model_fields_set
        ):
            raise ValueError("Provide a name, cron expression, or enabled state")
        return self


class FileScheduleItem(FileContract):
    id: UUID
    name: str
    target: FileSetTarget
    cron_expression: str
    enabled: bool
    authority_state: Literal["active", "inactive", "fenced"]
    storage: FileStorage
    created_at: datetime
    last_run_at: datetime | None
    next_run_at: datetime | None
    last_success_at: datetime | None
    last_status: str | None
    last_error: str | None


class FileScheduleList(FileContract):
    items: list[FileScheduleItem]


def _target(agent_id, file_set):
    return FileSetTarget(kind="file_set", agent_id=agent_id, file_set=file_set)


def _backup(row):
    return FileBackupItem.model_validate(
        {
            field: getattr(row, field)
            for field in FileBackupItem.model_fields
            if field != "storage"
        }
        | {"storage": storage_binding(row)}
    )


def _refusal(exc):
    return HTTPException(exc.status, {"code": exc.code, "message": str(exc)})


@router.get("/file-sets", response_model=FileSetList)
def list_file_sets(db: Session = Depends(get_db), user=Depends(get_current_user)):
    successes = {
        (agent_id, name): timestamp
        for agent_id, name, timestamp in db.execute(
            select(
                FileBackup.agent_id,
                FileBackup.file_set,
                func.max(FileBackup.completed_at),
            )
            .where(FileBackup.org_id == user.org_id, FileBackup.status == "completed")
            .group_by(FileBackup.agent_id, FileBackup.file_set)
        )
    }
    agents = db.scalars(
        select(Agent)
        .where(Agent.org_id == user.org_id)
        .order_by(Agent.hostname, Agent.id)
    )
    return FileSetList(
        items=[
            FileSetItem(
                target=_target(agent.id, name),
                host_name=agent.get_display_name(),
                host_status=agent.status or "offline",
                last_success_at=successes.get((agent.id, name)),
                storage=file_storage(agent.capabilities, name),
            )
            for agent in agents
            for name in sorted(advertised_file_sets(agent.capabilities))
        ]
    )


@router.get("/file-backups", response_model=FileBackupList)
def list_file_backups(
    agent_id: UUID | None = None,
    file_set: FileSetName | None = None,
    schedule_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query = select(FileBackup).where(FileBackup.org_id == user.org_id)
    for column, value in (
        (FileBackup.agent_id, agent_id),
        (FileBackup.file_set, file_set),
        (FileBackup.schedule_id, schedule_id),
    ):
        if value is not None:
            query = query.where(column == str(value))
    rows = db.scalars(
        query.order_by(FileBackup.created_at.desc(), FileBackup.id)
        .limit(limit)
        .offset(offset)
    )
    return FileBackupList(items=[_backup(row) for row in rows])


@router.get("/file-backups/{backup_id}", response_model=FileBackupItem)
def get_file_backup(
    backup_id: UUID, db: Session = Depends(get_db), user=Depends(get_current_user)
):
    row = db.scalar(select(FileBackup).filter_by(id=str(backup_id), org_id=user.org_id))
    if row is None:
        raise HTTPException(404, "File backup not found")
    return _backup(row)


@router.post("/file-backups", status_code=202, response_model=FileBackupItem)
def run_file_backup(
    body: FileBackupBody,
    idempotency_key: Annotated[str | None, Header(pattern=r"^[!-~]{1,128}$")] = None,
    db: Session = Depends(get_db),
    user=Depends(get_operator_or_admin),
):
    try:
        return _backup(
            admit_manual(
                db,
                user,
                str(body.target.agent_id),
                body.target.file_set,
                idempotency_key,
            )
        )
    except AdmissionRefused as exc:
        raise _refusal(exc) from exc


def _next_run(expression):
    try:
        return calculate_next_run(expression).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _schedule_query(org_id):
    latest = aliased(FileBackup)
    final = aliased(FileBackup)
    last_id = (
        select(latest.id)
        .where(latest.schedule_id == FileSchedule.id, latest.org_id == org_id)
        .order_by(latest.scheduled_at.desc())
        .limit(1)
        .correlate(FileSchedule)
        .scalar_subquery()
    )
    last_success = (
        select(func.max(final.completed_at))
        .where(
            final.schedule_id == FileSchedule.id,
            final.org_id == org_id,
            final.status == "completed",
        )
        .correlate(FileSchedule)
        .scalar_subquery()
    )
    return (
        select(
            FileSchedule,
            Organization.scheduler_epoch,
            FileBackup.status,
            FileBackup.error,
            last_success,
        )
        .join(Organization, Organization.id == FileSchedule.org_id)
        .outerjoin(FileBackup, FileBackup.id == last_id)
        .where(FileSchedule.org_id == org_id, FileSchedule.retired_at.is_(None))
    )


def _schedule(row, epoch, last_status=None, last_error=None, last_success_at=None):
    state = "inactive"
    if row.enabled:
        state = "active" if row.org_epoch == epoch else "fenced"
    return FileScheduleItem(
        id=row.id,
        name=row.name,
        target=_target(row.agent_id, row.file_set),
        cron_expression=row.cron_expression,
        enabled=row.enabled,
        authority_state=state,
        storage=FileStorage(**storage_binding(row)),
        created_at=row.created_at,
        last_run_at=row.last_run_at,
        next_run_at=row.next_run_at if state == "active" else None,
        last_success_at=last_success_at,
        last_status=last_status,
        last_error=last_error,
    )


@router.get("/file-schedules", response_model=FileScheduleList)
def list_file_schedules(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.execute(
        _schedule_query(user.org_id).order_by(
            FileSchedule.created_at.desc(), FileSchedule.id
        )
    )
    return FileScheduleList(items=[_schedule(*row) for row in rows])


@router.post("/file-schedules", status_code=201, response_model=FileScheduleItem)
def create_file_schedule(
    body: FileScheduleBody,
    db: Session = Depends(get_db),
    user=Depends(get_admin_user),
):
    next_run = _next_run(body.cron_expression)
    try:
        org, actor = locked_actor(db, user, admin=True)
        agent_id, file_set = str(body.target.agent_id), body.target.file_set
        policy = require_target(db, org.id, agent_id, file_set)
    except AdmissionRefused as exc:
        raise _refusal(exc) from exc
    row = FileSchedule(
        org_id=org.id,
        agent_id=agent_id,
        file_set=file_set,
        name=body.name,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
        authorized_by=actor.id,
        grant_id=str(uuid4()),
        org_epoch=org.scheduler_epoch,
        created_at=clock(),
        next_run_at=next_run if body.enabled else None,
    )
    bind_storage(row, policy)
    db.add(row)
    db.flush()
    log_activity(
        db, actor, "file_schedule_created", "file_schedule", row.id, commit=False
    )
    result = _schedule(row, org.scheduler_epoch)
    db.commit()
    return result


def _schedule_lock(db, org_id, schedule_id):
    schedule = db.scalar(
        select(FileSchedule)
        .filter_by(id=str(schedule_id), org_id=org_id, retired_at=None)
        .with_for_update()
    )
    if schedule is None:
        raise HTTPException(404, "File schedule not found")
    return schedule


@router.patch("/file-schedules/{schedule_id}", response_model=FileScheduleItem)
def update_file_schedule(
    schedule_id: UUID,
    body: FileScheduleUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_admin_user),
):
    try:
        org, actor = locked_actor(db, user, admin=True)
        row = _schedule_lock(db, org.id, schedule_id)
        if body.enabled is True:
            policy = require_target(db, org.id, row.agent_id, row.file_set)
            bind_storage(row, policy)
            row.authorized_by, row.org_epoch = actor.id, org.scheduler_epoch
            row.grant_id = str(uuid4())
        # Re-evaluate UTC only on activation or a cron edit. Renaming an enabled
        # schedule does not skip an already-due occurrence.
        if body.cron_expression is not None:
            next_run = _next_run(body.cron_expression)
            row.cron_expression = body.cron_expression
        elif body.enabled is True:
            next_run = _next_run(row.cron_expression)
        if body.enabled is not None:
            row.enabled = body.enabled
        if body.name is not None:
            row.name = body.name
        if not row.enabled:
            row.next_run_at = None
        elif body.enabled is True or body.cron_expression is not None:
            row.next_run_at = next_run
    except AdmissionRefused as exc:
        raise _refusal(exc) from exc
    log_activity(
        db, actor, "file_schedule_updated", "file_schedule", row.id, commit=False
    )
    result = _schedule(
        *db.execute(_schedule_query(org.id).where(FileSchedule.id == row.id)).one()
    )
    db.commit()
    return result


@router.delete("/file-schedules/{schedule_id}", status_code=204)
def retire_file_schedule(
    schedule_id: UUID, db: Session = Depends(get_db), user=Depends(get_admin_user)
):
    try:
        org, actor = locked_actor(db, user, admin=True)
        row = _schedule_lock(db, org.id, schedule_id)
    except AdmissionRefused as exc:
        raise _refusal(exc) from exc
    row.enabled = False
    row.next_run_at = None
    row.retired_at = clock()
    log_activity(
        db, actor, "file_schedule_retired", "file_schedule", row.id, commit=False
    )
    db.commit()
    return Response(status_code=204)
