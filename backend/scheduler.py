"""
Scheduler module for backup schedule management.

Contains functions for:
- Calculating next run time from cron expressions
- Managing APScheduler jobs
- Executing scheduled backups
"""

from datetime import datetime, timezone
from typing import Optional
import logging
import re
from config import settings
from core.tenant_context import TenantContext, PlatformContext, identity
from core.task_lifetime import SchedulerWork

from apscheduler.schedulers.background import BackgroundScheduler
from croniter import croniter

logger = logging.getLogger(__name__)

# Application startup owns this singleton's clock, after database validation.
scheduler = BackgroundScheduler()
scheduler_work = SchedulerWork()

USE_REAL_BACKUP_EXECUTOR = settings.use_real_backup_executor


def calculate_next_run(cron_expression: str) -> datetime:
    """Calculate next run time from cron expression"""
    try:
        if len(cron_expression.split()) != 5 or any(
            re.fullmatch(r"[0-9*,/-]+", field) is None
            for field in cron_expression.split()
        ):
            raise ValueError("Use five numeric cron fields in UTC")
        cron = croniter(cron_expression, datetime.utcnow())
        return cron.get_next(datetime)
    except Exception as e:
        raise ValueError(f"Invalid cron expression: {e}")


def _log_system_event(
    db,
    event_type: str,
    source: str,
    source_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
):
    """Log a system event (scheduler, agent, etc.)"""
    from models import SystemEvent

    event = SystemEvent(
        event_type=event_type,
        source=source,
        source_id=source_id,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
    )
    db.add(event)
    db.commit()


async def _run_backup_async(backup_id: str, use_real_executor: bool):
    """Application-loop work; never share its transport with temporary loops."""
    if use_real_executor:
        from core.backup_executor import backup_executor

        await backup_executor.execute_backup_and_wait(backup_id)
    else:
        from app import simulate_backup_execution

        await simulate_backup_execution(backup_id)


def execute_scheduled_backup(
    schedule_id: str,
    org_id: Optional[str] = None,
    initiating_user_id: Optional[str] = None,
):
    """Execute a scheduled backup job.

    Cluster-singleton (#47). The backend runs replicas: 2 and every pod schedules
    this job, so without the guard each fire creates one backup per VM PER POD.
    Nothing downstream de-duplicates: the loop below creates a backup per VM with
    no check that another instance is mid-run, and `last_run_at` is written only
    after the backups already exist.

    This has never fired in production — the `schedules` table has been empty since
    inception — so it is latent until the first schedule is created, which is
    exactly the change that restores native-host DR coverage on a protected estate.
    Doubling there means up to 23 VMs backed up twice against a single hypervisor
    that is the estate's SPOF.

    Keyed per schedule id, not per job class: two different schedules may legitimately
    run at the same instant, and only the same schedule running twice is the defect.
    """
    from database import SessionLocal
    from models import Schedule, VM, VMGroup
    from core.backup_service import BackupService
    from core.singleton import cluster_singleton

    if initiating_user_id is None:
        from core.scheduler_runtime import create_due_occurrence

        with scheduler_work.callback():
            try:
                return create_due_occurrence(SessionLocal, schedule_id, org_id)
            except Exception as exc:
                logger.warning(
                    "Schedule %s did not create an occurrence: %s",
                    schedule_id,
                    str(exc),
                )
                return None

    with scheduler_work.callback(), TenantContext(
        org_id, initiating_user_id
    ), cluster_singleton(f"scheduled_backup:{schedule_id}") as acquired:
        if not acquired:
            logger.info(
                f"Schedule {schedule_id} already executing on another instance; skipping"
            )
            return
        _execute_scheduled_backup_locked(
            schedule_id, SessionLocal, Schedule, VM, VMGroup, BackupService
        )


def _admit_manual_schedule_actor(db):
    """Re-admit an explicit manual requester; never invent a timer creator.

    Shared row locks fence authority reduction through this admission transaction.
    BackupService/queue persist this context's actor; D02 re-admits it at dispatch.
    """
    from models import Organization, User

    org_id, actor_id, _ = identity()
    if actor_id is None:
        raise PermissionError("Automatic scheduler authority is dormant")
    organization = (
        db.query(Organization)
        .filter(Organization.id == org_id)
        .populate_existing()
        .with_for_update(read=True)
        .first()
    )
    actor = (
        db.query(User)
        .filter(User.id == actor_id, User.org_id == org_id)
        .populate_existing()
        .with_for_update(read=True)
        .first()
    )
    if (
        organization is None
        or not organization.enabled
        or actor is None
        or not actor.is_active
        or actor.role not in ("admin", "operator")
    ):
        raise PermissionError("Manual schedule authority refused")


def _execute_scheduled_backup_locked(
    schedule_id: str, SessionLocal, Schedule, VM, VMGroup, BackupService
):
    """Body of execute_scheduled_backup, run only by the instance holding the lock."""
    db = SessionLocal()
    try:
        _admit_manual_schedule_actor(db)
        # Get the schedule
        schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not schedule or not schedule.enabled:
            return

        # Determine target VMs
        target_vms = []
        if schedule.vm_id:
            vm = db.query(VM).filter(VM.id == schedule.vm_id).first()
            if vm:
                target_vms = [vm]
        elif schedule.vm_group_id:
            group = db.query(VMGroup).filter(VMGroup.id == schedule.vm_group_id).first()
            if group:
                if group.group_type == "static":
                    target_vms = list(group.vms)
                else:
                    from core.group_rules import resolve_group_members

                    target_vms = resolve_group_members(db, group)

        # Use centralized BackupService
        service = BackupService(db)

        # Create backup for each target VM
        for vm in target_vms:
            _admit_manual_schedule_actor(db)
            result = service.create_backup(
                vm_id=vm.id,
                retention_days=schedule.retention_days,
                backup_type=schedule.backup_type or "full",
                tags=schedule.tags,
                exclude_disks=schedule.exclude_disks,
                workers=schedule.workers,
                schedule_id=schedule_id,
                schedule_name=schedule.name,
                check_maintenance=True,
                check_concurrent=True,
            )

            if not result.success:
                if result.error_code == 429:
                    # At capacity — queue for later
                    from core.backup_queue_processor import add_to_queue

                    add_to_queue(
                        db,
                        vm_id=vm.id,
                        retention_days=schedule.retention_days or 30,
                        backup_type=schedule.backup_type or "full",
                        tags=schedule.tags,
                        exclude_disks=schedule.exclude_disks,
                        workers=schedule.workers,
                        schedule_id=schedule_id,
                    )
                    logger.info(f"Queued scheduled backup for {vm.name} (at capacity)")
                    continue

                # Log skipped/failed backup as system event
                _log_system_event(
                    db,
                    event_type="scheduled_backup_skipped",
                    source="scheduler",
                    source_id=schedule_id,
                    resource_type="vm",
                    resource_id=vm.id,
                    details={
                        "schedule_name": schedule.name,
                        "vm_name": vm.name,
                        "reason": result.error,
                    },
                )
                logger.warning(
                    f"Scheduled backup skipped for {vm.name}: {result.error}"
                )
                continue

            backup = result.backup

            # Prometheus: count scheduled backup
            from core import metrics as prom

            prom.scheduled_backups_total.labels(schedule_id=schedule_id).inc()

            scheduler_work.submit(
                _run_backup_async, backup.id, USE_REAL_BACKUP_EXECUTOR
            )
            logger.info(f"Triggered scheduled backup {backup.id} for VM {vm.name}")

        # Update schedule's last_run and next_run
        schedule.last_run_at = datetime.utcnow()
        schedule.next_run_at = calculate_next_run(schedule.cron_expression)
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"Error executing scheduled backup: {e}")
    finally:
        db.close()


def add_schedule_to_scheduler(
    schedule_id: str, cron_expression: str, org_id: Optional[str] = None
):
    """Add a schedule to the APScheduler"""
    try:
        if org_id is None:
            org_id, _, platform = identity()
            if platform:
                raise ValueError("Platform scheduling requires explicit organization")
        # Validate before replacing an existing scheduled job.
        with TenantContext(org_id):
            identity()
        # Remove existing job if present
        if scheduler.get_job(schedule_id):
            scheduler.remove_job(schedule_id)

        # Add new job
        calculate_next_run(cron_expression)
        # Persisted croniter/SQL semantics are Sunday=0 and day-of-month OR
        # day-of-week. APScheduler's cron has different weekday/AND semantics;
        # use a minute wake-up and let the durable occurrence select its UTC slot.
        scheduler.add_job(
            execute_scheduled_backup,
            "interval",
            minutes=1,
            next_run_time=datetime.now(timezone.utc),
            args=[schedule_id, org_id],
            id=schedule_id,
            replace_existing=True,
        )
    except Exception as e:
        logger.error(f"Error adding schedule to scheduler: {e}")
        raise


def remove_schedule_from_scheduler(schedule_id: str):
    """Remove a schedule from the APScheduler"""
    try:
        if scheduler.get_job(schedule_id):
            scheduler.remove_job(schedule_id)
    except Exception as e:
        logger.error(f"Error removing schedule from scheduler: {e}")


async def load_schedules():
    """Load all enabled schedules on startup"""
    from database import SessionLocal
    from models import Schedule

    # The trusted startup enumerates identifiers only. All mutable schedule work
    # uses a new tenant session, including commits and future thread invocations.
    with PlatformContext(), SessionLocal() as lookup:
        schedules = (
            lookup.query(Schedule.id, Schedule.org_id)
            .filter(
                Schedule.enabled.is_(True),
                Schedule.retired_at.is_(None),
                Schedule.current_grant_id.isnot(None),
            )
            .all()
        )
    for schedule_id, org_id in schedules:
        with TenantContext(org_id), SessionLocal() as db:
            try:
                schedule = db.get(Schedule, schedule_id)
                if schedule is None or not schedule.enabled:
                    continue
                # Calculate next run if not set
                if not schedule.next_run_at:
                    schedule.next_run_at = calculate_next_run(schedule.cron_expression)
                    db.commit()

                # Add to scheduler
                add_schedule_to_scheduler(schedule.id, schedule.cron_expression, org_id)
                logger.info(
                    f"Loaded schedule: {schedule.name} ({schedule.cron_expression})"
                )
            except Exception as e:
                logger.error(f"Error loading schedule {schedule_id}: {e}")
