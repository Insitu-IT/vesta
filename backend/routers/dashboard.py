"""
Dashboard analytics endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from datetime import datetime, timedelta, timezone

from database import get_db
from models import Backup, BackupQueue, FileSchedule, Organization, VM, Agent, Schedule
from deps import get_current_user, iso_utc

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


@router.get("/dashboard/summary")
async def get_dashboard_summary(
    current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get dashboard summary statistics"""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    # Explicit tenant predicates also protect aggregate-only SQL queries.
    org_id = current_user.org_id
    vms = db.query(VM).filter(VM.org_id == org_id, VM.inventory_present.is_(True))
    agents = db.query(Agent).filter(Agent.org_id == org_id)
    backups = db.query(Backup).filter(Backup.org_id == org_id)
    schedules = db.query(Schedule).filter(Schedule.org_id == org_id)
    file_schedules = (
        db.query(FileSchedule)
        .join(Organization, Organization.id == FileSchedule.org_id)
        .filter(
            FileSchedule.org_id == org_id,
            FileSchedule.enabled.is_(True),
            FileSchedule.retired_at.is_(None),
            FileSchedule.org_epoch == Organization.scheduler_epoch,
            Organization.enabled.is_(True),
        )
    )
    file_now = now.replace(tzinfo=timezone.utc)
    active_file_schedules = file_schedules.count()
    upcoming_file_schedules = file_schedules.filter(
        FileSchedule.next_run_at >= file_now,
        FileSchedule.next_run_at < file_now + timedelta(hours=24),
    ).count()
    by_state = dict(
        vms.with_entities(VM.state, func.count(VM.id)).group_by(VM.state).all()
    )
    total_vms = sum(by_state.values())
    normalized_states = {}
    for state, count in by_state.items():
        key = state or "unknown"
        normalized_states[key] = normalized_states.get(key, 0) + count
    by_agent = (
        db.query(Agent.id, Agent.hostname, Agent.display_name, func.count(VM.id))
        .outerjoin(
            VM,
            (VM.agent_id == Agent.id)
            & (VM.org_id == org_id)
            & VM.inventory_present.is_(True),
        )
        .filter(Agent.org_id == org_id)
        .group_by(Agent.id, Agent.hostname, Agent.display_name)
        .all()
    )
    period_backups = backups.filter(
        Backup.created_at >= last_24h, Backup.created_at <= now
    )
    raw_statuses = dict(
        period_backups.with_entities(Backup.status, func.count(Backup.id))
        .group_by(Backup.status)
        .all()
    )
    statuses = dict.fromkeys(
        ("completed", "running", "queued", "failed", "held", "other"), 0
    )
    for status, count in raw_statuses.items():
        bucket = {
            "pending": "queued",
            "uploading": "running",
            "upload_failed": "failed",
        }.get(status, status)
        statuses[bucket if bucket in statuses else "other"] += count
    queue = (
        db.query(BackupQueue)
        .join(VM, BackupQueue.vm_id == VM.id)
        .filter(VM.org_id == org_id)
    )
    unstarted = queue.filter(
        BackupQueue.started_backup_id.is_(None),
        BackupQueue.queued_at >= last_24h,
        BackupQueue.queued_at <= now,
    )
    for status, count in (
        unstarted.with_entities(BackupQueue.status, func.count(BackupQueue.id))
        .group_by(BackupQueue.status)
        .all()
    ):
        if status in ("held_unclaimed", "held_claimed"):
            statuses["held"] += count
        elif status in ("queued", "claimed", "processing"):
            statuses["queued"] += count
    held = queue.filter(
        BackupQueue.status.in_(["held_unclaimed", "held_claimed"])
    ).count()
    total_agents = agents.count()
    online_agents = agents.filter(Agent.status == "online").count()
    recent = backups.order_by(Backup.created_at.desc()).limit(5).all()
    running = (
        backups.filter(Backup.status.in_(["running", "uploading"]))
        .order_by(Backup.created_at.desc())
        .limit(20)
        .all()
    )

    def job_row(job):
        return {
            "id": job.id,
            "vm_id": job.vm_id,
            "vm_name": job.vm.name if job.vm else None,
            "status": job.status,
            "backup_type": job.backup_type,
            "size_bytes": job.size_bytes,
            "progress": job.progress,
            "created_at": iso_utc(job.created_at),
            "agent_name": (
                job.vm.agent.get_display_name() if job.vm and job.vm.agent else None
            ),
        }

    total_size = (
        backups.with_entities(func.sum(Backup.size_bytes))
        .filter(Backup.status == "completed")
        .scalar()
        or 0
    )
    completed = statuses["completed"]
    finished = completed + statuses["failed"]
    return {
        "vms": {
            "total": total_vms,
            "running": by_state.get("running", 0),
            "stopped": by_state.get("stopped", 0) + by_state.get("shutoff", 0),
            "by_status": normalized_states,
            "by_agent": [
                {"agent_id": row[0], "name": row[2] or row[1], "count": row[3]}
                for row in by_agent
            ],
        },
        "agents": {
            "total": total_agents,
            "online": online_agents,
            "offline": total_agents - online_agents,
        },
        "backups": {
            "total": backups.count(),
            "last_24h": sum(statuses.values()),
            "completed_24h": completed,
            "failed_24h": statuses["failed"],
            "success_rate_24h": (
                round(completed / finished * 100, 1) if finished else None
            ),
            "uploads_pending": backups.filter(
                Backup.status.in_(["uploading", "upload_failed"])
            ).count(),
            "by_status": statuses,
            "period_start": iso_utc(last_24h),
            "period_end": iso_utc(now),
            "running_count": backups.filter(
                Backup.status.in_(["running", "uploading"])
            ).count(),
        },
        "storage": {
            "total_bytes": total_size,
            "total_gb": round(total_size / (1024**3), 2),
        },
        "schedules": {
            "active": schedules.filter(Schedule.enabled.is_(True)).count()
            + active_file_schedules,
            "upcoming": schedules.filter(
                Schedule.enabled.is_(True),
                Schedule.next_run_at >= now,
                Schedule.next_run_at < now + timedelta(hours=24),
            ).count()
            + upcoming_file_schedules,
        },
        "attention": {
            "offline_agents": total_agents - online_agents,
            "failed_backups": statuses["failed"],
            "held_jobs": held,
            "held_backups": backups.filter(
                or_(Backup.status == "held", Backup.capacity_state == "legacy_held")
            ).count(),
        },
        "recent_backups": [job_row(job) for job in recent],
        "running_backups": [job_row(job) for job in running],
        "generated_at": iso_utc(now),
    }


@router.get("/dashboard/backup-trends")
async def get_backup_trends(
    days: int = 7, current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get backup trends over time"""
    now = datetime.utcnow()

    # Get daily backup counts
    daily_data = []
    for i in range(days):
        day_start = (now - timedelta(days=days - i - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        day_end = day_start + timedelta(days=1)

        completed = (
            db.query(Backup)
            .filter(Backup.org_id == current_user.org_id)
            .filter(
                Backup.created_at >= day_start,
                Backup.created_at < day_end,
                Backup.status == "completed",
            )
            .count()
        )

        failed = (
            db.query(Backup)
            .filter(Backup.org_id == current_user.org_id)
            .filter(
                Backup.created_at >= day_start,
                Backup.created_at < day_end,
                Backup.status == "failed",
            )
            .count()
        )

        daily_data.append(
            {
                "date": day_start.strftime("%Y-%m-%d"),
                "completed": completed,
                "failed": failed,
                "total": completed + failed,
            }
        )

    return {"period_days": days, "data": daily_data}


@router.get("/dashboard/storage-usage")
async def get_storage_usage(
    current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get storage usage breakdown by agent"""
    agents = db.query(Agent).filter(Agent.org_id == current_user.org_id).all()

    usage_by_agent = []
    for agent in agents:
        agent_size = (
            db.query(func.sum(Backup.size_bytes))
            .join(VM)
            .filter(
                VM.org_id == current_user.org_id,
                Backup.org_id == current_user.org_id,
                VM.agent_id == agent.id,
                Backup.status == "completed",
            )
            .scalar()
            or 0
        )

        backup_count = (
            db.query(Backup)
            .filter(Backup.org_id == current_user.org_id)
            .join(VM)
            .filter(
                VM.org_id == current_user.org_id,
                Backup.org_id == current_user.org_id,
                VM.agent_id == agent.id,
                Backup.status == "completed",
            )
            .count()
        )

        usage_by_agent.append(
            {
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "size_bytes": agent_size,
                "size_gb": round(agent_size / (1024**3), 2),
                "backup_count": backup_count,
            }
        )

    return {
        "by_agent": sorted(usage_by_agent, key=lambda x: x["size_bytes"], reverse=True)
    }
