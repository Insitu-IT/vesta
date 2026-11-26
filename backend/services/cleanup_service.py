"""
Cleanup service for stale operations and old records
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from typing import Dict

from models import Backup, Restore, Agent, ActivityLog

logger = logging.getLogger(__name__)


class CleanupService:
    """Service for cleaning up stale records and maintaining data hygiene"""

    def __init__(self):
        self.stale_backup_timeout = timedelta(hours=2)
        self.stale_restore_timeout = timedelta(hours=1)
        self.offline_agent_timeout = timedelta(minutes=10)
        self.activity_log_retention = timedelta(days=90)

    async def cleanup_stale_operations(self, db: Session) -> Dict:
        """Clean up operations stuck in running state"""
        stats = {"backups_failed": 0, "restores_failed": 0, "agents_marked_offline": 0}

        try:
            # Observe old operations without changing producer or destination custody
            stale_time = datetime.utcnow() - self.stale_backup_timeout
            stale_backups = (
                db.query(Backup)
                .filter(
                    Backup.status.in_(["running", "pending", "uploading"]),
                    Backup.created_at < stale_time,
                )
                .all()
            )

            for backup in stale_backups:
                # Creation age cannot distinguish healthy long work from a
                # stalled producer. Agent-owned persisted progress budgets and
                # exact reconciliation determine status; this sweep has no
                # authority to fail, retry, clean up or release either operation.
                logger.warning(
                    "Long-running backup requires progress observation: %s", backup.id
                )

            # A partial or running destination cannot be failed by creation age
            stale_time = datetime.utcnow() - self.stale_restore_timeout
            stale_restores = (
                db.query(Restore)
                .filter(
                    Restore.status.in_(["running", "pending"]),
                    Restore.created_at < stale_time,
                )
                .all()
            )

            for restore in stale_restores:
                logger.warning(
                    "Long-running restore requires progress observation: %s", restore.id
                )

            # Mark agents as offline if no heartbeat
            offline_time = datetime.utcnow() - self.offline_agent_timeout
            offline_agents = (
                db.query(Agent)
                .filter(Agent.status == "online", Agent.last_heartbeat < offline_time)
                .all()
            )

            for agent in offline_agents:
                agent.status = "offline"
                stats["agents_marked_offline"] += 1
                logger.info(f"Marked agent {agent.hostname} as offline (no heartbeat)")

            db.commit()

        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
            db.rollback()
            raise

        return stats

    async def cleanup_old_logs(self, db: Session) -> int:
        """Remove old activity logs"""
        try:
            cutoff_date = datetime.utcnow() - self.activity_log_retention

            # Delete in batches to avoid locking
            batch_size = 1000
            deleted_total = 0

            while True:
                deleted = (
                    db.query(ActivityLog)
                    .filter(ActivityLog.created_at < cutoff_date)
                    .limit(batch_size)
                    .delete(synchronize_session=False)
                )

                if deleted == 0:
                    break

                deleted_total += deleted
                db.commit()
                logger.info(f"Deleted batch of {deleted} old activity logs")

            if deleted_total > 0:
                logger.info(f"Deleted total of {deleted_total} old activity logs")

            return deleted_total

        except Exception as e:
            logger.error(f"Error cleaning old logs: {e}", exc_info=True)
            db.rollback()
            raise

    def schedule_cleanup_jobs(self, scheduler):
        """Schedule periodic cleanup jobs"""
        from database import get_db

        @scheduler.scheduled_job("interval", hours=1, id="cleanup_stale_ops")
        async def cleanup_stale():
            with get_db() as db:
                await self.cleanup_stale_operations(db)

        @scheduler.scheduled_job("cron", hour=2, minute=0, id="cleanup_old_logs")
        async def cleanup_logs():
            with get_db() as db:
                await self.cleanup_old_logs(db)

        logger.info("Cleanup jobs scheduled")
