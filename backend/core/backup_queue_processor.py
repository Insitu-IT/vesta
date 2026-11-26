"""
Backup Queue Processor

Polls the backup queue and starts backups when slots are available.
Runs as a background task that checks the queue periodically.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, select

from models import BackupQueue, Backup, S3Publication, VM
from core.settings_reader import get_max_concurrent_backups
from core.tenant_context import PlatformContext, TenantContext, identity
from core.tenant_work import organization_work_ids
from core.task_lifetime import run_owned_worker

logger = logging.getLogger(__name__)

# Queue processor configuration
QUEUE_POLL_INTERVAL = 5  # seconds
MAX_QUEUE_PROCESS_BATCH = 10  # Max items to process per poll
RECOVERY_DISCOVERY_INTERVAL = 60  # seconds, not every queue poll
RECOVERY_NEW_ATTEMPT_DELAY = 300  # Let a live dispatch/observer finish first.


def _effect_custody_backup_ids():
    """Attempts whose original producer must be reconciled, not redispatched.

    An existing queue ID and backup ID are not themselves send authority. Once
    native admission or a KubeVirt dispatch token is durable, re-entering the
    ordinary queue path would propose a second producer token every poll.
    """
    return select(Backup.id).where(
        or_(
            Backup.native_job_transaction_id.is_not(None),
            Backup.id.in_(
                select(S3Publication.backup_id).where(
                    S3Publication.dispatch_token.is_not(None)
                )
            ),
        )
    )


class BackupQueueProcessor:
    """
    Processes the backup queue, starting backups when slots are available.
    """

    def __init__(
        self, db_session_factory, backup_executor, use_real_executor: bool = True
    ):
        """
        Initialize the queue processor.

        Args:
            db_session_factory: Factory function to create database sessions
            backup_executor: Backup executor instance for running backups
            use_real_executor: Whether to use real or mock backup executor
        """
        self.db_session_factory = db_session_factory
        self.backup_executor = backup_executor
        self.use_real_executor = use_real_executor
        self._running = False
        self._task = None
        self._children = set()
        self._stopping = False
        self._recovery_due = {}
        self._recovery_outcome = {}
        self._recovery_refresh_due = 0

    async def start(self):
        """Start the queue processor background task.

        On startup, resets any items stuck in "processing" state back to "queued".
        This handles recovery from crashes where items were marked processing but
        never completed.
        """
        if self._running:
            logger.warning("Queue processor already running")
            return

        self._stopping = False

        # Recover from crash: reset stuck "processing" items
        await self._recover_stuck_items()

        # Restarted custody can be reconciled immediately. Later lost sends
        # must also be discovered, without another backend restart or producer.
        if self.use_real_executor:
            await self._refresh_recovery_candidates(time.monotonic(), initial=True)

        self._running = True
        self._task = asyncio.create_task(self._process_loop())
        logger.info("Backup queue processor started")

    async def _recover_stuck_items(self):
        for org_id in await run_owned_worker(self._organization_work_ids):
            with TenantContext(org_id):
                await run_owned_worker(self._recover_tenant_items)

    def _recover_tenant_items(self):
        """Recover interrupted delivery without allocating another backup.

        Called on startup to recover from crashes where the processor was
        interrupted after marking items as processing but before completing them.
        """
        db = self.db_session_factory()
        try:
            stuck_count = (
                db.query(BackupQueue)
                .filter(
                    BackupQueue.authority_kind == "human",
                    or_(
                        BackupQueue.started_backup_id.is_(None),
                        ~BackupQueue.started_backup_id.in_(
                            _effect_custody_backup_ids()
                        ),
                    ),
                    or_(
                        BackupQueue.status == "processing",
                        and_(
                            BackupQueue.status == "started",
                            BackupQueue.started_backup_id.in_(
                                select(Backup.id).where(
                                    Backup.status.in_(["pending", "running"])
                                )
                            ),
                        ),
                    ),
                )
                .update({"status": "queued", "started_at": None})
            )

            if stuck_count > 0:
                db.commit()
                logger.warning(
                    f"Recovered {stuck_count} stuck queue items (processing → queued)"
                )
        except Exception as e:
            logger.error(f"Failed to recover stuck queue items: {e}")
            db.rollback()
        finally:
            db.close()

    async def stop(self):
        """Stop the queue processor"""
        self._running = False
        self._stopping = True
        failure = None
        try:
            if self._task:
                self._task.cancel()
                await self._task
        except asyncio.CancelledError as error:
            # The poller's requested cancellation is expected; cancellation of
            # the shutdown caller must remain observable after its child drain.
            if asyncio.current_task().cancelling():
                failure = error
        except Exception as error:
            failure = error
        finally:
            children = tuple(self._children)
            for child in children:
                child.cancel()
            await asyncio.gather(*children, return_exceptions=True)
            self._children.difference_update(children)
            self._task = None
        if failure is not None:
            raise failure
        logger.info("Backup queue processor stopped")

    async def _process_loop(self):
        """Main processing loop — handles queued backups and upload retries"""
        while self._running:
            try:
                await self._process_queue()
                await self._process_recovery()
                await self._process_upload_retries()
            except Exception as e:
                logger.error(f"Error in queue processor: {e}")

            await asyncio.sleep(QUEUE_POLL_INTERVAL)

    def _list_recovery_candidates(self):
        organizations = self._organization_work_ids()
        if not organizations:
            return ()
        with PlatformContext(), self.db_session_factory() as db:
            rows = (
                db.query(Backup.id, Backup.org_id)
                .join(VM, VM.id == Backup.vm_id)
                .filter(
                    Backup.status.in_(("pending", "running")),
                    Backup.capacity_state == "reserved",
                    Backup.id.in_(_effect_custody_backup_ids()),
                    Backup.org_id.in_(organizations),
                    VM.provider.in_(("kubevirt", "libvirt")),
                )
                .order_by(Backup.created_at, Backup.id)
                .all()
            )
            return tuple((row[0], row[1]) for row in rows)

    async def _refresh_recovery_candidates(self, now, *, initial=False):
        if not initial and now < self._recovery_refresh_due:
            return
        # Bound failed discovery too; never hammer a failing DB each poll.
        self._recovery_refresh_due = now + RECOVERY_DISCOVERY_INTERVAL
        candidates = await run_owned_worker(self._list_recovery_candidates)
        delay = 0 if initial else RECOVERY_NEW_ATTEMPT_DELAY
        # Preserve existing backoff/outcomes across scans. A fresh candidate
        # still has to pass original authority, capacity and journal admission.
        self._recovery_due = {
            candidate: self._recovery_due.get(candidate, now + delay)
            for candidate in candidates
        }
        self._recovery_outcome = {
            candidate: outcome
            for candidate, outcome in self._recovery_outcome.items()
            if candidate in self._recovery_due
        }

    async def _process_recovery(self):
        if not self.use_real_executor or self._stopping:
            return
        from core.backup_recovery import recover_original_attempt

        now = time.monotonic()
        await self._refresh_recovery_candidates(now)
        for candidate, due in tuple(self._recovery_due.items()):
            if due > now:
                continue
            backup_id, org_id = candidate
            try:
                result = await recover_original_attempt(
                    self.db_session_factory,
                    self.backup_executor,
                    backup_id,
                    org_id,
                    previous_outcome=self._recovery_outcome.get(candidate),
                )
            except Exception as error:
                # A DB/audit/transport failure must never become a second
                # producer. Keep the exact attempt eligible for a later retry.
                logger.warning(
                    "Backup %s recovery unavailable: %s",
                    backup_id,
                    type(error).__name__,
                )
                self._recovery_due[candidate] = time.monotonic() + 300
                return
            if result["status"] == "inactive":
                del self._recovery_due[candidate]
                self._recovery_outcome.pop(candidate, None)
            else:
                self._recovery_outcome[candidate] = (
                    result["status"],
                    result.get("reason"),
                )
                # The agent may later hold a resumable journal; a repeated
                # request is journal-deduplicated and never changes custody.
                self._recovery_due[candidate] = time.monotonic() + (
                    900 if result["status"] == "accepted" else 300
                )
            return  # One bounded agent admission per installation poll.

    async def _process_queue(self):
        """Retain the installation-wide capacity bound across tenant fan-out."""
        if self.use_real_executor:
            from core.scheduler_runtime import dispatch_queued_schedules

            await dispatch_queued_schedules(
                self.db_session_factory,
                self.backup_executor.send_storage_transaction,
                send_native=self.backup_executor.send_native_job,
                limit=MAX_QUEUE_PROCESS_BATCH,
            )
        remaining_batch = MAX_QUEUE_PROCESS_BATCH
        organizations = await run_owned_worker(self._organization_work_ids)
        candidates = await run_owned_worker(self._read_candidates, organizations)
        for queue_id, org_id, started_backup_id in candidates:
            slots = await run_owned_worker(self._available_slots)
            if remaining_batch <= 0:
                return
            if slots <= 0 and started_backup_id is None:
                continue
            with TenantContext(org_id):
                remaining_batch -= await self._process_tenant_queue(
                    1 if started_backup_id else min(slots, remaining_batch), queue_id
                )

    def _organization_work_ids(self):
        return organization_work_ids(self.db_session_factory)

    def _read_candidates(self, organizations):
        # Only scalar identity and attribution cross the worker boundary.
        with PlatformContext(), self.db_session_factory() as db:
            rows = (
                db.query(BackupQueue.id, VM.org_id, BackupQueue.started_backup_id)
                .join(VM, VM.id == BackupQueue.vm_id)
                .filter(
                    BackupQueue.status == "queued",
                    BackupQueue.authority_kind == "human",
                    or_(
                        BackupQueue.started_backup_id.is_(None),
                        ~BackupQueue.started_backup_id.in_(
                            _effect_custody_backup_ids()
                        ),
                    ),
                    VM.org_id.in_(organizations),
                )
                .order_by(
                    BackupQueue.priority.desc(),
                    BackupQueue.queued_at.asc(),
                    BackupQueue.id,
                )
                .limit(MAX_QUEUE_PROCESS_BATCH)
                .all()
            )
            return tuple((row[0], row[1], row[2]) for row in rows)

    def _available_slots(self):
        with PlatformContext(), self.db_session_factory() as db:
            running = (
                db.query(Backup)
                .filter(Backup.status.in_(["running", "pending"]))
                .count()
            )
            return get_max_concurrent_backups(db) - running

    async def _process_tenant_queue(self, available_slots, queue_id):
        """Process only rows visible in the explicitly installed tenant."""
        attempted, backup_id = await run_owned_worker(
            self._poll_tenant_queue, available_slots, queue_id
        )
        if backup_id is not None:
            self._launch_backup(backup_id)
        return attempted

    def _poll_tenant_queue(self, available_slots, queue_id):
        if available_slots <= 0:
            return 0, None
        with self.db_session_factory() as db:
            # queue_id is unique; no ORM object escapes this worker thread.
            item = (
                db.query(BackupQueue)
                .filter(
                    BackupQueue.status == "queued",
                    BackupQueue.authority_kind == "human",
                    BackupQueue.id == queue_id,
                )
                .order_by(
                    BackupQueue.priority.desc(),
                    BackupQueue.queued_at.asc(),
                    BackupQueue.id.asc(),
                )
                .first()
            )
            if item is None:
                return 0, None
            existing = (
                db.query(Backup)
                .filter(
                    Backup.vm_id == item.vm_id,
                    Backup.status.in_(["running", "pending"]),
                )
                .first()
            )
            if existing and existing.id != item.started_backup_id:
                return 0, None
            return 1, self._start_backup_from_queue_sync(db, item)

    async def _process_upload_retries(self):
        for org_id in await run_owned_worker(self._organization_work_ids):
            with TenantContext(org_id):
                if await self._retry_tenant_upload():
                    return  # Preserve one upload retry per installation cycle.

    async def _retry_tenant_upload(self):
        """Inspect one delayed retry without treating backoff/status as custody."""
        from core.backup_executor import backup_executor

        work = await run_owned_worker(self._read_retry_candidate)
        if work is None:
            return False
        backup_id, org_id, actor_id = work
        await backup_executor.execute_upload(
            backup_id,
            org_id=org_id,
            initiating_user_id=actor_id,
            origin="automatic_retry",
        )
        return True

    def _read_retry_candidate(self):
        db = self.db_session_factory()
        try:
            backup = (
                db.query(Backup)
                .filter(
                    Backup.status == "upload_failed",
                    Backup.authority_kind == "human",
                )
                .order_by(Backup.created_at, Backup.id)
                .first()
            )
            if backup is not None:
                return backup.id, backup.org_id, backup.initiating_user_id
        except Exception:
            logger.warning("Upload retry inventory unavailable")
        finally:
            db.close()
        return None

    async def _start_backup_from_queue(self, db: Session, queue_item: BackupQueue):
        backup_id = await run_owned_worker(
            self._start_backup_from_queue_sync, db, queue_item
        )
        if backup_id is not None:
            self._launch_backup(backup_id)

    def _start_backup_from_queue_sync(self, db: Session, queue_item: BackupQueue):
        """
        Commit the original queue attempt on a worker before dispatch admission.
        """
        from core.backup_service import BackupService

        queue_id = queue_item.id
        if queue_item.authority_kind == "scheduler":
            return
        try:
            # Mark queue item as processing
            queue_item.status = "processing"
            queue_item.started_at = datetime.utcnow()
            db.commit()

            # Build tags: start from queue item tags, add queue metadata
            # (BackupService.create_backup adds schedule tags separately)
            tags = queue_item.tags.copy() if queue_item.tags else {}
            tags["from_queue"] = "true"
            tags["queue_id"] = queue_item.id

            # Use BackupService for chain resolution + storage_path
            service = BackupService(db)
            result = service.create_backup(
                vm_id=queue_item.vm_id,
                retention_days=queue_item.retention_days,
                backup_type=queue_item.backup_type,
                tags=tags,
                exclude_disks=queue_item.exclude_disks,
                workers=queue_item.workers,
                schedule_id=queue_item.schedule_id,
                check_concurrent=False,  # Already checked by _process_queue
                queue_item=queue_item,
            )

            if not result.success:
                logger.warning(
                    f"Queue item {queue_item.id} failed to create backup: {result.error}"
                )
                queue_item.status = "held" if result.error_code == 423 else "queued"
                queue_item.started_at = None
                db.commit()
                return

            backup = result.backup
            vm_name = service.get_vm_name(queue_item.vm_id) or "Unknown"

            # Commit durable restart attribution before the child can dispatch.
            queue_item.status = "started"
            db.commit()
            logger.info(f"Admitted backup {backup.id} for VM {vm_name} from queue")
            return backup.id

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to start backup from queue item {queue_id}: {e}")
            queue_item.status = "queued"
            queue_item.started_at = None
            db.commit()
            return None

    def _launch_backup(self, backup_id):
        if self._stopping:
            return
        if self.use_real_executor:
            child = asyncio.create_task(self._execute_backup_async(backup_id))
        else:
            child = asyncio.create_task(self._mock_backup_execution(backup_id))
        self._children.add(child)
        child.add_done_callback(self._children.discard)
        logger.info("Started backup %s from queue", backup_id)

    async def _execute_backup_async(self, backup_id: str):
        """Execute backup asynchronously"""
        try:
            if not await run_owned_worker(self._human_backup_exists, backup_id):
                return
            await self.backup_executor.execute_backup_and_wait(backup_id)
        except Exception as e:
            logger.error(f"Backup execution failed for {backup_id}: {e}")

    def _human_backup_exists(self, backup_id):
        with self.db_session_factory() as db:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            return backup is not None and backup.authority_kind != "scheduler"

    async def _mock_backup_execution(self, backup_id: str):
        """Mock backup execution for testing/development.

        Simulates backup progress updates and completes after a short delay.
        """
        import random

        db = self.db_session_factory()
        try:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if not backup:
                logger.warning(f"Mock backup not found: {backup_id}")
                return

            if backup.authority_kind == "scheduler":
                return

            # Simulate progress updates
            for progress in range(0, 101, 10):
                backup.progress = progress
                backup.status = "running"
                db.commit()
                await asyncio.sleep(0.2)  # Fast simulation

            # Complete the backup
            backup.status = "completed"
            backup.progress = 100
            backup.completed_at = datetime.utcnow()
            backup.size_bytes = random.randint(100_000_000, 10_000_000_000)
            db.commit()

            logger.info(f"Mock backup completed: {backup_id}")
        except Exception as e:
            logger.error(f"Mock backup failed for {backup_id}: {e}")
            try:
                backup = db.query(Backup).filter(Backup.id == backup_id).first()
                if backup:
                    backup.status = "failed"
                    backup.error_message = str(e)
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()

    def get_queue_status(self, db: Session) -> Dict[str, Any]:
        """
        Get current queue status.

        Returns:
            Dict with queue statistics
        """
        total_queued = (
            db.query(BackupQueue).filter(BackupQueue.status == "queued").count()
        )

        processing = (
            db.query(BackupQueue).filter(BackupQueue.status == "processing").count()
        )

        # Get queue with positions
        queued_items = (
            db.query(BackupQueue)
            .filter(BackupQueue.status == "queued")
            .order_by(
                BackupQueue.priority.desc(),
                BackupQueue.queued_at.asc(),
                BackupQueue.id.asc(),
            )
            .all()
        )

        # Calculate positions
        queue_list = []
        for idx, item in enumerate(queued_items):
            queue_list.append(
                {
                    "id": item.id,
                    "vm_id": item.vm_id,
                    "vm_name": item.vm.name if item.vm else "Unknown",
                    "priority": item.priority,
                    "position": idx + 1,
                    "queued_at": item.queued_at.isoformat() if item.queued_at else None,
                    "schedule_id": item.schedule_id,
                    "status": item.status,
                    "hold_reason": item.hold_reason
                    or ("queue_held" if item.status == "held" else None),
                    "started_backup_id": item.started_backup_id,
                }
            )

        return {
            "total_queued": total_queued,
            "processing": processing,
            "queue": queue_list,
        }


def add_to_queue(
    db: Session,
    vm_id: str,
    retention_days: int = 30,
    backup_type: str = "full",
    tags: Optional[Dict[str, Any]] = None,
    exclude_disks: Optional[List[str]] = None,
    workers: Optional[int] = None,
    priority: int = 0,
    created_by: Optional[str] = None,
    schedule_id: Optional[str] = None,
    is_bulk_operation: bool = False,
) -> BackupQueue:
    """Public manual entry point owns its commit."""
    item = _add_to_queue_flush(
        db,
        vm_id,
        retention_days,
        backup_type,
        tags,
        exclude_disks,
        workers,
        priority,
        created_by,
        schedule_id,
        is_bulk_operation,
    )
    db.commit()
    db.refresh(item)
    return item


def _add_to_queue_flush(
    db: Session,
    vm_id: str,
    retention_days: int = 30,
    backup_type: str = "full",
    tags: Optional[Dict[str, Any]] = None,
    exclude_disks: Optional[List[str]] = None,
    workers: Optional[int] = None,
    priority: int = 0,
    created_by: Optional[str] = None,
    schedule_id: Optional[str] = None,
    is_bulk_operation: bool = False,
) -> BackupQueue:
    """
    Add a backup request to the queue.

    Args:
        db: Database session
        vm_id: VM to backup
        retention_days: Days to retain backup
        backup_type: Type of backup
        tags: Tags for the backup
        exclude_disks: Disks to exclude
        workers: Number of workers
        priority: Queue priority (higher = more urgent)
        created_by: User ID who created the request
        schedule_id: Schedule ID if from schedule
        is_bulk_operation: Whether this is part of bulk operation

    Returns:
        Created BackupQueue item
    """
    queue_item = BackupQueue(
        authority_kind="human",
        vm_id=vm_id,
        initiating_user_id=identity()[1],
        priority=priority,
        retention_days=retention_days,
        backup_type=backup_type,
        tags=tags or {},
        exclude_disks=exclude_disks or [],
        workers=workers,
        status="queued",
        created_by=created_by,
        schedule_id=schedule_id,
        is_bulk_operation=is_bulk_operation,
    )

    db.add(queue_item)
    db.flush()

    return queue_item


def cancel_queue_item(db: Session, queue_id: str) -> bool:
    """
    Cancel a queued backup request.

    Args:
        db: Database session
        queue_id: ID of queue item to cancel

    Returns:
        True if cancelled, False if not found or already processing
    """
    item = db.query(BackupQueue).filter(BackupQueue.id == queue_id).first()

    if not item:
        return False

    if item.status != "queued":
        return False  # Can't cancel if already processing

    item.status = "cancelled"
    db.commit()

    return True


def get_queue_position(db: Session, queue_id: str) -> Optional[int]:
    """
    Get the position of an item in the queue.

    Args:
        db: Database session
        queue_id: ID of queue item

    Returns:
        Position in queue (1-indexed) or None if absent or no longer queued
    """
    item = db.query(BackupQueue).filter(BackupQueue.id == queue_id).first()

    if not item or item.status != "queued":
        return None

    # Match every queue reader: priority DESC, queued_at ASC, id ASC.
    position = (
        db.query(BackupQueue)
        .filter(
            BackupQueue.status == "queued",
            (
                (BackupQueue.priority > item.priority)
                | (
                    (BackupQueue.priority == item.priority)
                    & (
                        (BackupQueue.queued_at < item.queued_at)
                        | (
                            (BackupQueue.queued_at == item.queued_at)
                            & (BackupQueue.id < item.id)
                        )
                    )
                )
            ),
        )
        .count()
    )

    return position + 1
