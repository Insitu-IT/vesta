"""Timer-to-transaction wiring for organization-owned backup schedules."""

from datetime import datetime, timedelta, timezone
import logging

from croniter import croniter

from core.scheduler_transactions import OccurrenceKey, create_occurrence
from core.scheduler_scope import ScopeRefused
from core.tenant_context import TenantContext
from models import (
    BackupQueue,
    Schedule,
    ScheduleOccurrence,
    SchedulerGrant,
    Organization,
    VM,
)

logger = logging.getLogger(__name__)


def occurrence_key(db, schedule, scheduled_at):
    from core.backup_authority import schedule_authority_state

    grant = (
        db.get(SchedulerGrant, schedule.current_grant_id)
        if schedule.current_grant_id
        else None
    )
    org = db.get(Organization, schedule.org_id)
    if org is None or schedule_authority_state(schedule, grant, org) != "active":
        raise ScopeRefused("active_scheduler_grant_required")
    return OccurrenceKey(
        org.id,
        schedule.id,
        schedule.authority_revision,
        scheduled_at,
        grant.id,
        grant.scope_sha256,
        grant.org_epoch,
    )


def create_due_occurrence(factory, schedule_id, org_id, *, now=None):
    """Create the latest due minute once; no unbounded missed-run catch-up."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("An aware UTC clock is required")
    now = now.astimezone(timezone.utc)
    with TenantContext(org_id):
        with factory() as db:
            schedule = db.query(Schedule).filter_by(id=schedule_id).one_or_none()
            if (
                schedule is None
                or not schedule.enabled
                or schedule.retired_at is not None
            ):
                return None
            if schedule.next_run_at is not None:
                due = (
                    schedule.next_run_at.replace(tzinfo=timezone.utc)
                    if schedule.next_run_at.tzinfo is None
                    else schedule.next_run_at
                )
                if due > now:
                    return None
            instant = croniter(
                schedule.cron_expression, now + timedelta(microseconds=1)
            ).get_prev(datetime)
            # A late callback must not manufacture an arbitrarily old occurrence.
            if now - instant > timedelta(minutes=5):
                raise ScopeRefused("scheduled_window_missed")
            key = occurrence_key(db, schedule, instant)
        custody = create_occurrence(factory, key)
        with factory() as db:
            schedule = db.get(Schedule, schedule_id)
            if schedule is not None and schedule.authority_revision == key.revision:
                schedule.last_run_at = instant.replace(tzinfo=None)
                schedule.next_run_at = (
                    croniter(schedule.cron_expression, now)
                    .get_next(datetime)
                    .replace(tzinfo=None)
                )
                db.commit()
        return custody


def fail_no_effect_claim(factory, org_id, queue_id):
    """Fail only a claimed schedule that never acquired producer custody.

    A lost send or a committed publication remains held. The database's
    capacity trigger independently attests that the release has no effect.
    """
    from core.backup_capacity import release_never_effect
    from models import Backup, S3Publication, StorageLineageGeneration

    with TenantContext(org_id):
        with factory() as db:
            queue = db.get(BackupQueue, queue_id)
            backup_id = queue.started_backup_id if queue else None
            db.rollback()
        if not backup_id:
            return False

        def terminal(db):
            queue = db.get(BackupQueue, queue_id, populate_existing=True)
            backup = db.get(Backup, backup_id, populate_existing=True)
            if (
                queue is None
                or backup is None
                or backup.org_id != org_id
                or queue.authority_kind != "scheduler"
                or queue.status != "claimed"
                or not queue.claim_id
                or queue.started_backup_id != backup_id
                or queue.scheduler_occurrence_id != backup.scheduler_occurrence_id
                or backup.authority_kind != "scheduler"
                or backup.status != "pending"
                or backup.capacity_state != "released"
                or not backup.capacity_release
                or backup.capacity_release.get("reason") != "never_effect_admitted"
                or db.query(S3Publication.id).filter_by(backup_id=backup_id).first()
                or db.query(StorageLineageGeneration.id)
                .filter_by(backup_id=backup_id)
                .first()
            ):
                raise RuntimeError("Scheduled attempt retains producer custody")
            # Queue options/tags are immutable claim identity; only lifecycle
            # status changes. The database trigger checks that identity again.
            backup.status = "failed"

        result = release_never_effect(factory, backup_id, before_commit=terminal)
        return result["disposition"] == "committed_custody"


def _scheduler_work_ids(factory):
    from core.tenant_work import organization_work_ids

    return organization_work_ids(factory)


def _queued_schedule_rows(factory, limit):
    """Read scalar queue attribution in the copied tenant scope, off-loop."""
    with factory() as db:
        rows = (
            db.query(
                BackupQueue.id,
                ScheduleOccurrence.schedule_id,
                ScheduleOccurrence.schedule_revision,
                ScheduleOccurrence.scheduled_at,
                ScheduleOccurrence.grant_id,
                SchedulerGrant.scope_sha256,
                SchedulerGrant.org_epoch,
                VM.provider,
            )
            .join(VM, VM.id == BackupQueue.vm_id)
            .join(
                ScheduleOccurrence,
                ScheduleOccurrence.id == BackupQueue.scheduler_occurrence_id,
            )
            .join(SchedulerGrant, SchedulerGrant.id == ScheduleOccurrence.grant_id)
            .filter(
                BackupQueue.authority_kind == "scheduler",
                BackupQueue.status == "queued",
            )
            .order_by(BackupQueue.queued_at, BackupQueue.id)
            .limit(limit)
            .all()
        )
        return tuple(tuple(row) for row in rows)


async def dispatch_queued_schedules(factory, send, *, send_native=None, limit=10):
    """Dispatch only unclaimed original queues; claims survive every lost reply."""
    from core.storage_dispatch import ConnectedKubevirtDispatch
    from core.native_dispatch import ConnectedNativeDispatch
    from core.task_lifetime import run_owned_worker

    attempted = 0
    for org_id in await run_owned_worker(_scheduler_work_ids, factory):
        if attempted >= limit:
            break
        with TenantContext(org_id):
            rows = await run_owned_worker(
                _queued_schedule_rows, factory, limit - attempted
            )
            for (
                queue_id,
                schedule_id,
                revision,
                instant,
                grant_id,
                scope_hash,
                epoch,
                provider,
            ) in rows:
                key = OccurrenceKey(
                    org_id, schedule_id, revision, instant, grant_id, scope_hash, epoch
                )
                if provider == "libvirt" and send_native is not None:
                    dispatch = ConnectedNativeDispatch(factory, send_native)
                elif provider == "kubevirt":
                    dispatch = ConnectedKubevirtDispatch(factory, send)
                else:
                    logger.warning(
                        "Scheduled provider unavailable for queue %s", queue_id
                    )
                    attempted += 1
                    continue
                try:
                    await dispatch.dispatch(key, queue_id)
                except Exception as exc:
                    from core.scheduler_scope import ScopeRefused

                    if isinstance(exc, ScopeRefused) and str(exc) in {
                        "backup_admission_paused",
                        "backup_admission_policy_unavailable",
                    }:
                        logger.debug(
                            "Scheduled admission deferred for queue %s: %s",
                            queue_id,
                            str(exc),
                        )
                    else:
                        # A claim with no publication was never sent. Close only
                        # that exact no-effect case; any uncertain send stays held.
                        try:
                            failed_no_effect = await run_owned_worker(
                                fail_no_effect_claim, factory, org_id, queue_id
                            )
                        except Exception as close_exc:
                            logger.warning(
                                "Scheduled no-effect closeout refused for queue %s: %s",
                                queue_id,
                                type(close_exc).__name__,
                            )
                            failed_no_effect = False
                        logger.warning(
                            "Scheduled dispatch %s for queue %s: %s",
                            (
                                "failed before producer custody"
                                if failed_no_effect
                                else "retained"
                            ),
                            queue_id,
                            type(exc).__name__,
                        )
                finally:
                    await dispatch.close()
                attempted += 1
    return attempted
