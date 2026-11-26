"""
vnbui - KVM Backup Orchestration Platform

Main FastAPI application entry point.
Endpoints are organized into routers under the routers/ directory.
"""

from fastapi import FastAPI
import os
import asyncio
import logging
from builtins import BaseExceptionGroup

from models import Agent, VM
from config import settings
from version import OPERATOR_API_VERSION, __version__
from core import metrics

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import licensing
from core.licensing import features  # noqa: E402

# Distribution and authentication scope are installation configuration. License
# validation is advisory and cannot select modules or an organization namespace.
if settings.demo_mode and features.profile.edition != "community":
    raise ValueError("Demo mode requires a Community installed profile")
# Offline registration is evaluated through its local advisory service. Startup
# and loaded implementations never depend on legacy certificate readers.

# Configuration refuses simulated execution in a normal installation.
USE_REAL_BACKUP_EXECUTOR = settings.use_real_backup_executor

from core.product_identity import product_name  # noqa: E402

# Initialize FastAPI with the same safe public identity as the web UI.
app = FastAPI(
    title=f"{product_name()} API",
    description="KVM Backup Orchestration Platform",
    version=OPERATOR_API_VERSION,
    docs_url=None,
    redoc_url=None,
)

from api_docs import register_api_docs  # noqa: E402

register_api_docs(app)

from operator_contracts import install_operator_contracts  # noqa: E402
from core.settings_service import SettingsService  # noqa: E402
from deps import REQUIRE_MTLS  # noqa: E402

install_operator_contracts(
    app,
    SettingsService.DEFINITIONS,
    SettingsService.SECRET_DEFINITIONS,
    require_mtls=REQUIRE_MTLS,
)

# Setup middleware stack
from middleware import setup_middleware  # noqa: E402

setup_middleware(app)

# Tenant isolation middleware
from core.tenant_context import tenant_middleware  # noqa: E402

app.middleware("http")(tenant_middleware)

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://vnbui:vnbui_password@localhost:5432/vnbui"
)
from database import sync_engine as engine, SessionLocal  # noqa: E402

# ============================================================================
# SCHEDULER SETUP
# ============================================================================

from apscheduler.triggers.cron import CronTrigger  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402

# Single scheduler instance is owned by scheduler.py (#42). app.py previously ran a
# SECOND BackgroundScheduler here; the split — startup-load + the retention job on
# app.py's instance, but runtime create/update/delete on scheduler.py's via the
# schedules router — caused double-execution on edit and ghost-execution on
# delete-after-restart. Importing the one instance + its wiring makes startup-load,
# the retention job, and the router all share a single scheduler.
from scheduler import (  # noqa: E402
    scheduler,
    scheduler_work,
    calculate_next_run,
    add_schedule_to_scheduler,
    remove_schedule_from_scheduler,
    load_schedules,
)


def run_retention_enforcement():
    """Run the daily retention enforcer to completion.

    Invoked by the BackgroundScheduler worker thread, which has NO running event
    loop — so asyncio.run() is required to drive the async enforce_all(). The
    previous asyncio.create_task() raised "no running event loop" and silently
    skipped every scheduled run (#37, broken since 2026-07-06). Matches the
    scheduled-backup path (scheduler.py). All organizations in this invocation
    share one event loop. Agent HTTP transports are request-owned and closed on
    that loop, so no connection pool crosses scheduler/API loop boundaries.

    Cluster-singleton (#47): the backend runs replicas: 2, and every pod's
    scheduler fires this at the same cron instant — measured 2026-07-30, both pods
    at 03:00:00+00:00. Two concurrent enforcers would prune the same backup set at
    once. It is a no-op today only because backup.auto_cleanup is held off for the
    internal-DR restore, which is precisely the flag that work intends to flip.
    """
    from core.retention import retention_enforcer
    from core.singleton import cluster_singleton

    with cluster_singleton("retention_enforcement") as acquired:
        if not acquired:
            logger.info(
                "Retention enforcement already running on another instance; skipping"
            )
            return
        try:
            from core.tenant_work import run_organization_coroutines

            async def enforce_organization():
                try:
                    await retention_enforcer.enforce_all()
                except Exception:
                    # A failed organization is retried on the next cycle; it
                    # must not prevent independent organizations being visited.
                    logger.exception("Organization retention enforcement failed")

            run_organization_coroutines(SessionLocal, enforce_organization)
        except Exception:
            logger.exception("Retention enforcement job failed")


def reschedule_retention_job(hour) -> int:
    """(Re)schedule the daily retention-enforcement job at the given server-local hour.

    Safe to call at runtime: the fixed job id + replace_existing reschedules the job
    in place (mirrors add_schedule_to_scheduler for user schedules). Invoked at startup
    and whenever backup.retention_hour changes via PUT /api/v1/settings (#29). The hour
    is clamped to 0-23 (falling back to 3 on bad input). The prune itself still runs
    only when backup.auto_cleanup is enabled — enforce_all() checks that at run time.
    Returns the effective hour used.
    """
    try:
        hour = int(hour)
    except (TypeError, ValueError):
        hour = 3
    if hour < 0 or hour > 23:
        hour = 3
    scheduler.add_job(
        run_retention_enforcement,
        CronTrigger.from_crontab(f"0 {hour} * * *"),
        id="retention_enforcement",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    logger.info(f"Retention enforcement scheduled (daily at {hour:02d}:00 server time)")
    return hour


# ============================================================================
# INCLUDE ROUTERS
# ============================================================================

from routers import (  # noqa: E402
    auth_router,
    agents_router,
    backups_router,
    schedules_router,
    groups_router,
    users_router,
    health_router,
    reports_router,
    restores_router,
    config_router,
    activity_router,
    api_keys_router,
    public_router,
    licensing_router,
    stats_router,
    bulk_router,
    queue_router,
    notifications_router,
    search_router,
    dashboard_router,
    verification_router,
    realtime_router,
    encryption_router,
    pki_router,
    s3_import_router,
    demo_router,
    operator_router,
)

# Public endpoints (no prefix needed for some)
app.include_router(licensing_router)
app.include_router(public_router)
if not settings.demo_mode:
    app.include_router(realtime_router)
app.include_router(demo_router)

# API v1 routers
app.include_router(auth_router)
app.include_router(agents_router)
# Literal /backups/queue must precede /backups/{backup_id} in dispatch order.
app.include_router(queue_router)
app.include_router(backups_router)
app.include_router(schedules_router)
app.include_router(groups_router)
app.include_router(users_router)
app.include_router(health_router)
app.include_router(reports_router)
app.include_router(restores_router)
app.include_router(config_router)
app.include_router(activity_router)
app.include_router(api_keys_router)
app.include_router(stats_router)
app.include_router(bulk_router)
app.include_router(notifications_router)
app.include_router(search_router)
app.include_router(dashboard_router)
app.include_router(verification_router)
app.include_router(encryption_router)
app.include_router(pki_router)
app.include_router(s3_import_router)
from core.operator_dispatch import operator_dispatcher  # noqa: E402

app.include_router(operator_router)


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

from core.admin_credentials import ensure_initial_admin  # noqa: E402


def init_database():
    """Validate migrated schema before bootstrap; never repair it at startup."""
    from core.schema_parity import assert_schema_current

    with engine.connect() as connection:
        assert_schema_current(connection)

    # Demo state is created per anonymous session. Seeding ordinary workload
    # rows here would recreate the shared writable surface demo mode is
    # designed to exclude.
    if settings.demo_mode:
        return

    db = SessionLocal()
    try:
        if ensure_initial_admin(
            db,
            settings.initial_admin_username,
            settings.initial_admin_password_file,
        ):
            logger.info(
                "Initial admin user created (username=%s)",
                settings.initial_admin_username,
            )

        # Real inventory comes only from authenticated agent registration and
        # synchronization. Synthetic inventory belongs to the isolated demo API,
        # never to empty-database application startup.
    finally:
        db.close()


# ============================================================================
# STARTUP/SHUTDOWN EVENTS
# ============================================================================

# Global queue processor instance
queue_processor = None


async def _recover_orphaned_uploads():
    """Inspect local-only candidates; never manufacture upload authority.

    Current settings and local object names do not establish historical target
    custody. Transaction/native recovery belongs to its durable D06/D07 path.
    """
    from models import Backup, Organization
    from core.tenant_work import organization_work_ids
    from core.tenant_context import TenantContext

    for org_id in organization_work_ids(SessionLocal):
        try:
            with TenantContext(org_id), SessionLocal() as db:
                organization = db.get(Organization, org_id)
                if organization is None or not organization.enabled:
                    continue
                count = (
                    db.query(Backup)
                    .filter(
                        Backup.status == "completed",
                        Backup.storage_path.like("file://%"),
                    )
                    .count()
                )
                if count:
                    logger.warning(
                        "Local-only backup candidates require durable recovery review: %d",
                        count,
                    )
        except Exception:
            logger.warning("Local-only recovery inspection failed for a work scope")


@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    global queue_processor

    # Fail at boot, not at first login. jwt_secret() raises on its own when the
    # key is absent, but without this the process would start healthy, pass its
    # probes, and only break when a user tried to sign in — which reads as an
    # auth outage rather than a missing setting. Calling it here turns a
    # misconfiguration into a crashloop that names itself. (#51)
    if not settings.demo_mode:
        from deps import jwt_secret

        jwt_secret()

    init_database()

    from core.backup_executor import backup_executor
    from core.restore_executor import restore_executor
    from core.notifications import notification_service
    from core.realtime import realtime
    from core.websocket import websocket_manager

    realtime.start()
    websocket_manager.start()
    backup_executor.start()
    restore_executor.start()
    notification_service.start()
    scheduler_work.start()
    if not scheduler.running:
        # A stopped APScheduler pool cannot accept work after restart.
        try:
            scheduler.remove_executor("default", shutdown=False)
        except KeyError:
            # First startup has no executor until add/start below.
            pass
        scheduler.add_executor("threadpool", alias="default")
        scheduler.start()

    # Initialize Prometheus metrics
    metrics.set_app_info(version=__version__)
    metrics.collect_gauge_metrics()  # Populate gauges immediately on startup

    scheduler.add_job(
        metrics.collect_gauge_metrics,
        "interval",
        seconds=30,
        id="collect_gauge_metrics",
        replace_existing=True,
        misfire_grace_time=30,
    )
    logger.info("Prometheus metrics initialized (gauge collection every 30s)")

    if settings.demo_mode:
        from demo.limits import DemoRateLimiter
        from demo.sessions import DemoSessionService

        if settings.demo_max_sessions <= 0:
            raise RuntimeError(
                "DEMO_MAX_SESSIONS must be set to the approved positive capacity envelope"
            )

        def cleanup_demo_sessions():
            from core.tenant_context import DemoContext

            with DemoContext():
                cleanup_demo_storage()

        def cleanup_demo_storage():
            db = SessionLocal()
            try:
                removed = DemoSessionService(
                    db,
                    idle_minutes=settings.demo_session_idle_minutes,
                    absolute_minutes=settings.demo_session_absolute_minutes,
                    max_sessions=settings.demo_max_sessions,
                ).cleanup_expired()
                removed_buckets = DemoRateLimiter(db).cleanup()
                if removed:
                    logger.info("Removed %d expired demo session(s)", removed)
                if removed_buckets:
                    logger.info(
                        "Removed %d expired demo rate bucket(s)", removed_buckets
                    )
            finally:
                db.close()

        scheduler.add_job(
            cleanup_demo_sessions,
            "interval",
            minutes=5,
            id="cleanup_demo_sessions",
            replace_existing=True,
            misfire_grace_time=300,
        )
        logger.info(
            "Public demo mode active: standard schedulers, executors, agents, "
            "integrations, and commercial modules are disabled"
        )
        return

    # Load schedules
    await load_schedules()

    # Add retention enforcement job at the configured hour (backup.retention_hour,
    # default 3 = 03:00 server time; #29). run_retention_enforcement (module level)
    # drives the async enforcer via asyncio.run() from the BackgroundScheduler worker
    # thread — see #37. The prune runs only when backup.auto_cleanup is enabled.
    from core.settings_reader import get_setting_with_db

    reschedule_retention_job(
        get_setting_with_db("backup", "retention_hour", 3, "integer")
    )

    # Load mTLS certs from DB for backend-to-agent communication
    try:
        from core.backup_executor import backup_executor
        from core.restore_executor import restore_executor

        _db = SessionLocal()
        try:
            backup_executor.configure_mtls_from_db(_db)
            restore_executor.configure_mtls_from_db(_db)
        finally:
            _db.close()
    except Exception as e:
        logger.warning(f"mTLS DB config load failed: {e}")

    # Start backup queue processor
    from core.backup_queue_processor import BackupQueueProcessor
    from core.backup_executor import backup_executor

    queue_processor = BackupQueueProcessor(
        db_session_factory=SessionLocal,
        backup_executor=backup_executor,
        use_real_executor=USE_REAL_BACKUP_EXECUTOR,
    )
    await queue_processor.start()
    logger.info("Backup queue processor started")

    # Recover completed backups that never made it to S3.
    # This catches the race where heartbeat overwrites "uploading" with
    # "completed" without authoritative upload acceptance after a restart.
    await _recover_orphaned_uploads()

    # Add cleanup job for stale operations
    def cleanup_stale_operations():
        with scheduler_work.callback():
            scheduler_work.submit(cleanup_stale_operations_on_loop)

    async def cleanup_stale_operations_on_loop():
        """Keep the sweep's synchronous database work off the serving loop."""
        from core.notifications import notify_stale_backup_failure
        from core.task_lifetime import run_owned_worker
        from core.tenant_context import TenantContext

        for org_id, backup, vm_name, reason in await run_owned_worker(
            _cleanup_stale_operations_worker
        ):
            with TenantContext(org_id):
                try:
                    await notify_stale_backup_failure(
                        backup=backup, vm_name=vm_name, error=reason
                    )
                except Exception:
                    logger.exception("Stale backup notification failed")

    def _cleanup_stale_operations_worker():
        """Hold singleton custody and tenant SQL in one cancellable owned worker."""
        from core.singleton import cluster_singleton
        from core.tenant_context import TenantContext
        from core.tenant_work import organization_work_ids
        from database import SessionLocal
        from models import Backup, SystemEvent

        notifications = []
        with cluster_singleton("cleanup_stale_operations") as acquired:
            if not acquired:
                return ()
            for org_id in organization_work_ids(SessionLocal):
                with TenantContext(org_id):
                    notifications.extend(
                        (org_id, backup, vm_name, reason)
                        for backup, vm_name, reason in _cleanup_stale_operations_locked(
                            SessionLocal, Backup, SystemEvent
                        )
                    )
        return tuple(notifications)

    def _cleanup_stale_operations_locked(SessionLocal, Backup, SystemEvent):
        from types import SimpleNamespace

        db = SessionLocal()
        try:
            now = datetime.utcnow()

            # Mark agents offline if no heartbeat for 5 min
            stale_agents = (
                db.query(Agent)
                .filter(
                    Agent.status == "online",
                    Agent.last_heartbeat < (now - timedelta(minutes=5)),
                )
                .all()
            )
            for agent in stale_agents:
                agent.status = "offline"
                logger.info(f"Marked agent {agent.hostname} offline")

            # Heartbeat-aware backup liveness detection
            # Instead of a static 2h timeout, check whether the agent is
            # alive and still reports the backup as active. A 458GB backup
            # at compression 9 can legitimately run 14+ hours.
            from core.backup_monitor import stale_backup_candidates

            running_backups = stale_backup_candidates(db)
            failed_backups = []
            for backup in running_backups:
                age_minutes = (now - backup.created_at).total_seconds() / 60
                if age_minutes < 10:
                    continue  # Too young to judge

                # Find the agent for this backup's VM
                vm = db.query(VM).filter(VM.id == backup.vm_id).first()
                agent = (
                    db.query(Agent).filter(Agent.id == vm.agent_id).first()
                    if vm
                    else None
                )

                reason = None
                if not agent:
                    reason = "Agent not found for backup VM"
                elif agent.status == "offline":
                    reason = f"Agent {agent.hostname} is offline"
                elif (
                    agent.last_heartbeat
                    and (now - agent.last_heartbeat).total_seconds() > 300
                ):
                    stale_secs = int((now - agent.last_heartbeat).total_seconds())
                    reason = f"Agent {agent.hostname} heartbeat stale ({stale_secs}s)"
                elif agent.status == "online":
                    # Agent is alive — check if it still reports active backups
                    active_count = (agent.health_data or {}).get("active_backups", 0)
                    if active_count == 0 and age_minutes > 30:
                        reason = f"Agent {agent.hostname} online but reports 0 active backups"
                    # else: agent alive and reports active backups — backup is legitimately running

                if reason:
                    backup.status = "failed"
                    backup.tags = {**(backup.tags or {}), "error": reason}
                    failed_backups.append(
                        (
                            SimpleNamespace(
                                id=backup.id,
                                vm_id=backup.vm_id,
                                status="failed",
                                backup_type=backup.backup_type,
                                created_at=backup.created_at,
                                tags=dict(backup.tags),
                            ),
                            vm.name if vm else "unknown",
                            reason,
                        )
                    )
                    logger.warning(f"Marked backup {backup.id} as failed: {reason}")

            # Commit status and its durable event together. A second replica
            # sees only terminal rows and cannot repeat the notification.
            for backup, vm_name, reason in failed_backups:
                db.add(
                    SystemEvent(
                        event_type="backup_stale_timeout",
                        source="system",
                        source_id="cleanup_job",
                        resource_type="backup",
                        resource_id=backup.id,
                        details={
                            "backup_id": backup.id,
                            "vm_name": vm_name,
                            "reason": reason,
                            "old_status": "running",
                            "new_status": "failed",
                        },
                    )
                )
            if stale_agents or failed_backups:
                db.commit()
            return failed_backups

        except Exception as e:
            logger.error(f"Cleanup job error: {e}")
            db.rollback()
            return []
        finally:
            db.close()

    scheduler.add_job(
        cleanup_stale_operations,
        "interval",
        minutes=2,
        id="cleanup_stale_operations",
        replace_existing=True,
        misfire_grace_time=120,
    )
    logger.info("Cleanup job scheduled (every 2 minutes)")

    # Installed modules require working implementations; certificate validity
    # never interrupts their loading or changes authentication scope.
    logger.info("Installed profile: %s", features.profile.public())
    from core.commercial import load_commercial_modules

    loaded_modules = load_commercial_modules(app, features)
    if loaded_modules:
        logger.info("Commercial capabilities active: %s", ", ".join(loaded_modules))

    # TLS/PKI and licensing must be initialized before read-only scrub recovery.
    # Demo never dispatches real provider work.
    if not settings.demo_mode:
        from core.verification_executor import verification_executor

        verification_executor.start()
        operator_dispatcher.start()


@app.on_event("shutdown")
async def shutdown_event():
    """Drain independent owners, retaining every failure and cancellation."""
    from core.backup_executor import backup_executor
    from core.restore_executor import restore_executor
    from core.verification_executor import verification_executor
    from core.notifications import notification_service
    from core.realtime import realtime
    from core.websocket import websocket_manager

    # No await before all production dispatch admission gates are closed.
    scheduler_work.close_admission()
    operator_dispatcher.close_admission()
    backup_executor.close_admission()
    restore_executor.close_admission()
    verification_executor.close_admission()
    notification_service.close_admission()
    realtime.close_admission()
    websocket_manager.close_admission()
    failures = []
    if queue_processor:
        try:
            await queue_processor.stop()
            logger.info("Backup queue processor stopped")
        except (Exception, asyncio.CancelledError) as error:
            failures.append(error)

    if scheduler.running:
        try:
            await asyncio.to_thread(scheduler.shutdown, wait=True)
            logger.info("Scheduler stopped")
        except (Exception, asyncio.CancelledError) as error:
            failures.append(error)

    try:
        await scheduler_work.drain()
    except (Exception, asyncio.CancelledError) as error:
        failures.append(error)
    # Owners refuse foreign loops rather than closing their transport underneath
    # live users. Scheduler dispatch now shares this application's loop instead.
    for owner in (
        operator_dispatcher,
        realtime,
        websocket_manager,
        backup_executor,
        verification_executor,
        restore_executor,
        notification_service,
    ):
        try:
            await owner.cleanup()
        except (Exception, asyncio.CancelledError) as error:
            failures.append(error)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("Application shutdown owner failures", failures)


# ============================================================================
# MOCK BACKUP EXECUTION (for development)
# ============================================================================


async def simulate_backup_execution(backup_id: str):
    """Simulate backup execution with progress updates (for development)"""
    from models import Backup
    import random

    db = SessionLocal()
    try:
        backup = db.query(Backup).filter(Backup.id == backup_id).first()
        if not backup or backup.authority_kind == "scheduler":
            return

        stages = [(10, 2), (30, 3), (50, 4), (70, 5), (90, 3), (100, 1)]

        for progress_value, sleep_seconds in stages:
            await asyncio.sleep(sleep_seconds)
            backup.progress = progress_value
            backup.status = "running"
            db.commit()
            db.refresh(backup)

        backup.status = "completed"
        backup.progress = 100
        backup.size_bytes = random.randint(1_000_000_000, 10_000_000_000)
        backup.completed_at = datetime.utcnow()
        db.commit()

        logger.info(f"Mock backup {backup_id} completed")

    except Exception as e:
        logger.error(f"Error in mock backup {backup_id}: {e}")
        backup = db.query(Backup).filter(Backup.id == backup_id).first()
        if backup:
            backup.status = "failed"
            db.commit()
    finally:
        db.close()


# Export for use by routers
__all__ = [
    "app",
    "SessionLocal",
    "scheduler",
    "USE_REAL_BACKUP_EXECUTOR",
    "simulate_backup_execution",
    "calculate_next_run",
    "add_schedule_to_scheduler",
    "remove_schedule_from_scheduler",
]
