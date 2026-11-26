"""
Prometheus metrics for Vesta

Exposes key operational metrics for monitoring:
- Backup operations and status
- Agent health and connectivity
- Reconciliation events
- WebSocket connections
- API request latency
"""

from copy import copy

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

# Create a custom registry (avoids conflicts with other prometheus instrumentation)
REGISTRY = CollectorRegistry()

storage_control_step_seconds = Histogram(
    "vnbui_storage_control_step_seconds",
    "Storage control admission, persistence or signing/configuration latency; "
    "nested observations are not wall-time slices",
    ["step"],
    buckets=[0.001, 0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60],
    registry=REGISTRY,
)

# =============================================================================
# Application Info
# =============================================================================
app_info = Info("vnbui", "vnbui application information", registry=REGISTRY)

# =============================================================================
# Backup Metrics
# =============================================================================
backups_total = Counter(
    "vnbui_backups_total",
    "Total number of backup operations",
    ["status"],  # completed, failed, cancelled
    registry=REGISTRY,
)

backups_in_progress = Gauge(
    "vnbui_backups_in_progress",
    "Number of backups currently running",
    registry=REGISTRY,
)

backup_duration_seconds = Histogram(
    "vnbui_backup_duration_seconds",
    "Backup duration in seconds",
    buckets=[60, 300, 600, 1800, 3600, 7200, 14400],  # 1m to 4h
    registry=REGISTRY,
)

backup_size_bytes = Histogram(
    "vnbui_backup_size_bytes",
    "Backup size in bytes",
    buckets=[1e8, 5e8, 1e9, 5e9, 1e10, 5e10, 1e11],  # 100MB to 100GB
    registry=REGISTRY,
)

backup_queue_size = Gauge(
    "vnbui_backup_queue_size", "Number of backups in queue", registry=REGISTRY
)

# =============================================================================
# Agent Metrics
# =============================================================================
agents_total = Gauge(
    "vnbui_agents_total", "Total number of registered agents", registry=REGISTRY
)

agents_online = Gauge(
    "vnbui_agents_online", "Number of agents currently online", registry=REGISTRY
)

agents_degraded = Gauge(
    "vnbui_agents_degraded", "Number of agents in degraded state", registry=REGISTRY
)

agents_degraded_by_reason = Gauge(
    "vnbui_agents_degraded_by_reason",
    "Number of online agents degraded for a bounded health reason",
    ["reason"],
    registry=REGISTRY,
)

agent_heartbeats_total = Counter(
    "vnbui_agent_heartbeats_total",
    "Total agent heartbeats received",
    ["agent_id"],
    registry=REGISTRY,
)

# =============================================================================
# Reconciliation Metrics
# =============================================================================
reconciliation_events_total = Counter(
    "vnbui_reconciliation_events_total",
    "Total reconciliation events processed",
    ["event_type"],  # backup_recovered, backup_orphaned, status_corrected
    registry=REGISTRY,
)

reconciliation_duration_seconds = Histogram(
    "vnbui_reconciliation_duration_seconds",
    "Reconciliation processing duration",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
    registry=REGISTRY,
)

# =============================================================================
# S3 Upload Metrics
# =============================================================================
s3_uploads_total = Counter(
    "vnbui_s3_uploads_total",
    "Total S3 upload operations",
    ["status"],  # success, failed
    registry=REGISTRY,
)

s3_upload_duration_seconds = Histogram(
    "vnbui_s3_upload_duration_seconds",
    "S3 upload duration in seconds",
    buckets=[1, 5, 10, 30, 60, 120, 300],
    registry=REGISTRY,
)

s3_upload_retries_total = Counter(
    "vnbui_s3_upload_retries_total", "Total S3 upload retry attempts", registry=REGISTRY
)

# =============================================================================
# WebSocket Metrics
# =============================================================================
websocket_connections = Gauge(
    "vnbui_websocket_connections",
    "Current number of WebSocket connections",
    registry=REGISTRY,
)

websocket_connections_rejected = Counter(
    "vnbui_websocket_connections_rejected_total",
    "Total WebSocket connections rejected (limit exceeded)",
    registry=REGISTRY,
)

# =============================================================================
# Connector Gauges (for Zabbix/monitoring-integrations)
# =============================================================================
vms_total = Gauge(
    "vnbui_vms_total", "Total VMs discovered across all agents", registry=REGISTRY
)

encryption_keys_active = Gauge(
    "vnbui_encryption_keys_active",
    "Number of active encryption keys",
    registry=REGISTRY,
)

last_backup_success_timestamp = Gauge(
    "vnbui_last_backup_success_timestamp",
    "Epoch timestamp of most recent successful backup",
    registry=REGISTRY,
)

backup_last_success_age_seconds = Gauge(
    "vnbui_backup_last_success_age_seconds",
    "Seconds since the most recent successful backup for a VM (age since VM "
    "registration if it has never had a successful backup). Enables per-VM "
    "backup-staleness alerting — the signal that was missing when backups "
    "failed silently for months (#38).",
    ["vm_name", "vm_id"],
    registry=REGISTRY,
)

# =============================================================================
# Scheduler Metrics
# =============================================================================
scheduled_backups_total = Counter(
    "vnbui_scheduled_backups_total",
    "Total scheduled backup executions",
    ["schedule_id"],
    registry=REGISTRY,
)

scheduler_misfires_total = Counter(
    "vnbui_scheduler_misfires_total",
    "Total scheduler misfire events",
    registry=REGISTRY,
)

# =============================================================================
# API Metrics
# =============================================================================
api_requests_total = Counter(
    "vnbui_api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status"],
    registry=REGISTRY,
)

api_request_duration_seconds = Histogram(
    "vnbui_api_request_duration_seconds",
    "API request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=REGISTRY,
)


# =============================================================================
# Helper Functions
# =============================================================================
class _ExposedMetrics:
    def collect(self):
        for family in REGISTRY.collect():
            if family.name == "vnbui" or family.name.startswith("vnbui_"):
                # Both series use the same samples so existing dashboards can migrate.
                branded = copy(family)
                branded.name = "vesta" + family.name.removeprefix("vnbui")
                branded.samples = [
                    sample._replace(name="vesta" + sample.name.removeprefix("vnbui"))
                    for sample in family.samples
                ]
                yield branded
            yield family


def get_metrics():
    """Render Vesta metrics and backwards-compatible series."""
    return generate_latest(_ExposedMetrics())


def get_content_type():
    """Get the content type for metrics endpoint"""
    return CONTENT_TYPE_LATEST


def set_app_info(version: str, build_date: str = None):
    """Set application info metric"""
    info = {"version": version}
    if build_date:
        info["build_date"] = build_date
    app_info.info(info)


# =============================================================================
# Metric Recording Helpers
# =============================================================================
def record_backup_completed(duration_seconds: float, size_bytes: int = None):
    """Record a completed backup"""
    backups_total.labels(status="completed").inc()
    backup_duration_seconds.observe(duration_seconds)
    if size_bytes:
        backup_size_bytes.observe(size_bytes)


def record_backup_failed():
    """Record a failed backup"""
    backups_total.labels(status="failed").inc()


def record_backup_cancelled():
    """Record a cancelled backup"""
    backups_total.labels(status="cancelled").inc()


def record_reconciliation_event(event_type: str, duration_seconds: float = None):
    """Record a reconciliation event"""
    reconciliation_events_total.labels(event_type=event_type).inc()
    if duration_seconds is not None:
        reconciliation_duration_seconds.observe(duration_seconds)


def record_s3_upload(success: bool, duration_seconds: float = None, retries: int = 0):
    """Record an S3 upload operation"""
    status = "success" if success else "failed"
    s3_uploads_total.labels(status=status).inc()
    if duration_seconds is not None:
        s3_upload_duration_seconds.observe(duration_seconds)
    if retries > 0:
        s3_upload_retries_total.inc(retries)


def update_websocket_stats(connections: int, rejected: int = 0):
    """Update WebSocket connection metrics"""
    websocket_connections.set(connections)
    if rejected > 0:
        websocket_connections_rejected.inc(rejected)


def update_agent_stats(total: int, online: int, degraded: int = 0):
    """Update agent metrics"""
    agents_total.set(total)
    agents_online.set(online)
    agents_degraded.set(degraded)


def update_agent_degradation_reasons(reason_counts: dict[str, int]):
    """Emit every bounded reason, including explicit zero values."""
    from core.agent_health import HEALTH_REASONS

    for reason in HEALTH_REASONS:
        agents_degraded_by_reason.labels(reason=reason).set(
            reason_counts.get(reason, 0)
        )


def update_backup_queue_stats(queue_size: int, in_progress: int):
    """Update backup queue metrics"""
    backup_queue_size.set(queue_size)
    backups_in_progress.set(in_progress)


def collect_gauge_metrics():
    """Installation telemetry only; explicit trusted read scope, never mutation."""
    from core.tenant_context import PlatformContext

    with PlatformContext():
        _collect_gauge_metrics()


def _collect_gauge_metrics():
    """Periodic collector that queries DB for current gauge values.

    Registered as an APScheduler job (every 30s) in app.py startup.
    """
    from datetime import datetime, timedelta

    from core.agent_health import HEALTH_REASONS
    from database import SessionLocal
    from models import VM, Agent, Backup, BackupQueue, EncryptionKey

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        health_threshold = timedelta(minutes=5)

        # Agent gauges
        all_agents = db.query(Agent).all()
        online = 0
        degraded = 0
        degradation_reason_counts = {reason: 0 for reason in HEALTH_REASONS}
        for agent in all_agents:
            since = now - (agent.last_heartbeat or agent.created_at)
            if since < health_threshold:
                online += 1
                m = agent.metrics or {}
                if m.get("health_status") == "degraded":
                    degraded += 1
                    for reason in set(m.get("health_reasons") or []):
                        if reason in degradation_reason_counts:
                            degradation_reason_counts[reason] += 1
        update_agent_stats(total=len(all_agents), online=online, degraded=degraded)
        update_agent_degradation_reasons(degradation_reason_counts)

        # Backup / queue gauges
        running = db.query(Backup).filter(Backup.status == "running").count()
        queued = db.query(BackupQueue).filter(BackupQueue.status == "queued").count()
        update_backup_queue_stats(queue_size=queued, in_progress=running)

        # Connector gauges
        vms_total.set(db.query(VM).count())
        encryption_keys_active.set(
            db.query(EncryptionKey).filter(EncryptionKey.status == "active").count()
        )

        last_completed = (
            db.query(Backup.completed_at)
            .filter(Backup.status == "completed", Backup.completed_at.isnot(None))
            .order_by(Backup.completed_at.desc())
            .first()
        )
        if last_completed and last_completed[0]:
            last_backup_success_timestamp.set(last_completed[0].timestamp())

        # Per-VM backup staleness (#38): seconds since each VM's last successful
        # backup (age since registration if it never succeeded). SMTP-independent
        # signal for monitoring/zabbix staleness alerting — backups had failed
        # silently for months because notify_on_failure needs email configured.
        backup_last_success_age_seconds.clear()
        for vm in db.query(VM).all():
            last_ok = (
                db.query(Backup.completed_at)
                .filter(
                    Backup.vm_id == vm.id,
                    Backup.status == "completed",
                    Backup.completed_at.isnot(None),
                )
                .order_by(Backup.completed_at.desc())
                .first()
            )
            baseline = (
                last_ok[0] if (last_ok and last_ok[0]) else (vm.created_at or now)
            )
            age = max(0.0, (now - baseline).total_seconds())
            backup_last_success_age_seconds.labels(
                vm_name=vm.name, vm_id=str(vm.id)
            ).set(age)

    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Gauge collection error: {e}")
    finally:
        db.close()
