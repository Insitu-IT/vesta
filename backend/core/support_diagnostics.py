"""Read-only, bounded diagnostic projections; never serialize ORM objects."""

import logging
import re
import time
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, text

from models import Agent, Backup, BackupVerification, Restore
from version import __version__

logger = logging.getLogger(__name__)
ROW_LIMIT = 50
STATEMENT_TIMEOUT_MS = 2000
COLLECTION_SECONDS = 10
STATES = frozenset(
    (
        "online",
        "offline",
        "pending",
        "queued",
        "running",
        "completed",
        "failed",
        "cancelled",
        "passed",
        "held",
        "uncertain",
        "upload_completed",
        "uploading",
        "retry_pending",
        "cancel_requested",
        "cancelling",
        "unreserved",
        "reserved",
        "legacy_held",
        "released",
        "full",
        "incremental",
        "differential",
    )
)


def identifier(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def timestamp(value):
    if not isinstance(value, datetime):
        return None
    return (
        value.replace(tzinfo=value.tzinfo or timezone.utc)
        .astimezone(timezone.utc)
        .isoformat()
    )


def state(value):
    return value if isinstance(value, str) and value in STATES else "unknown"


def bounded_number(value, maximum):
    return value if type(value) is int and 0 <= value <= maximum else None


def _agents(org_id):
    return (
        select(
            Agent.id,
            Agent.status,
            Agent.version,
            Agent.last_heartbeat,
            Agent.cert_expires_at,
            Agent.mtls_enabled,
        )
        .where(Agent.org_id == org_id)
        .order_by(Agent.last_heartbeat.desc(), Agent.id)
    )


def _backups(org_id, backup_id):
    query = select(
        Backup.id,
        Backup.vm_id,
        Backup.status,
        Backup.capacity_state,
        Backup.backup_type,
        Backup.progress,
        Backup.created_at,
        Backup.completed_at,
        Backup.parent_backup_id,
        Backup.chain_position,
        Backup.native_job_intent.is_not(None).label("native_intent_present"),
        Backup.native_inventory.is_not(None).label("native_inventory_present"),
        Backup.native_closed_failure.is_not(None).label(
            "native_failure_evidence_present"
        ),
    ).where(Backup.org_id == org_id)
    if backup_id:
        query = query.where(Backup.id == backup_id)
    return query.order_by(
        Backup.capacity_state.in_(("reserved", "legacy_held")).desc(),
        Backup.created_at.desc(),
        Backup.id,
    )


def _restores(org_id, backup_id):
    query = select(
        Restore.id,
        Restore.backup_id,
        Restore.status,
        Restore.progress,
        Restore.created_at,
        Restore.completed_at,
        Restore.error_message.is_not(None).label("error_recorded"),
    ).where(Restore.org_id == org_id)
    if backup_id:
        query = query.where(Restore.backup_id == backup_id)
    return query.order_by(Restore.created_at.desc(), Restore.id)


def _verifications(org_id, backup_id):
    query = select(
        BackupVerification.id,
        BackupVerification.backup_id,
        BackupVerification.status,
        BackupVerification.created_at,
        BackupVerification.completed_at,
        BackupVerification.verification_worker_id,
        BackupVerification.verification_read_attempts,
        BackupVerification.verification_read_limit,
        BackupVerification.verification_cancel_requested,
    ).where(BackupVerification.org_id == org_id)
    if backup_id:
        query = query.where(BackupVerification.backup_id == backup_id)
    return query.order_by(BackupVerification.created_at.desc(), BackupVerification.id)


ID_FIELDS = frozenset(
    ("id", "vm_id", "backup_id", "parent_backup_id", "verification_worker_id")
)
TIME_FIELDS = frozenset(
    ("created_at", "completed_at", "last_heartbeat", "cert_expires_at")
)
STATE_FIELDS = frozenset(("status", "capacity_state", "backup_type"))
BOOL_FIELDS = frozenset(
    (
        "mtls_enabled",
        "native_intent_present",
        "native_inventory_present",
        "native_failure_evidence_present",
        "error_recorded",
        "verification_cancel_requested",
    )
)
NUMBER_FIELDS = {
    "progress": 100,
    "chain_position": 1_000_000,
    "verification_read_attempts": 1_000_000,
    "verification_read_limit": 1_000_000,
}


def project(row):
    """Only finite scalars: never names, URLs, messages, settings or JSON blobs."""
    result = {}
    for key, value in row.items():
        if key in ID_FIELDS:
            result[key] = identifier(value)
        elif key in TIME_FIELDS:
            result[key] = timestamp(value)
        elif key in STATE_FIELDS:
            result[key] = state(value)
        elif key in BOOL_FIELDS:
            result[key] = value if type(value) is bool else None
        elif key in NUMBER_FIELDS:
            result[key] = bounded_number(value, NUMBER_FIELDS[key])
        elif key == "version":
            result[key] = (
                value
                if isinstance(value, str)
                and re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", value)
                else None
            )
    return result


def collect(db, org_id, *, backup_id=None):
    """Use an authenticated tenant session. Queries cannot flush or repair data.

    Each failed section rolls back its savepoint, not previous observations.
    PostgreSQL enforces the query timeout. SQLite is used only by unit tests.
    """
    if identifier(org_id) is None:
        raise ValueError("Organization identity required")
    if backup_id is not None and identifier(backup_id) is None:
        raise ValueError("Invalid backup identity")
    if db.new or db.dirty or db.deleted:
        raise ValueError("Diagnostic collection requires an unchanged session")
    report_id = str(uuid4())
    started = time.monotonic()
    report = {
        "schema": "vnbui-support-diagnostics/1",
        "report_id": report_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "backend_version": __version__,
        "scope": "Authenticated organization only; sampled recorded state, not integrity or restore proof",
        "privacy": (
            "No names, endpoints, configuration, raw logs, error messages, keys or credentials. "
            "Review identifiers before sharing."
        ),
        "limits": {
            "rows_per_section": ROW_LIMIT,
            "query_timeout_ms": STATEMENT_TIMEOUT_MS,
        },
        "sections": {},
        "guidance": {
            "held": (
                "Preserve journals, keys, source disks and objects. Use same-attempt recovery; "
                "do not guess cleanup or abort foreign jobs."
            ),
            "failed": "Correlate operation IDs and timestamps with backend/agent logs using the shipped support guide.",
            "unavailable": (
                "Collection failure is not a healthy result. Collect pod/service logs locally; "
                "do not restart or repair during collection."
            ),
        },
    }
    for name, build in (
        ("agents", lambda: _agents(org_id)),
        ("backups", lambda: _backups(org_id, backup_id)),
        ("restores", lambda: _restores(org_id, backup_id)),
        ("verifications", lambda: _verifications(org_id, backup_id)),
    ):
        try:
            if time.monotonic() - started >= COLLECTION_SECONDS:
                raise TimeoutError()
            with db.no_autoflush, db.begin_nested():
                if db.get_bind().dialect.name == "postgresql":
                    db.execute(text("SET LOCAL statement_timeout = '2000ms'"))
                rows = db.execute(build().limit(ROW_LIMIT + 1)).mappings().all()
                section = {
                    "status": "observed",
                    "truncated": len(rows) > ROW_LIMIT,
                    "rows": [project(row) for row in rows[:ROW_LIMIT]],
                }
            report["sections"][name] = section
        except Exception:
            # Exception text/tracebacks can contain credentials and SQL parameters.
            report["sections"][name] = {
                "status": "unavailable",
                "reason": "collection_failed",
            }
            logger.warning(
                "diagnostic_section_unavailable report_id=%s section=%s",
                report_id,
                name,
            )
    report["status"] = (
        "partial"
        if any(
            section["status"] != "observed" for section in report["sections"].values()
        )
        else "collected"
    )
    logger.info(
        "diagnostic_collected report_id=%s status=%s", report_id, report["status"]
    )
    return report
