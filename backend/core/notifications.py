"""
Notification Service

Handles email notifications for backup events and system alerts.
Reads configuration from SystemSettings via settings_reader.
"""

import asyncio
import logging
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Backup, Agent, NotificationLog, SystemEvent
from .settings_reader import get_setting, get_sustained_failure_threshold
from .product_identity import product_name
from .task_lifetime import DispatchLifetime, owned_dispatch, run_owned_worker

logger = logging.getLogger(__name__)


class SMTPDeliveryUncertain(RuntimeError):
    """A submitted SMTP operation has no trustworthy delivery verdict."""


class NotificationService:
    """
    Service for sending email notifications based on system events.
    """

    MAX_PENDING_SENDS = 32

    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        self._workers = set()
        self._shutdown_complete = False
        self.drain_timeout = 35.0

    def start(self):
        if self.dispatch_lifetime.closed:
            if not self._shutdown_complete or self._workers:
                raise RuntimeError("SMTP shutdown remains unresolved")
            self.dispatch_lifetime = DispatchLifetime()
            self._shutdown_complete = False

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    async def cleanup(self):
        self.close_admission()
        await self.dispatch_lifetime.drain()
        if self._workers:
            # wait does not cancel executor futures on timeout or caller cancel.
            _, pending = await asyncio.wait(self._workers, timeout=self.drain_timeout)
            if pending:
                raise RuntimeError("SMTP worker drain incomplete; delivery uncertain")
        self._shutdown_complete = True

    def _worker_finished(self, future):
        self._workers.discard(future)
        # Retrieve any late exception even when the caller was cancelled. Never
        # log its body: SMTP errors may contain credentials or message content.
        if not future.cancelled():
            future.exception()

    @owned_dispatch
    async def _send_logged_email(
        self, *, db, notification_type, recipients, subject, body, config, **attribution
    ):
        outcome = "uncertain"
        try:
            success = await self._send_email(subject, body, recipients, config)
            outcome = "sent" if success else "failed"
        finally:
            # A cancelled await is not proof that the running worker sent nothing.
            # The stale sweep supplies no session: its DB outcome write belongs
            # to an owned worker, while SMTP stays on this service's loop.
            if db is None:
                await run_owned_worker(
                    self._log_fresh,
                    notification_type,
                    recipients,
                    subject,
                    body,
                    success=outcome == "sent",
                    outcome=outcome,
                    **attribution,
                )
            else:
                self._log_notification(
                    db,
                    notification_type,
                    recipients,
                    subject,
                    body,
                    success=outcome == "sent",
                    outcome=outcome,
                    **attribution,
                )

    def _log_fresh(self, notification_type, recipients, subject, body, **outcome):
        db = SessionLocal()
        try:
            self._log_notification(
                db, notification_type, recipients, subject, body, **outcome
            )
        finally:
            db.close()

    def _prepare_stale_failure_email(self, backup, vm_name, error):
        """Read settings and build the detached sweep alert on a DB worker."""
        with SessionLocal() as db:
            config = self._get_smtp_config(db)
            prefs = self._get_notification_prefs(db)
        if not config["enabled"] or not prefs["on_failure"]:
            return None
        recipients = self._parse_recipients(config["recipients"])
        if not recipients:
            return None
        name = vm_name or backup.vm_id
        return (
            config,
            recipients,
            f"[{product_name()}] Backup FAILED: {name}",
            self._build_failure_email(backup, name, error),
        )

    def _get_smtp_config(self, db: Session) -> dict:
        """Get SMTP configuration from settings"""
        return {
            "enabled": get_setting(
                "notifications", "email_enabled", False, "boolean", db
            ),
            "server": get_setting("notifications", "smtp_server", "", "string", db),
            "port": get_setting("notifications", "smtp_port", 587, "integer", db),
            "username": get_setting("notifications", "smtp_username", "", "string", db),
            "password": get_setting("notifications", "smtp_password", "", "string", db),
            "from_email": get_setting("notifications", "smtp_from", "", "string", db),
            "use_tls": get_setting(
                "notifications", "smtp_use_tls", True, "boolean", db
            ),
            "recipients": get_setting(
                "notifications", "notification_recipients", "", "string", db
            ),
        }

    def _get_notification_prefs(self, db: Session) -> dict:
        """Get notification preferences from settings"""
        return {
            "on_success": get_setting(
                "notifications", "notify_on_success", False, "boolean", db
            ),
            "on_failure": get_setting(
                "notifications", "notify_on_failure", True, "boolean", db
            ),
            "on_agent_offline": get_setting(
                "notifications", "notify_agent_offline", True, "boolean", db
            ),
        }

    def _parse_recipients(self, recipients_str: str) -> List[str]:
        """Parse comma-separated recipients into list"""
        if not recipients_str:
            return []
        return [r.strip() for r in recipients_str.split(",") if r.strip()]

    async def send_backup_notification(
        self,
        backup: Backup,
        event: str,
        vm_name: Optional[str] = None,
        error_message: Optional[str] = None,
        db: Optional[Session] = None,
    ):
        """
        Send notification for backup events.

        Args:
            backup: Backup record
            event: Event type ('success', 'failure', 'started')
            vm_name: Optional VM name for display
            error_message: Optional error message for failures
            db: Optional database session
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            config = self._get_smtp_config(db)
            prefs = self._get_notification_prefs(db)

            # Check if notifications are enabled
            if not config["enabled"]:
                logger.debug("Email notifications disabled")
                return

            # Check if we should send for this event type
            if event == "success" and not prefs["on_success"]:
                logger.debug("Notifications for backup success disabled")
                return
            if event == "failure" and not prefs["on_failure"]:
                logger.debug("Notifications for backup failure disabled")
                return

            # Get recipients
            recipients = self._parse_recipients(config["recipients"])
            if not recipients:
                logger.warning("No notification recipients configured")
                return

            # Build email
            vm_display = vm_name or backup.vm_id
            if event == "success":
                subject = f"[{product_name()}] Backup completed: {vm_display}"
                body = self._build_success_email(backup, vm_display)
            elif event == "failure":
                subject = f"[{product_name()}] Backup FAILED: {vm_display}"
                body = self._build_failure_email(backup, vm_display, error_message)
            else:
                subject = f"[{product_name()}] Backup {event}: {vm_display}"
                body = f"Backup {event} for VM {vm_display}\n\nBackup ID: {backup.id}"

            # Send email
            await self._send_logged_email(
                db=db,
                notification_type="backup_" + event,
                recipients=recipients,
                subject=subject,
                body=body,
                config=config,
                backup_id=backup.id,
            )

        except Exception:
            logger.error("Backup notification failed or delivery is uncertain")
        finally:
            if close_db:
                db.close()

    async def send_agent_offline_notification(
        self, agent: Agent, db: Optional[Session] = None
    ):
        """
        Send notification when an agent goes offline.

        Args:
            agent: Agent record that went offline
            db: Optional database session
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            config = self._get_smtp_config(db)
            prefs = self._get_notification_prefs(db)

            # Check if notifications are enabled
            if not config["enabled"]:
                return

            # Check if agent offline notifications are enabled
            if not prefs["on_agent_offline"]:
                return

            # Get recipients
            recipients = self._parse_recipients(config["recipients"])
            if not recipients:
                return

            # Build email
            subject = f"[{product_name()}] Agent OFFLINE: {agent.hostname}"
            body = self._build_agent_offline_email(agent)

            # Send email
            await self._send_logged_email(
                db=db,
                notification_type="agent_offline",
                recipients=recipients,
                subject=subject,
                body=body,
                config=config,
                agent_id=agent.id,
            )

        except Exception:
            logger.error("Agent notification failed or delivery is uncertain")
        finally:
            if close_db:
                db.close()

    def _build_success_email(self, backup: Backup, vm_name: str) -> str:
        """Build email body for successful backup"""
        duration = ""
        if backup.completed_at and backup.created_at:
            delta = backup.completed_at - backup.created_at
            minutes = int(delta.total_seconds() // 60)
            seconds = int(delta.total_seconds() % 60)
            duration = f"\nDuration: {minutes}m {seconds}s"

        size = ""
        if backup.size_bytes:
            size_gb = backup.size_bytes / (1024**3)
            size = f"\nSize: {size_gb:.2f} GB"

        return f"""Backup completed successfully.

VM: {vm_name}
Backup ID: {backup.id}
Type: {backup.backup_type or 'full'}
Status: {backup.status}
Started: {backup.created_at}
Completed: {backup.completed_at}{duration}{size}
Retention: {backup.retention_days} days

--
{product_name()} Backup System
"""

    def _build_failure_email(
        self, backup: Backup, vm_name: str, error: Optional[str]
    ) -> str:
        """Build email body for failed backup"""
        error_msg = (
            error or backup.tags.get("error", "Unknown error")
            if backup.tags
            else "Unknown error"
        )

        return f"""Backup FAILED!

VM: {vm_name}
Backup ID: {backup.id}
Type: {backup.backup_type or 'full'}
Status: {backup.status}
Started: {backup.created_at}

Error:
{error_msg}

Please check the system logs for more details.

--
{product_name()} Backup System
"""

    def _build_agent_offline_email(self, agent: Agent) -> str:
        """Build email body for agent offline notification"""
        return f"""Agent has gone OFFLINE!

Hostname: {agent.hostname}
Agent ID: {agent.id}
Last Heartbeat: {agent.last_heartbeat}
IP Address: {agent.ip_address or 'N/A'}

VMs managed by this agent may not be available for backup until the agent comes back online.

Please check the agent status and network connectivity.

--
{product_name()} Backup System
"""

    @owned_dispatch
    async def _send_email(
        self, subject: str, body: str, recipients: List[str], config: dict
    ) -> bool:
        """
        Send an email via SMTP.

        True means SMTP acknowledged, not mailbox delivery. False is local
        pre-send refusal. Submitted failures raise a redacted uncertain result;
        cancellation propagates while the service retains worker ownership.
        """
        if not config["server"]:
            logger.error("SMTP server not configured")
            return False

        if not config["from_email"]:
            logger.error("SMTP from email not configured")
            return False

        if len(self._workers) >= self.MAX_PENDING_SENDS:
            logger.warning("SMTP worker capacity exhausted; no send submitted")
            return False

        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = config["from_email"]
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            # Connect and send
            # Run in thread pool to not block async loop
            loop = asyncio.get_running_loop()
            worker = loop.run_in_executor(
                None, self._send_smtp, msg, list(recipients), dict(config)
            )
        except Exception:
            logger.error("SMTP preparation or worker submission failed")
            return False

        self._workers.add(worker)
        worker.add_done_callback(self._worker_finished)
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            logger.warning("SMTP caller cancelled; delivery uncertain, worker retained")
            raise
        except Exception:
            logger.warning("SMTP delivery uncertain; no automatic retry")
            raise SMTPDeliveryUncertain(
                "SMTP delivery uncertain; do not automatically retry"
            ) from None
        logger.info("SMTP server acknowledged notification")
        return True

    def _send_smtp(self, msg: MIMEMultipart, recipients: List[str], config: dict):
        """Synchronous SMTP send (runs in thread pool)"""
        if config["use_tls"]:
            # Start with plain connection, then upgrade to TLS (STARTTLS)
            # Use SSL_CERT_FILE env var for corporate CA trust (set by K8s deployment)
            context = ssl.create_default_context()
            ca_bundle = os.environ.get("SSL_CERT_FILE")
            if ca_bundle and os.path.exists(ca_bundle):
                context.load_verify_locations(ca_bundle)
                logger.debug(f"Loaded CA bundle from {ca_bundle}")
            with smtplib.SMTP(config["server"], config["port"], timeout=30) as server:
                server.starttls(context=context)
                if config["username"] and config["password"]:
                    server.login(config["username"], config["password"])
                refused = server.sendmail(
                    config["from_email"], recipients, msg.as_string()
                )
                if refused:
                    raise SMTPDeliveryUncertain(
                        "SMTP recipients only partially accepted"
                    )
        else:
            # Plain SMTP (no TLS)
            with smtplib.SMTP(config["server"], config["port"], timeout=30) as server:
                if config["username"] and config["password"]:
                    server.login(config["username"], config["password"])
                refused = server.sendmail(
                    config["from_email"], recipients, msg.as_string()
                )
                if refused:
                    raise SMTPDeliveryUncertain(
                        "SMTP recipients only partially accepted"
                    )

    def _log_notification(
        self,
        db: Session,
        notification_type: str,
        recipients: List[str],
        subject: str,
        body: str,
        success: bool,
        backup_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        outcome: Optional[str] = None,
    ):
        """Log notification to database"""
        try:
            log = NotificationLog(
                event_type=notification_type,  # e.g., "backup_failure", "backup_success", "agent_offline"
                recipient=", ".join(recipients),
                subject=subject,
                body=body,
                status=outcome or ("sent" if success else "failed"),
            )
            db.add(log)
            db.commit()
        except Exception:
            logger.warning("Notification outcome persistence failed; no retry implied")


# Global instance
notification_service = NotificationService()


# Convenience functions
async def notify_backup_success(
    backup: Backup, vm_name: str = None, db: Session = None
):
    """Send backup success notification"""
    await notification_service.send_backup_notification(
        backup=backup, event="success", vm_name=vm_name, db=db
    )


def _record_backup_failure_event(
    backup: Backup, vm_name: str = None, error: str = None
):
    """Persist a durable, SMTP-independent SystemEvent for a backup failure (#38).

    Backup-failure alerting used to be entirely email-gated: send_backup_notification
    silently no-ops when SMTP is off or no recipients are configured, and the only
    durable trace of a failure was backup.status="failed" on the row — so a sustained
    failure streak stayed invisible in-product (Mesh: 66 failures over ~110 days, no
    alarm). This records every failure as an alertable event in the activity feed /
    dashboard, independent of email.

    Uses its own DB session so recording is isolated from the caller's transaction,
    and is best-effort — a recording error must never mask the underlying failure.
    """
    db = SessionLocal()
    try:
        db.add(
            SystemEvent(
                event_type="backup_failed",
                source="backup",
                resource_type="backup",
                resource_id=str(backup.id) if getattr(backup, "id", None) else None,
                details={
                    "vm_name": vm_name or getattr(backup, "vm_id", None),
                    "vm_id": getattr(backup, "vm_id", None),
                    "error": (error or "")[:2000],
                },
            )
        )
        db.commit()
    except Exception:
        logger.exception("Failed to record backup-failure system event")
        db.rollback()
    finally:
        db.close()


def _maybe_record_sustained_failure(
    backup: Backup, vm_name: str = None, error: str = None
):
    """Emit a distinct `backup_failing_sustained` SystemEvent once a VM crosses a
    consecutive-failure threshold (#41, follow-up to #38).

    The per-failure `backup_failed` event (see _record_backup_failure_event) makes every
    failure visible; this adds a *distinct* streak signal so a sustained outage (the Mesh
    case: a VM failing for weeks) is distinguishable in-product from a one-off blip. The
    no-success-in-X-days angle is deliberately NOT reimplemented here — that is already the
    `vnbui_backup_last_success_age_seconds` staleness metric.

    Semantics:
    - Fires when the current failure plus the most recent committed terminal outcomes make
      `threshold` consecutive `failed` backups for the VM with no `completed` in between.
    - Threshold from setting `backup.sustained_failure_threshold` (default 3); <= 1 disables
      (1 would fire on every single failure, which `backup_failed` already covers).
    - Only hard `failed` outcomes count. `upload_failed` (backup succeeded locally, S3 retry
      pending) is neither a success nor a streak failure — the guard below skips it and the
      terminal-window query ignores it; only `completed` breaks a streak.
    - De-duplicated to once per streak: re-checked against the most recent success, so a long
      outage yields one alert, not one per failed attempt.
    - Keyed on the VM (resource_type="vm"), unlike the per-backup `backup_failed` event, since
      the streak is a per-VM condition; the de-dup query relies on that key.

    Best-effort on its own session; a bookkeeping error must never mask the real failure.
    """
    # notify_backup_failure also fires for exhausted S3 uploads (status "upload_failed"),
    # which produced a local backup and must NOT count as a hard failure. The in-memory
    # status is authoritative here — at some call sites the row isn't committed yet.
    if getattr(backup, "status", None) != "failed":
        return
    vm_id = getattr(backup, "vm_id", None)
    if not vm_id:
        return

    db = SessionLocal()
    try:
        threshold = get_sustained_failure_threshold(db)
        if not threshold or threshold <= 1:
            return  # feature disabled

        backup_id = getattr(backup, "id", None)
        # Most recent committed *definitive* outcomes for this VM, excluding the current
        # backup — its "failed" status may be uncommitted at some call sites, so we count it
        # explicitly as the head of the streak. upload_failed / in-flight rows are ignored.
        prev = (
            db.query(Backup.status)
            .filter(
                Backup.vm_id == vm_id,
                Backup.status.in_(("completed", "failed")),
                Backup.id != backup_id,
            )
            .order_by(Backup.created_at.desc())
            .limit(threshold - 1)
            .all()
        )
        # current (failed) + (threshold - 1) prior, all failed => `threshold` in a row.
        if len(prev) < threshold - 1:
            return
        if any(status != "failed" for (status,) in prev):
            return

        # Streak confirmed. Boundary = the VM's most recent success (None if never).
        last_success_at = (
            db.query(Backup.created_at)
            .filter(Backup.vm_id == vm_id, Backup.status == "completed")
            .order_by(Backup.created_at.desc())
            .limit(1)
            .scalar()
        )
        # De-dup: skip if we already alerted for the current streak (since last success).
        dedup_q = db.query(SystemEvent.id).filter(
            SystemEvent.event_type == "backup_failing_sustained",
            SystemEvent.resource_type == "vm",
            SystemEvent.resource_id == str(vm_id),
        )
        if last_success_at is not None:
            dedup_q = dedup_q.filter(SystemEvent.created_at > last_success_at)
        if db.query(dedup_q.exists()).scalar():
            return

        # Full streak length (>= threshold) for the alert detail.
        streak_q = db.query(func.count(Backup.id)).filter(
            Backup.vm_id == vm_id, Backup.status == "failed"
        )
        if last_success_at is not None:
            streak_q = streak_q.filter(Backup.created_at > last_success_at)
        consecutive = max(int(streak_q.scalar() or 0), threshold)

        db.add(
            SystemEvent(
                event_type="backup_failing_sustained",
                source="backup",
                resource_type="vm",
                resource_id=str(vm_id),
                details={
                    "vm_name": vm_name or vm_id,
                    "vm_id": vm_id,
                    "threshold": threshold,
                    "consecutive_failures": consecutive,
                    "last_success_at": (
                        last_success_at.isoformat() if last_success_at else None
                    ),
                    "latest_error": (error or "")[:2000],
                },
            )
        )
        db.commit()
        logger.warning(
            "VM %s has %s consecutive backup failures (threshold %s) — recorded "
            "backup_failing_sustained event",
            vm_name or vm_id,
            consecutive,
            threshold,
        )
    except Exception:
        logger.exception("Failed to evaluate/record sustained backup-failure event")
        db.rollback()
    finally:
        db.close()


async def notify_backup_failure(
    backup: Backup, vm_name: str = None, error: str = None, db: Session = None
):
    """Record a backup failure durably, then send an email if configured.

    The durable SystemEvent (see _record_backup_failure_event) is the SMTP-independent
    fix for the silent-failure gap (#38); email is best-effort on top and only fires
    when SMTP + recipients are configured. A distinct sustained-failure event
    (see _maybe_record_sustained_failure) fires once a VM crosses the consecutive-failure
    threshold (#41).
    """
    _record_backup_failure_event(backup, vm_name, error)
    _maybe_record_sustained_failure(backup, vm_name, error)
    await notification_service.send_backup_notification(
        backup=backup, event="failure", vm_name=vm_name, error_message=error, db=db
    )


async def notify_stale_backup_failure(backup, vm_name=None, error=None):
    """Keep a stale sweep's SQL off the API loop without moving SMTP custody."""
    await run_owned_worker(_record_backup_failure_event, backup, vm_name, error)
    await run_owned_worker(_maybe_record_sustained_failure, backup, vm_name, error)
    prepared = await run_owned_worker(
        notification_service._prepare_stale_failure_email,
        backup,
        vm_name,
        error,
    )
    if prepared is None:
        return
    config, recipients, subject, body = prepared
    await notification_service._send_logged_email(
        db=None,
        notification_type="backup_failure",
        recipients=recipients,
        subject=subject,
        body=body,
        config=config,
        backup_id=backup.id,
    )


async def notify_agent_offline(agent: Agent, db: Session = None):
    """Send agent offline notification"""
    await notification_service.send_agent_offline_notification(agent=agent, db=db)
