"""Admission and reconciliation shared by manual and scheduled full file backups."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import re
from urllib.parse import urlsplit
from uuid import uuid4

from croniter import croniter
import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text

from core.backup_admission_pause import new_backup_admission_paused
from core.file_agent_http import AgentPeer
from core.scheduler_runtime import due_schedule_minute
from core.scheduler_scope import ScopeRefused
from core.settings_reader import is_maintenance_mode
from core.singleton import lock_key
from core.task_lifetime import run_owned_worker
from core.tenant_context import TenantContext
from core.tenant_work import organization_work_ids
from models import (
    Agent,
    AgentCertificate,
    FileBackup,
    FileSchedule,
    Organization,
    SystemEvent,
    User,
)

logger = logging.getLogger(__name__)

FILE_SET_PATTERN = r"^[a-z][a-z0-9_-]{0,62}$"
BUCKET_PATTERN = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
PREFIX_PATTERN = r"[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*"
REGION_PATTERN = r"[a-z0-9][a-z0-9-]{0,62}"
ENDPOINT_PATTERN = r"https://(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[a-f0-9:]+\])(?::[1-9][0-9]{0,4})?"
FILE_CAPABILITY_FIELDS = ("managed_file_sets", "managed_file_storage")
ARCHIVE_FORMAT = "vesta-file-archive-v1"
POLL_INTERVAL = timedelta(seconds=10)
CHECK_LEASE = timedelta(seconds=90)
PRE_DISPATCH_TIMEOUT = timedelta(minutes=15)
TERMINAL = {"completed", "failed"}


class AdmissionRefused(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code


def advertised_file_sets(capabilities):
    value = (
        capabilities.get("managed_file_sets")
        if isinstance(capabilities, dict)
        else None
    )
    if (
        not isinstance(value, list)
        or len(value) > 256
        or any(
            not isinstance(name, str) or not re.fullmatch(FILE_SET_PATTERN, name)
            for name in value
        )
        or len(set(value)) != len(value)
    ):
        return []
    return value


def valid_endpoint(endpoint):
    if not isinstance(endpoint, str) or not re.fullmatch(ENDPOINT_PATTERN, endpoint):
        return False
    try:
        port = urlsplit(endpoint).port
        return port is None or port != 443
    except ValueError:
        return False


def file_storage(capabilities, name):
    advertised = (
        capabilities.get("managed_file_storage")
        if isinstance(capabilities, dict)
        else None
    )
    if not isinstance(advertised, dict):
        return None
    endpoint, region, bucket, prefix, recipients = (
        advertised.get("endpoint"),
        advertised.get("region"),
        advertised.get("bucket"),
        advertised.get("prefix"),
        advertised.get("recipient_sha256"),
    )
    digest = recipients.get(name) if isinstance(recipients, dict) else None
    if (
        not valid_endpoint(endpoint)
        or not isinstance(region, str)
        or not re.fullmatch(REGION_PATTERN, region)
        or not isinstance(bucket, str)
        or not re.fullmatch(BUCKET_PATTERN, bucket)
        or not isinstance(prefix, str)
        or len(prefix) > 512
        or not re.fullmatch(PREFIX_PATTERN, prefix)
        or any(part in {".", ".."} for part in prefix.split("/"))
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        return None
    return {
        "endpoint": endpoint,
        "region": region,
        "bucket": bucket,
        "prefix": prefix,
        "recipient_sha256": digest,
    }


def sanitized_file_storage(capabilities, names):
    policies = {name: file_storage(capabilities, name) for name in names}
    policies = {name: policy for name, policy in policies.items() if policy is not None}
    if not policies:
        return None
    sample = next(iter(policies.values()))
    return {
        "endpoint": sample["endpoint"],
        "region": sample["region"],
        "bucket": sample["bucket"],
        "prefix": sample["prefix"],
        "recipient_sha256": {
            name: policy["recipient_sha256"] for name, policy in policies.items()
        },
    }


def bind_file_capabilities(previous, reported, *, trusted):
    """File discovery and storage changes require the enrolled TLS identity."""
    from core.storage_transfer import refreshed_capabilities

    current = refreshed_capabilities(previous, reported)
    for field in FILE_CAPABILITY_FIELDS:
        current.pop(field, None)
    if not trusted:
        if previous and previous.get("managed_file_sets"):
            for field in (*FILE_CAPABILITY_FIELDS, "provider"):
                if field in previous:
                    current[field] = previous[field]
        return current
    if reported.get("provider") not in {"libvirt", "none"}:
        return current
    names = advertised_file_sets(reported)
    if names:
        current["managed_file_sets"] = names
        storage = sanitized_file_storage(reported, names)
        if storage:
            current["managed_file_storage"] = storage
    return current


def storage_binding(row):
    return {
        "endpoint": row.storage_endpoint,
        "region": row.storage_region,
        "bucket": row.storage_bucket,
        "prefix": row.storage_prefix,
        "recipient_sha256": row.storage_recipient_sha256,
    }


def bind_storage(row, policy):
    row.storage_endpoint = policy["endpoint"]
    row.storage_region = policy["region"]
    row.storage_bucket = policy["bucket"]
    row.storage_prefix = policy["prefix"]
    row.storage_recipient_sha256 = policy["recipient_sha256"]


def clock():
    return datetime.now(timezone.utc)


def locked_actor(db, user, *, admin=False):
    organization = db.scalar(
        select(Organization)
        .where(Organization.id == user.org_id, Organization.enabled.is_(True))
        .with_for_update(read=True)
    )
    actor = db.scalar(
        select(User)
        .where(User.id == user.id, User.org_id == user.org_id, User.is_active.is_(True))
        .execution_options(populate_existing=True)
        .with_for_update(read=True)
    )
    if (
        organization is None
        or actor is None
        or actor.role not in (("admin",) if admin else ("admin", "operator"))
    ):
        raise AdmissionRefused(
            403, "file_authority_required", "File backup authority is unavailable"
        )
    return organization, actor


def target_agent(db, org_id, agent_id, file_set, *, lock=False):
    stmt = select(Agent).where(Agent.org_id == org_id, Agent.id == agent_id)
    agent = db.scalar(stmt.with_for_update(read=True) if lock else stmt)
    if agent is not None and file_set in advertised_file_sets(agent.capabilities):
        return agent
    return None


def require_target(db, org_id, agent_id, file_set):
    agent = target_agent(db, org_id, agent_id, file_set, lock=True)
    if agent is None:
        raise AdmissionRefused(404, "file_set_not_found", "Enrolled file set not found")
    policy = file_storage(agent.capabilities, file_set)
    if policy is None:
        raise AdmissionRefused(
            409,
            "file_storage_unavailable",
            "The enrolled host has not advertised a valid file archive destination",
        )
    return policy


def require_admission(db):
    if db.get_bind().dialect.name == "postgresql":
        # Share the installation lock that fences pause updates for VM admission.
        db.execute(text("SELECT pg_advisory_xact_lock(1447977557,1)"))
    if is_maintenance_mode(db):
        raise AdmissionRefused(
            503, "maintenance_mode", "New backups are disabled during maintenance"
        )
    try:
        paused = new_backup_admission_paused(db)
    except ValueError:
        raise AdmissionRefused(
            409,
            "backup_admission_policy_unavailable",
            "The installation's backup admission policy needs review",
        ) from None
    if paused:
        raise AdmissionRefused(
            409, "backup_admission_paused", "New backup admissions are paused"
        )


def admit_manual(db, user, agent_id, file_set, request_key):
    org, actor = locked_actor(db, user)
    if request_key is not None:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {
                    "key": lock_key(
                        f"file-backup-request:{org.id}:{actor.id}:{request_key}"
                    )
                },
            )
        previous = db.scalar(
            select(FileBackup).filter_by(
                org_id=org.id, actor_id=actor.id, request_key=request_key
            )
        )
        if previous is not None:
            if (previous.agent_id, previous.file_set) != (agent_id, file_set):
                raise AdmissionRefused(
                    409,
                    "file_request_conflict",
                    "Idempotency key is bound to another file set",
                )
            return previous
    policy = require_target(db, org.id, agent_id, file_set)
    require_admission(db)
    now = clock()
    row = FileBackup(
        org_id=org.id,
        agent_id=agent_id,
        file_set=file_set,
        actor_id=actor.id,
        request_key=request_key,
        created_at=now,
        next_check_at=now,
    )
    from deps import log_activity

    bind_storage(row, policy)
    db.add(row)
    db.flush()
    log_activity(
        db,
        actor,
        "file_backup_requested",
        "file_backup",
        row.id,
        {"agent_id": agent_id, "file_set": file_set},
        commit=False,
    )
    db.commit()
    return row


def create_due_file_attempts(factory, org_id, now):
    """Current UTC slot only, with one immutable occurrence per schedule and minute."""
    with factory() as db:
        org = db.scalar(
            select(Organization).filter_by(id=org_id).with_for_update(read=True)
        )
        if org is None or not org.enabled:
            return
        rows = db.scalars(
            select(FileSchedule)
            .where(
                FileSchedule.org_id == org_id,
                FileSchedule.enabled.is_(True),
                FileSchedule.retired_at.is_(None),
                FileSchedule.org_epoch == org.scheduler_epoch,
                FileSchedule.next_run_at <= now,
            )
            .order_by(FileSchedule.next_run_at, FileSchedule.id)
            .limit(50)
            .with_for_update(skip_locked=True)
        ).all()
        for schedule in rows:
            next_run = croniter(schedule.cron_expression, now).get_next(datetime)
            try:
                instant = due_schedule_minute(
                    schedule.cron_expression, schedule.next_run_at, now
                )
                if instant is None:
                    continue
                require_admission(db)
            except (AdmissionRefused, ScopeRefused) as exc:
                logger.debug("File schedule %s deferred: %s", schedule.id, str(exc))
            else:
                row = FileBackup(
                    org_id=org_id,
                    agent_id=schedule.agent_id,
                    file_set=schedule.file_set,
                    schedule_id=schedule.id,
                    schedule_grant_id=schedule.grant_id,
                    scheduled_at=instant,
                    created_at=now,
                    next_check_at=now,
                )
                bind_storage(row, storage_binding(schedule))
                db.add(row)
                schedule.last_run_at = instant
            schedule.next_run_at = next_run
        db.commit()


class AgentStorage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    endpoint: str
    region: str
    bucket: str
    prefix: str
    recipient_sha256: str


class AgentObservation(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    backup_id: str
    file_set: str
    status: str
    files: int | None = Field(default=None, ge=0, le=2**63 - 1)
    directories: int | None = Field(default=None, ge=0, le=2**63 - 1)
    bytes: int | None = Field(default=None, ge=0, le=2**63 - 1)
    error: str | None = None
    s3_path: str | None = Field(default=None, max_length=2048)
    s3_version_id: str | None = Field(default=None, max_length=1024)
    storage: AgentStorage | None = None
    archive_format: str | None = None
    archive_size_bytes: int | None = Field(default=None, gt=0, le=2**63 - 1)
    archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    recipient_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Check:
    backup_id: str
    agent_id: str
    file_set: str
    token: str
    peer: AgentPeer
    already_accepted: bool
    first_send: bool
    can_start: bool
    storage: dict


def _terminal_event(db, row):
    success = row.status == "completed"
    db.add(
        SystemEvent(
            org_id=row.org_id,
            attribution="tenant",
            event_type="file_backup_completed" if success else "file_backup_failed",
            source="backup",
            source_id=row.schedule_id,
            resource_type="file_backup",
            resource_id=row.id,
            details={
                "agent_id": row.agent_id,
                "file_set": row.file_set,
                "error": row.error,
            },
        )
    )
    return success, row.id, row.agent_id, row.file_set, row.error


def _no_effect_fail(db, row, now, error):
    row.status = "failed"
    row.completed_at = now
    row.error = error
    return _terminal_event(db, row)


def _can_dispatch_new(db, organization, row):
    if row.schedule_id is None:
        actor_id = db.scalar(
            select(User.id)
            .where(
                User.id == row.actor_id,
                User.org_id == row.org_id,
                User.is_active.is_(True),
                User.role.in_(("admin", "operator")),
            )
            .with_for_update(read=True)
        )
        return actor_id is not None
    schedule = db.scalar(
        select(FileSchedule)
        .where(
            FileSchedule.id == row.schedule_id,
            FileSchedule.org_id == row.org_id,
            FileSchedule.enabled.is_(True),
            FileSchedule.retired_at.is_(None),
            FileSchedule.org_epoch == organization.scheduler_epoch,
            FileSchedule.grant_id == row.schedule_grant_id,
        )
        .with_for_update(read=True)
    )
    return schedule is not None


def certified_file_fingerprint(db, agent, now):
    fingerprint = agent.cert_fingerprint
    if (
        not agent.mtls_enabled
        or not fingerprint
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
    ):
        return None
    leaves = db.scalars(
        select(AgentCertificate.id)
        .where(
            AgentCertificate.agent_id == agent.id,
            AgentCertificate.fingerprint == fingerprint,
            AgentCertificate.common_name == agent.hostname,
            AgentCertificate.status == "active",
            AgentCertificate.revoked_at.is_(None),
            AgentCertificate.expires_at > now.replace(tzinfo=None),
        )
        .limit(2)
    ).all()
    return fingerprint if len(leaves) == 1 else None


def certified_file_peer(db, agent, now):
    port = agent.port or 8090
    fingerprint = certified_file_fingerprint(db, agent, now)
    if fingerprint is None or not 1 <= port <= 65535:
        return None
    return AgentPeer(
        agent.ip_address or agent.hostname, port, agent.hostname, fingerprint
    )


def claim_checks(factory, org_id, now, executor):
    with factory() as db:
        organization = db.scalar(
            select(Organization)
            .where(Organization.id == org_id, Organization.enabled.is_(True))
            .with_for_update(read=True)
        )
        if organization is None:
            return [], []
        rows = db.scalars(
            select(FileBackup)
            .where(
                FileBackup.org_id == org_id,
                FileBackup.status.in_(("pending", "running")),
                FileBackup.next_check_at <= now,
            )
            .order_by(FileBackup.next_check_at, FileBackup.id)
            .limit(8)
            .with_for_update(skip_locked=True)
        ).all()
        checks, notifications = [], []
        for row in rows:
            row.next_check_at = now + POLL_INTERVAL
            first = row.dispatch_started_at is None
            can_start = row.agent_accepted_at is None and _can_dispatch_new(
                db, organization, row
            )
            if first and not can_start:
                notifications.append(
                    _no_effect_fail(
                        db,
                        row,
                        now,
                        "The backup requester or schedule grant is no longer authorized.",
                    )
                )
                continue
            agent = db.scalar(select(Agent).filter_by(id=row.agent_id, org_id=org_id))
            if first and (
                agent is None
                or row.file_set not in advertised_file_sets(agent.capabilities)
            ):
                notifications.append(
                    _no_effect_fail(
                        db, row, now, "The enrolled file set is no longer available"
                    )
                )
                continue
            if first and file_storage(
                agent.capabilities, row.file_set
            ) != storage_binding(row):
                notifications.append(
                    _no_effect_fail(
                        db,
                        row,
                        now,
                        "File archive destination or recipient changed. "
                        "Review the enrolled host and reactivate its schedule.",
                    )
                )
                continue
            peer = (
                certified_file_peer(db, agent, now)
                if agent is not None
                and agent.status == "online"
                and executor.has_authenticated_agent_transport()
                else None
            )
            if peer is None:
                row.error = "Waiting for a verified connection to the enrolled host"
                if (
                    first
                    and now - row.created_at.replace(tzinfo=timezone.utc)
                    >= PRE_DISPATCH_TIMEOUT
                ):
                    notifications.append(_no_effect_fail(db, row, now, row.error))
                continue
            if first:
                row.dispatch_started_at = now
            token = str(uuid4())
            row.next_check_at = now + CHECK_LEASE
            row.check_token = token
            checks.append(
                Check(
                    row.id,
                    agent.id,
                    row.file_set,
                    token,
                    peer,
                    row.agent_accepted_at is not None,
                    first,
                    can_start,
                    storage_binding(row),
                )
            )
        db.commit()
        return checks, notifications


def validate_observation(data, check):
    observed = AgentObservation.model_validate(data)
    if (observed.backup_id, observed.file_set) != (check.backup_id, check.file_set):
        raise ValueError("Agent returned an unrelated backup")
    if observed.status not in {"pending", "running", "completed", "failed"}:
        raise ValueError("Unknown agent backup status")
    if observed.status == "completed":
        path = urlsplit(observed.s3_path or "")
        expected = f"/{check.storage['prefix']}/managed-files/{check.file_set}/{check.backup_id}/archive.age"
        if (
            path.scheme != "s3"
            or path.netloc != check.storage["bucket"]
            or path.query
            or path.fragment
            or path.path != expected
            or observed.recipient_sha256 != check.storage["recipient_sha256"]
            or observed.storage is None
            or observed.storage.model_dump() != check.storage
            or any(ord(c) < 32 or ord(c) == 127 for c in observed.s3_path)
            or observed.archive_format != ARCHIVE_FORMAT
            or not observed.s3_version_id
            or observed.s3_version_id == "null"
            or any(ord(c) < 32 or ord(c) == 127 for c in observed.s3_version_id)
            or any(
                field is None
                for field in (
                    observed.archive_size_bytes,
                    observed.archive_sha256,
                    observed.recipient_sha256,
                    observed.files,
                    observed.directories,
                    observed.bytes,
                )
            )
        ):
            raise ValueError("Versioned encrypted archive receipt is incomplete")
    return observed


async def read_agent(executor, check):
    headers = {**executor._get_agent_headers(), "X-Vesta-Agent-ID": check.agent_id}
    path = "/api/file-backups"
    async with asyncio.timeout(35):
        if not check.first_send:
            response = await executor.file_agent_http.get(
                check.peer, f"{path}/{check.backup_id}", headers=headers
            )
            if response.status_code != 404 or check.already_accepted:
                if response.status_code == 404:
                    raise ValueError(
                        "The original agent journal has no record of the accepted backup"
                    )
                response.raise_for_status()
                return validate_observation(response.json(), check)
            if not check.can_start:
                raise ValueError(
                    "No authority to create a backup after the previous send"
                )
        response = await executor.file_agent_http.post(
            check.peer,
            path,
            json={
                "backup_id": check.backup_id,
                "file_set": check.file_set,
                "storage": check.storage,
            },
            headers=headers,
        )
        # The agent reports domain-level refusal only after authenticating and
        # looking up this exact backup ID. Other failures retain the dispatch.
        if response.status_code in {409, 422}:
            return AgentObservation(
                backup_id=check.backup_id,
                file_set=check.file_set,
                status="failed",
                error="The enrolled host refused the file set or backup identity",
            )
        if response.status_code != 202:
            response.raise_for_status()
            raise ValueError("Agent did not acknowledge the backup")
        return validate_observation(response.json(), check)


def persist_check(factory, org_id, check, observed, retry_error):
    with factory() as db:
        row = db.scalar(
            select(FileBackup)
            .filter_by(org_id=org_id, id=check.backup_id, check_token=check.token)
            .with_for_update()
        )
        if row is None or row.status in TERMINAL:
            return None
        now = clock()
        row.error = retry_error
        row.check_token = None
        row.next_check_at = now + POLL_INTERVAL
        result = None
        if observed is not None:
            row.agent_accepted_at = row.agent_accepted_at or now
            if observed.status == "running" or observed.status == "completed":
                row.started_at = row.started_at or now
            if observed.status != "pending" or row.status == "pending":
                row.status = observed.status
            for name in ("files", "directories", "bytes"):
                value = getattr(observed, name)
                if value is not None:
                    setattr(row, name, value)
            if (
                row.status == "running"
                and observed.error
                == "Awaiting S3 confirmation; encrypted archive retained on host"
            ):
                row.error = "Waiting for S3 to confirm the object version. The host has retained the encrypted archive."
            if row.status == "completed":
                row.error = None
                for name in (
                    "s3_path",
                    "s3_version_id",
                    "archive_format",
                    "archive_size_bytes",
                    "archive_sha256",
                    "recipient_sha256",
                ):
                    setattr(row, name, getattr(observed, name))
            elif row.status == "failed":
                # Host logs retain diagnostics, including potentially private
                # filesystem details. The control plane exposes a bounded summary.
                row.error = (
                    "The enrolled host refused the file set or backup identity"
                    if observed.error
                    == "The enrolled host refused the file set or backup identity"
                    else "File backup failed on the enrolled host. Check its backup log."
                )
            if row.status in TERMINAL:
                row.completed_at = now
                result = _terminal_event(db, row)
        db.commit()
        return result


async def _run_check(factory, org_id, executor, check):
    observed, retry_error = None, None
    try:
        observed = await read_agent(executor, check)
    except (
        httpx.HTTPError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        logger.info(
            "File backup %s awaiting agent reconciliation (%s)",
            check.backup_id,
            type(exc).__name__,
        )
        retry_error = "Waiting for a valid outcome from the enrolled host"
    return await run_owned_worker(
        persist_check, factory, org_id, check, observed, retry_error
    )


async def run_file_backup_tick(factory, executor):
    """Run both trigger types on the existing scheduler's owned application loop."""
    from core.notifications import notification_service

    for org_id in await run_owned_worker(organization_work_ids, factory):
        with TenantContext(org_id):
            try:
                now = clock()
                await run_owned_worker(create_due_file_attempts, factory, org_id, now)
                checks, notifications = await run_owned_worker(
                    claim_checks, factory, org_id, now, executor
                )
                results = await asyncio.gather(
                    *(_run_check(factory, org_id, executor, check) for check in checks),
                    return_exceptions=True,
                )
                for outcome in [*notifications, *results]:
                    if isinstance(outcome, Exception):
                        logger.warning(
                            "File backup check failed (%s)", type(outcome).__name__
                        )
                    elif outcome:
                        await notification_service.send_file_backup_notification(
                            *outcome
                        )
            except Exception as exc:
                logger.warning(
                    "File backup scheduler tick deferred for organization %s (%s)",
                    org_id,
                    type(exc).__name__,
                )
