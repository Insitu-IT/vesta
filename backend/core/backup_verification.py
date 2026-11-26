"""Original-principal, accepted-catalog scrub custody and exact result binding.

This module grants only reads. No provider result authorizes publication, backup
mutation, retention, capacity release, VM creation or import trust.
"""

import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import uuid

from core.s3_ownership import StorageOwnershipError
from core.operation_budget import (
    verification_admission_budget,
    verification_admission_exhausted,
)
from core.storage_receipt_v2 import canonical, decode
from core.storage_restore import build_restore_bundle
from core.tenant_context import commercial_mode, is_superuser
from models import (
    Agent,
    Backup,
    BackupVerification,
    Organization,
    OrganizationDefault,
    S3Publication,
    SettingV3,
    User,
    VM,
)

SCHEMA = "vnbui-backup-verification/1"
PROGRESS_SCHEMA = "vnbui-backup-verification-progress/1"
RESULT_SCHEMA = "vnbui-chain-verification/1"
MAX_PLAN_BYTES = (32 << 20) - (64 << 10)
TYPE = "artifact_scrub"
TERMINAL = frozenset({"passed", "failed", "cancelled"})
MAX_UNFINISHED_PER_AGENT = 16


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _refuse():
    raise StorageOwnershipError(
        "Original verification custody or authority is unavailable"
    )


def _id(value):
    try:
        parsed = uuid.UUID(value)
        return str(parsed) == value and parsed.int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _authority(db, org_id, actor_id):
    if is_superuser.get():
        _refuse()
    if not commercial_mode():
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None or assignment.org_id != org_id:
            _refuse()
    org = (
        db.query(Organization)
        .filter_by(id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    actor = (
        db.query(User)
        .filter_by(id=actor_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        org is None
        or org.enabled is not True
        or actor is None
        or actor.is_active is not True
        or actor.role not in {"admin", "operator"}
    ):
        _refuse()
    from core.installation_config import read_configuration

    policies = read_configuration(db, SettingV3, "backup.capacity_admission")
    try:
        policy = decode(policies[0].value) if len(policies) == 1 else None
        if (
            type(policy) is not dict
            or set(policy) != {"schema", "revision", "limit", "maintenance"}
            or type(policy["schema"]) is not int
            or policy["schema"] != 1
            or type(policy["revision"]) is not int
            or not 0 < policy["revision"] < 2**63
            or type(policy["limit"]) is not int
            or not 1 <= policy["limit"] <= 100000
            or policy["maintenance"] is not False
        ):
            _refuse()
    except (ValueError, TypeError, KeyError):
        _refuse()
    return {
        "org_id": org_id,
        "actor_id": actor_id,
        "role": actor.role,
        "org_epoch": org.scheduler_epoch,
    }


def _bundle(db, backup_id, org_id):
    # Caller already owns the organization's admission lock. Use retention's
    # org -> VM -> sorted backup order; never lock a child before its source VM.
    selected = db.query(Backup).filter_by(id=backup_id, org_id=org_id).one_or_none()
    if selected is None:
        _refuse()
    vm = (
        db.query(VM)
        .filter_by(id=selected.vm_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if vm is None or vm.provider not in {"kubevirt", "libvirt"}:
        _refuse()
    bundle = build_restore_bundle(db, backup_id, org_id)
    ids = [m["request"]["backup_id"] for m in bundle["members"]]
    locked = (
        db.query(Backup)
        .filter(Backup.org_id == org_id, Backup.id.in_(ids))
        .order_by(Backup.id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    if len(locked) != len(ids) or any(
        b.status != "completed" or b.vm_id != vm.id for b in locked
    ):
        _refuse()
    if any(m["request"]["agent_id"] != vm.agent_id for m in bundle["members"]):
        _refuse()
    agent = db.query(Agent).filter_by(id=vm.agent_id, org_id=org_id).one_or_none()
    if agent is None:
        _refuse()
    return bundle, vm


def load_plan(record):
    try:
        text = record.verification_plan_canonical
        plan = decode(text)
        authority = decode(record.verification_authority_canonical)
        if (
            not isinstance(text, str)
            or len(text.encode()) > MAX_PLAN_BYTES
            or canonical(plan).decode() != text
            or digest(plan) != record.verification_plan_sha256
            or set(plan)
            != {
                "schema",
                "verification_id",
                "org_id",
                "agent_id",
                "provider",
                "authority_sha256",
                "bundle",
            }
            or plan["schema"] != SCHEMA
            or plan["verification_id"] != record.id
            or plan["org_id"] != record.org_id
            or plan["agent_id"] != record.verification_agent_id
            or plan["provider"] not in {"kubevirt", "libvirt"}
            or digest(authority) != plan["authority_sha256"]
            or canonical(authority).decode() != record.verification_authority_canonical
            or set(authority) != {"actor_id", "org_id", "role", "org_epoch"}
            or authority["actor_id"] != record.created_by
            or authority["org_id"] != record.org_id
            or authority["role"] not in {"admin", "operator"}
            or type(authority["org_epoch"]) is not int
            or authority["org_epoch"] < 0
            or plan["bundle"]["members"][-1]["request"]["backup_id"] != record.backup_id
            or record.verification_type != TYPE
        ):
            _refuse()
        return plan, authority
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ):
        _refuse()


def enroll(db, *, backup_id, org_id, actor_id, verification_id):
    if not all(_id(v) for v in (backup_id, org_id, actor_id, verification_id)):
        _refuse()
    authority = _authority(db, org_id, actor_id)
    bundle, vm = _bundle(db, backup_id, org_id)
    existing = (
        db.query(BackupVerification)
        .filter_by(id=verification_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if existing is not None:
        saved, original = load_plan(existing)
        if (
            existing.backup_id != backup_id
            or existing.created_by != actor_id
            or original != authority
            or saved["bundle"] != bundle
        ):
            _refuse()
        return existing
    unfinished = db.query(BackupVerification).filter(
        BackupVerification.org_id == org_id,
        BackupVerification.verification_type == TYPE,
        BackupVerification.status.notin_(TERMINAL),
    )
    if unfinished.filter(BackupVerification.backup_id == backup_id).first() or (
        unfinished.filter(
            BackupVerification.verification_agent_id == vm.agent_id
        ).count()
        >= MAX_UNFINISHED_PER_AGENT
    ):
        _refuse()
    plan = {
        "schema": SCHEMA,
        "verification_id": verification_id,
        "org_id": org_id,
        "agent_id": vm.agent_id,
        "provider": vm.provider,
        "authority_sha256": digest(authority),
        "bundle": bundle,
    }
    body = canonical(plan)
    if len(body) > MAX_PLAN_BYTES:
        _refuse()
    record = BackupVerification(
        id=verification_id,
        org_id=org_id,
        backup_id=backup_id,
        created_by=actor_id,
        verification_type=TYPE,
        status="pending",
        result_message="Awaiting authenticated verification worker",
        verification_plan_canonical=body.decode(),
        verification_plan_sha256=digest(plan),
        verification_authority_canonical=canonical(authority).decode(),
        verification_agent_id=vm.agent_id,
        verification_cancel_requested=False,
        verification_read_attempts=0,
        verification_last_busy_attempt=0,
        verification_read_limit=3,
        verification_admission_budget=verification_admission_budget(bundle),
    )
    db.add(record)
    db.flush()
    return record


def readmit(db, record):
    plan, original = load_plan(record)
    if record.verification_cancel_requested or record.status in TERMINAL:
        _refuse()
    if _authority(db, record.org_id, record.created_by) != original:
        _refuse()
    bundle, vm = _bundle(db, record.backup_id, record.org_id)
    if bundle != plan["bundle"] or vm.agent_id != record.verification_agent_id:
        _refuse()
    return plan


def hydrate_request(db, record):
    from core.settings_service import SettingsService
    from core.storage_attempt_key import unwrap_retained_attempt_key

    plan = readmit(db, record)
    cfg = SettingsService(db).get_s3_config()
    target = plan["bundle"]["members"][0]["request"]["plan"]["target"]
    if (
        not cfg
        or not target["region"]
        or any(cfg.get(k) != target[k] for k in ("endpoint", "bucket", "region"))
        or not cfg.get("access_key")
        or not cfg.get("secret_key")
    ):
        _refuse()
    request = {
        "plan": deepcopy(plan),
        "s3": {
            k: cfg[k]
            for k in ("endpoint", "bucket", "region", "access_key", "secret_key")
        },
        "keys": {},
    }
    if cfg.get("session_token"):
        request["s3"]["session_token"] = cfg["session_token"]
    for member in plan["bundle"]["members"]:
        r = member["request"]
        claim = (
            db.query(S3Publication)
            .filter_by(
                id=r["reservation_id"],
                org_id=record.org_id,
                backup_id=r["backup_id"],
                kind="payload",
                state="published",
            )
            .one_or_none()
        )
        if claim is None:
            _refuse()
        dek = unwrap_retained_attempt_key(db, claim, r)
        if dek is not None:
            request["keys"][r["backup_id"]] = base64.b64encode(dek).decode("ascii")
    return request


def grant_readmission(db, record, actor_id):
    """Explicit original-operator resume may grant three more bounded reads."""
    if actor_id != record.created_by:
        _refuse()
    readmit(db, record)
    db.refresh(record, with_for_update=True)
    if verification_admission_exhausted(record) or record.result_message in {
        "operation_budget_exhausted",
        "operation_budget_exhausted_or_missing",
    }:
        raise StorageOwnershipError(
            "Verification admission budget exhausted; cancel this verification and explicitly request a new one"
        )
    if record.status != "held" or record.verification_cancel_requested:
        _refuse()
    if record.verification_read_attempts >= record.verification_read_limit:
        record.verification_read_limit += 3
    record.verification_next_poll_at = datetime.utcnow()


def expected_result(plan):
    members = plan["bundle"]["members"]
    return {
        "schema": RESULT_SCHEMA,
        "provider": plan["provider"],
        "org_id": plan["org_id"],
        "agent_id": plan["agent_id"],
        "vm_id": members[0]["request"]["plan"]["source"]["vm_id"],
        "members": [
            {
                "backup_id": m["request"]["backup_id"],
                "reservation_id": m["request"]["reservation_id"],
                "plan_sha256": m["request"]["plan_sha256"],
                "receipt_sha256": digest(m["receipt"]),
                "objects": len(m["receipt"]["objects"]),
            }
            for m in members
        ],
    }


def apply_progress(record, response):
    """Accept only exact authenticated worker output, never an arbitrary pass.

    First observation binds the original worker and requires a separate commit
    before passed can be recorded. The PG guard enforces that transaction split.
    """
    plan, _ = load_plan(record)
    try:
        if (
            not isinstance(response, dict)
            or set(response)
            != {
                "schema",
                "verification_id",
                "org_id",
                "agent_id",
                "plan_sha256",
                "worker_id",
                "status",
                "message",
                "result",
            }
            or response["schema"] != PROGRESS_SCHEMA
            or response["verification_id"] != record.id
            or response["org_id"] != record.org_id
            or response["agent_id"] != record.verification_agent_id
            or response["plan_sha256"] != record.verification_plan_sha256
            or not _id(response["worker_id"])
        ):
            _refuse()
        status = response["status"]
        messages = {
            "pending": {"awaiting_worker"},
            "running": {"reading_exact_artifacts", "cancellation_pending"},
            "held": {
                "readmission_required",
                "journal_unavailable",
                "operation_budget_exhausted",
                "operation_budget_exhausted_or_missing",
            },
            "failed": {"artifact_verification_failed"},
            "passed": {"artifact_bytes_verified"},
        }
        if status not in messages or response["message"] not in messages[status]:
            _refuse()
        if status == "passed":
            if canonical(response["result"]) != canonical(expected_result(plan)):
                _refuse()
        elif response["result"] is not None:
            _refuse()
        if (
            record.verification_worker_id
            and record.verification_worker_id != response["worker_id"]
        ):
            _refuse()
        if record.status == "cancelled":
            # A repeated authenticated quiescent observation is harmless, but
            # cancellation never turns into a successful scrub afterward.
            if status not in {"held", "failed", "passed"}:
                _refuse()
            return True
        if record.status in {"passed", "failed"}:
            if record.status != status or canonical(
                record.verification_result
            ) != canonical(response["result"]):
                _refuse()
            return True
        newly_bound = record.verification_worker_id is None
        if newly_bound:
            record.verification_worker_id = response["worker_id"]
            record.started_at = record.started_at or datetime.utcnow()
        if record.verification_cancel_requested:
            quiescent = status in {"held", "failed", "passed"}
            record.status, record.result_message = (
                "cancelled" if quiescent else "held",
                (
                    "Verification cancelled; reader stopped; no result accepted"
                    if quiescent
                    else "Verification cancellation awaiting reader stop"
                ),
            )
            record.verification_result = None
            if quiescent:
                record.completed_at = datetime.utcnow()
        elif newly_bound and status == "passed":
            record.status, record.result_message = (
                "running",
                "Original worker bound; awaiting durable result",
            )
        else:
            record.status = "running" if status in {"pending", "running"} else status
            record.result_message = response["message"]
            if status == "passed":
                record.verification_result = deepcopy(response["result"])
            if status in {"passed", "failed"}:
                record.completed_at = datetime.utcnow()
        return record.status in TERMINAL
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        _refuse()
