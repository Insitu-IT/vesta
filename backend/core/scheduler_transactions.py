"""Occurrence/claim transactions. No result alone confers effect authority.

Flush helpers do not commit. T1 owns a clean SERIALIZABLE transaction; connected
T2 plus capacity reservation uses READ COMMITTED. Neither retries ambiguous
commits. Capture the returned binding via
before_commit before committing, so a caller can compare it during custody lookup.
"""

from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import dataclass
from collections import Counter

from croniter import croniter
from sqlalchemy import text

from models import (
    Organization,
    OrganizationDefault,
    Schedule,
    SchedulerGrant,
    ScheduleOccurrence,
    ScheduleOccurrenceMember,
    BackupQueue,
    Backup,
    VM,
    Agent,
)
from core.tenant_context import identity, commercial_mode
from core.scheduler_scope import (
    compile_scope,
    digest,
    source_member,
    refuse,
    ScopeRefused,
)
from core.scheduler_occurrence import prepare_occurrence, observed_scope
from core.scheduler_admission import _locked, MAX_ORDER
from core.backup_service import BackupService
from core.scheduler_policy_decision import choose_for_claim, resolved_options

HOLD_REASONS = frozenset(
    {
        "source_unavailable",
        "authority_revoked",
        "organization_fenced",
        "scope_drift",
        "recovery_required",
        "commit_outcome_unknown",
    }
)


@dataclass(frozen=True)
class OccurrenceKey:
    org_id: str
    schedule_id: str
    revision: int
    scheduled_at: datetime
    grant_id: str
    scope_sha256: str
    org_epoch: int


@dataclass(frozen=True)
class ClaimBinding:
    queue_id: str
    claim_id: str | None
    claimed_at: datetime | None
    backup_id: str | None
    state: str


def _context(db):
    org, actor, platform = identity()
    if not org or actor is not None or platform or db.new or db.dirty or db.deleted:
        refuse("clean_scheduler_tenant_required")
    if not commercial_mode():
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None or org not in ("default", assignment.org_id):
            refuse("organization_unavailable")
        org = assignment.org_id
    return org


def _grant_scope(grant, key):
    scope = compile_scope(grant.scope)
    if (
        grant.id != key.grant_id
        or grant.org_id != key.org_id
        or grant.schedule_id != key.schedule_id
        or grant.schedule_revision != key.revision
        or grant.org_epoch != key.org_epoch
        or grant.scope_sha256 != key.scope_sha256
        or digest(scope) != key.scope_sha256
        or scope["org_id"] != key.org_id
        or scope["schedule_id"] != key.schedule_id
        or scope["revision"] != key.revision
    ):
        refuse("binding_conflict")
    return scope


def _authority(db, key):
    org = _locked(db, Organization, id=key.org_id)
    schedule = _locked(db, Schedule, id=key.schedule_id, org_id=key.org_id)
    grant = _locked(db, SchedulerGrant, id=key.grant_id, org_id=key.org_id)
    scope = _grant_scope(grant, key)
    if org.enabled is not True or org.scheduler_epoch != key.org_epoch:
        refuse("organization_fenced")
    if (
        grant.state != "active"
        or schedule.current_grant_id != grant.id
        or schedule.authority_revision != key.revision
        or schedule.retired_at is not None
    ):
        refuse("authority_revoked")
    return org, schedule, scope


def _occurrence(db, key):
    return (
        db.query(ScheduleOccurrence)
        .filter_by(
            org_id=key.org_id,
            schedule_id=key.schedule_id,
            schedule_revision=key.revision,
            scheduled_at=key.scheduled_at,
        )
        .populate_existing()
        .one_or_none()
    )


def lookup_custody(db, key, *, expected_claim=None):
    """Read exact original custody, including after fencing. No admission/locks."""
    if _context(db) != key.org_id:
        refuse("binding_conflict")
    grant = (
        db.query(SchedulerGrant)
        .filter_by(id=key.grant_id, org_id=key.org_id)
        .one_or_none()
    )
    if grant is None:
        refuse("binding_conflict")
    scope = _grant_scope(grant, key)
    occurrence = _occurrence(db, key)
    if occurrence is None:
        return None  # Absence is not a decision that an unknown transaction aborted.
    if occurrence.grant_id != grant.id or occurrence.construction_xid is None:
        refuse("binding_conflict")
    members = (
        db.query(ScheduleOccurrenceMember).filter_by(occurrence_id=occurrence.id).all()
    )
    queues = (
        db.query(BackupQueue).filter_by(scheduler_occurrence_id=occurrence.id).all()
    )
    expected = {m["vm_id"]: m for m in scope["members"]}
    if (
        {m.vm_id for m in members} != set(expected)
        or {q.vm_id for q in queues} != set(expected)
        or len(queues) != len(expected)
    ):
        refuse("binding_conflict")
    for m in members:
        if (
            m.org_id != key.org_id
            or m.source_snapshot != expected[m.vm_id]
            or m.source_sha256 != digest(m.source_snapshot)
        ):
            refuse("binding_conflict")
    bindings = []
    for q in queues:
        options = resolved_options(
            scope["options"], q.backup_decision, claimed=q.started_backup_id is not None
        )
        if (
            q.authority_kind != "scheduler"
            or q.initiating_user_id is not None
            or q.created_by is not None
            or q.schedule_id != key.schedule_id
            or any(getattr(q, name) != value for name, value in options.items())
        ):
            refuse("binding_conflict")
        binding = _claim_binding(q)
        if q.started_backup_id:
            b = db.get(Backup, q.started_backup_id, populate_existing=True)
            if (
                b is None
                or b.org_id != key.org_id
                or b.vm_id != q.vm_id
                or b.authority_kind != "scheduler"
                or b.initiating_user_id is not None
                or b.scheduler_occurrence_id != occurrence.id
                or any(getattr(b, name) != value for name, value in options.items())
            ):
                refuse("binding_conflict")
        bindings.append(binding)
    if expected_claim is not None:
        found = next(
            (b for b in bindings if b.queue_id == expected_claim.queue_id), None
        )
        if found is None or (found.claim_id, found.claimed_at, found.backup_id) != (
            expected_claim.claim_id,
            expected_claim.claimed_at,
            expected_claim.backup_id,
        ):
            refuse("binding_conflict")
    return dict(
        occurrence_id=occurrence.id,
        queues=tuple(bindings),
        total=len(expected),
        states=dict(Counter(b.state for b in bindings)),
        protected=False,
        disposition="custody_found",
    )


def construct_occurrence_flush(db, key):
    """T1 all members and queues, or none. Caller owns rollback and commit."""
    if _context(db) != key.org_id:
        refuse("binding_conflict")
    if db.execute(text("SHOW transaction_isolation")).scalar_one() != "serializable":
        refuse("serializable_transaction_required")
    # Duplicate observation remains possible after revocation, without admission.
    existing = lookup_custody(db, key)
    if existing is not None:
        return existing
    org, schedule, scope = _authority(db, key)
    if schedule.enabled is not True:
        refuse("schedule_disabled")
    instant = key.scheduled_at
    if (
        instant.tzinfo is None
        or instant.utcoffset() is None
        or instant.second
        or instant.microsecond
        or instant > datetime.now(timezone.utc)
        or not croniter.match(
            schedule.cron_expression, instant.astimezone(timezone.utc)
        )
    ):
        refuse("invalid_scheduled_instant")
    for m in scope["members"]:
        _locked(db, VM, id=m["vm_id"], org_id=key.org_id)
    prepare_occurrence(db, schedule, scope)
    if org.scheduler_order >= MAX_ORDER:
        refuse("admission_order_exhausted")
    occurrence = ScheduleOccurrence(
        org_id=key.org_id,
        schedule_id=key.schedule_id,
        schedule_revision=key.revision,
        grant_id=key.grant_id,
        scheduled_at=instant,
        admission_order=org.scheduler_order + 1,
    )
    db.add(occurrence)
    db.flush()
    db.refresh(occurrence)
    for m in scope["members"]:
        db.add(
            ScheduleOccurrenceMember(
                org_id=key.org_id,
                occurrence_id=occurrence.id,
                vm_id=m["vm_id"],
                source_snapshot=deepcopy(m),
                source_sha256=digest(m),
            )
        )
    db.flush()
    for m in scope["members"]:
        db.add(
            BackupQueue(
                authority_kind="scheduler",
                scheduler_occurrence_id=occurrence.id,
                vm_id=m["vm_id"],
                schedule_id=key.schedule_id,
                status="queued",
                initiating_user_id=None,
                created_by=None,
                tags=deepcopy(schedule.tags or {}),
                **resolved_options(scope["options"])
            )
        )
    db.flush()
    return lookup_custody(db, key)


def _claim_binding(q):
    return ClaimBinding(q.id, q.claim_id, q.claimed_at, q.started_backup_id, q.status)


def _queue(db, key, queue_id):
    occurrence = _occurrence(db, key)
    if occurrence is None or occurrence.grant_id != key.grant_id:
        refuse("binding_conflict")
    q = _locked(db, BackupQueue, id=queue_id, scheduler_occurrence_id=occurrence.id)
    if q.authority_kind != "scheduler" or q.initiating_user_id is not None:
        refuse("binding_conflict")
    return q


def hold_queue_flush(db, key, queue_id, reason):
    """Custody-only monotonic hold. Revocation is not a reason to lose custody."""
    if reason not in HOLD_REASONS or _context(db) != key.org_id:
        refuse("invalid_hold")
    _locked(db, Organization, id=key.org_id)
    _locked(db, Schedule, id=key.schedule_id, org_id=key.org_id)
    _locked(db, SchedulerGrant, id=key.grant_id, org_id=key.org_id)
    lookup_custody(db, key)
    q = _queue(db, key, queue_id)
    if q.started_backup_id:
        _locked(db, Backup, id=q.started_backup_id, org_id=key.org_id)
    q.status = "held_claimed" if q.claim_id is not None else "held_unclaimed"
    q.hold_reason = reason
    db.flush()
    return _claim_binding(q)


def claim_queue_flush(db, key, queue_id, *, reserve=False):
    """T2 durable preparation only. Never source-plan creation or execution."""
    if _context(db) != key.org_id:
        refuse("binding_conflict")
    required_isolation = "read committed" if reserve else "serializable"
    if (
        db.execute(text("SHOW transaction_isolation")).scalar_one()
        != required_isolation
    ):
        refuse("serializable_transaction_required")
    lookup_custody(db, key)
    try:
        _, schedule, scope = _authority(db, key)
    except ScopeRefused as error:
        if str(error) not in {"organization_fenced", "authority_revoked"}:
            raise
        return hold_queue_flush(db, key, queue_id, str(error))
    q = _queue(db, key, queue_id)
    if q.status in {"held_claimed", "held_unclaimed"}:
        return _claim_binding(q)
    if q.status == "claimed":
        # Another worker can have selected this row before the winner committed.
        # Observation grants no continuation, but must not fence that winner.
        # This is a return disposition only; persisted status remains claimed.
        return ClaimBinding(
            q.id, q.claim_id, q.claimed_at, q.started_backup_id, "already_claimed"
        )
    vm = _locked(db, VM, id=q.vm_id, org_id=key.org_id)
    agent = _locked(db, Agent, id=vm.agent_id, org_id=key.org_id)
    expected = next(m for m in scope["members"] if m["vm_id"] == vm.id)
    try:
        if agent.status != "online" or source_member(vm) != expected:
            refuse("source_unavailable")
        live = observed_scope(db, schedule, [vm])
        live["members"] = scope["members"]
        if live != scope:
            refuse("scope_drift")
    except ScopeRefused as error:
        reason = (
            "scope_drift"
            if str(error) != "source_unavailable"
            else "source_unavailable"
        )
        return hold_queue_flush(db, key, queue_id, reason)
    service = BackupService(db)
    allowed, admission_error, _ = service.can_start_backup(
        vm.id, check_concurrent=False
    )
    if not allowed:
        if type(admission_error) is dict and admission_error.get("code") in {
            "backup_admission_paused",
            "backup_admission_policy_unavailable",
        }:
            # No claim or reservation exists yet. Roll back this observation;
            # the original queued occurrence can be reconsidered after unpause.
            refuse(admission_error["code"])
        return hold_queue_flush(db, key, queue_id, "source_unavailable")
    decision = None
    kind = q.backup_type
    if kind == "automatic":
        today = db.execute(
            text("SELECT (clock_timestamp() AT TIME ZONE 'UTC')::date")
        ).scalar_one()
        decision = choose_for_claim(
            db,
            org_id=key.org_id,
            vm_id=vm.id,
            grant_id=key.grant_id,
            source_snapshot=expected,
            policy=scope["options"]["backup_policy"],
            today=today,
        )
        kind = decision["backup_type"]
    service._insert_backup_flush(
        vm,
        q.retention_days,
        kind,
        deepcopy(q.tags),
        deepcopy(q.exclude_disks),
        q.workers,
        "scheduler",
        None,
        q.scheduler_occurrence_id,
        q,
        scheduler_decision=decision,
    )
    q.status = "claimed"
    db.flush()
    if reserve:
        from core.storage_source import validate_native_disk_selection
        from models import Backup

        validate_native_disk_selection(
            db.get(Backup, q.started_backup_id), vm, agent, db=db
        )
        # The connected dispatcher claims and reserves under owner row locks in
        # READ COMMITTED, as required by installation-wide capacity accounting.
        # If capacity is
        # busy, the entire transaction rolls back and the original queue stays
        # queued, instead of stranding a permanently claimed, unreserved backup.
        db.execute(
            text(
                "UPDATE backups SET capacity_state='reserved' WHERE id=:id AND org_id=:org"
            ),
            {"id": q.started_backup_id, "org": key.org_id},
        )
    db.refresh(q)  # Server-generated UUID/time captured before commit.
    return _claim_binding(q)


def _transaction(factory, work, before_commit, *, isolation="SERIALIZABLE"):
    with factory() as db:
        if db.in_transaction():
            refuse("clean_transaction_required")
        db.connection(execution_options={"isolation_level": isolation})
        try:
            result = work(db)
            if before_commit is not None:
                before_commit(result)
            db.commit()
            return result
        except BaseException:
            db.rollback()
            raise  # A failed commit acknowledgement never becomes an automatic retry.


def create_occurrence(factory, key, *, before_commit=None):
    return _transaction(
        factory, lambda db: construct_occurrence_flush(db, key), before_commit
    )


def claim_queue(factory, key, queue_id, *, before_commit=None, reserve=False):
    return _transaction(
        factory,
        lambda db: claim_queue_flush(db, key, queue_id, reserve=reserve),
        before_commit,
        isolation="READ COMMITTED" if reserve else "SERIALIZABLE",
    )


def hold_queue(factory, key, queue_id, reason):
    return _transaction(
        factory, lambda db: hold_queue_flush(db, key, queue_id, reason), None
    )
