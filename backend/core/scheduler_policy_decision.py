"""Automatic claim decisions from accepted custody, never completed-row guesses.

Caller holds original organization/schedule/grant/VM locks until claim commit.
This selects a kind only; all normal capacity, dispatch and publication admission
still applies. A saved decision is read, never recomputed during custody lookup.
"""

from copy import deepcopy
from datetime import date, datetime, timezone

from core.scheduler_policy import BackupPolicyError, decide_automatic, validate_policy
from core.scheduler_scope import identifier
from core.s3_ownership import StorageOwnershipError
from core.storage_restore import build_restore_bundle
from models import (
    Backup,
    BackupQueue,
    ScheduleOccurrence,
    ScheduleOccurrenceMember,
    StorageLineageGeneration,
    StorageLineageHead,
)

EARLY_FULL = frozenset(
    {
        "parent_unavailable",
        "new_grant",
        "source_changed",
        "root_time_unavailable",
        "previous_failure",
    }
)


def validate_decision(value, policy):
    """One persisted shape; fixed-mode queues must not call this validator."""
    policy = validate_policy(policy)
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema",
            "policy",
            "backup_type",
            "reason",
            "observed_date",
            "generation_id",
            "root_backup_id",
            "root_date",
            "incremental_count",
        }
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or validate_policy(value["policy"]) != policy
    ):
        raise BackupPolicyError("invalid_saved_backup_decision")
    try:
        today = date.fromisoformat(value["observed_date"])
        if today.isoformat() != value["observed_date"]:
            raise ValueError()
        if value["reason"] in EARLY_FULL:
            if value["backup_type"] != "full" or any(
                value[key] is not None
                for key in (
                    "generation_id",
                    "root_backup_id",
                    "root_date",
                    "incremental_count",
                )
            ):
                raise ValueError()
        else:
            identifier(value["generation_id"])
            identifier(value["root_backup_id"])
            root = date.fromisoformat(value["root_date"])
            if root.isoformat() != value["root_date"]:
                raise ValueError()
            result = decide_automatic(
                policy,
                today=today,
                root_date=root,
                incremental_count=value["incremental_count"],
            )
            if any(value[key] != result[key] for key in ("backup_type", "reason")):
                raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise BackupPolicyError("invalid_saved_backup_decision") from None
    return deepcopy(value)


def resolved_options(options, decision=None, *, claimed=False):
    """Queue/Backup fields only; policy itself is sealed in the grant."""
    result = deepcopy(options)
    if result["backup_type"] != "automatic":
        if decision is not None:
            raise BackupPolicyError("decision_on_fixed_schedule")
        return result
    policy = result.pop("backup_policy")
    if claimed:
        result["backup_type"] = validate_decision(decision, policy)["backup_type"]
    elif decision is not None:
        raise BackupPolicyError("decision_on_unclaimed_queue")
    return result


def choose_for_claim(db, *, org_id, vm_id, grant_id, source_snapshot, policy, today):
    policy = validate_policy(policy)
    # Validate the observation even when no accepted parent exists.
    decide_automatic(policy, today=today)
    base = dict(
        schema=1,
        policy=policy,
        observed_date=today.isoformat(),
        generation_id=None,
        root_backup_id=None,
        root_date=None,
        incremental_count=None,
    )

    def full(reason):
        return validate_decision(dict(base, backup_type="full", reason=reason), policy)

    head = (
        db.query(StorageLineageHead)
        .filter_by(org_id=org_id, vm_id=vm_id)
        .populate_existing()
        .one_or_none()
    )
    if head is None or head.state != "current":
        return full("parent_unavailable")
    generation = (
        db.query(StorageLineageGeneration)
        .filter_by(id=head.generation_id, org_id=org_id, vm_id=vm_id, state="accepted")
        .populate_existing()
        .one_or_none()
    )
    if generation is None or any(
        getattr(head, key) != getattr(generation, key)
        for key in (
            "root_backup_id",
            "tracker_uid",
            "checkpoint",
            "manifest_receipt_sha256",
        )
    ):
        return full("parent_unavailable")
    try:
        bundle = build_restore_bundle(db, generation.backup_id, org_id)
    except StorageOwnershipError:
        # An invalid retained chain cannot authorize an incremental. It does not
        # release held attempts or change custody; a separately authorized full
        # must still reserve capacity and pass normal producer admission.
        return full("parent_unavailable")
    root = (
        db.query(Backup)
        .filter_by(id=generation.root_backup_id, vm_id=vm_id, org_id=org_id)
        .populate_existing()
        .one_or_none()
    )
    if root is None:
        return full("parent_unavailable")
    occurrence = (
        db.query(ScheduleOccurrence)
        .filter_by(id=root.scheduler_occurrence_id, org_id=org_id)
        .one_or_none()
    )
    if (
        root.authority_kind != "scheduler"
        or occurrence is None
        or occurrence.grant_id != grant_id
    ):
        return full("new_grant")
    member = (
        db.query(ScheduleOccurrenceMember)
        .filter_by(occurrence_id=occurrence.id, vm_id=vm_id, org_id=org_id)
        .one_or_none()
    )
    if member is None or member.source_snapshot != source_snapshot:
        return full("source_changed")
    root_queue = (
        db.query(BackupQueue)
        .filter_by(
            started_backup_id=root.id,
            vm_id=vm_id,
            scheduler_occurrence_id=occurrence.id,
        )
        .one_or_none()
    )
    # The database sets claim time and forbids replacing it. Backup.created_at
    # is presentation metadata, not the periodic-full clock authority.
    if root_queue is None or not isinstance(root_queue.claimed_at, datetime):
        return full("root_time_unavailable")
    root_date = (
        root_queue.claimed_at.replace(tzinfo=timezone.utc)
        if root_queue.claimed_at.tzinfo is None
        else root_queue.claimed_at.astimezone(timezone.utc)
    ).date()
    # Every member was validated by the accepted-bundle reader. Status/timestamps
    # can only force an earlier full, never establish or extend accepted lineage.
    selected = (
        db.query(Backup)
        .filter_by(id=generation.backup_id, org_id=org_id, vm_id=vm_id)
        .one()
    )
    if selected.created_at is None:
        return full("root_time_unavailable")
    failed = (
        db.query(Backup.id)
        .filter(
            Backup.org_id == org_id,
            Backup.vm_id == vm_id,
            Backup.status.in_(("failed", "cancelled")),
            Backup.capacity_state == "released",
            Backup.created_at > selected.created_at,
        )
        .first()
    )
    if failed is not None:
        return full("previous_failure")
    result = decide_automatic(
        policy,
        today=today,
        root_date=root_date,
        incremental_count=len(bundle["members"]) - 1,
    )
    return validate_decision(
        dict(
            base,
            **result,
            generation_id=generation.id,
            root_backup_id=root.id,
            root_date=root_date.isoformat(),
            incremental_count=len(bundle["members"]) - 1
        ),
        policy,
    )
