"""Durable libvirt local-job admission. No command, credential or provider I/O."""

from copy import deepcopy
import re
from types import SimpleNamespace
import uuid

from core.native_inventory import digest, exact, native_source_disks, refuse, validate
from core.storage_attempt_key import _credential
from core.storage_receipt_v2 import canonical
from models import S3Publication, User, BackupQueue, ScheduleOccurrence, SchedulerGrant

from core.native_manifest import FORMAT, bind_inventory


def _scheduler_parent(db, backup, parent):
    """Veto drift before native effects; original authority locks are already held."""
    if backup.authority_kind != "scheduler":
        return
    from core.scheduler_scope import compile_scope
    from core.scheduler_policy_decision import resolved_options

    queue = (
        db.query(BackupQueue)
        .filter_by(
            started_backup_id=backup.id,
            scheduler_occurrence_id=backup.scheduler_occurrence_id,
            vm_id=backup.vm_id,
        )
        .one_or_none()
    )
    grant = (
        db.query(SchedulerGrant)
        .join(ScheduleOccurrence, ScheduleOccurrence.grant_id == SchedulerGrant.id)
        .filter(
            ScheduleOccurrence.id == backup.scheduler_occurrence_id,
            ScheduleOccurrence.org_id == backup.org_id,
            SchedulerGrant.org_id == backup.org_id,
        )
        .one_or_none()
    )
    if queue is None or grant is None or queue.status != "claimed":
        refuse()
    try:
        options = resolved_options(
            compile_scope(grant.scope)["options"], queue.backup_decision, claimed=True
        )
    except ValueError:
        refuse()
    if (
        backup.backup_type != options["backup_type"]
        or queue.backup_type != options["backup_type"]
    ):
        refuse()
    if queue.backup_decision is not None and options["backup_type"] == "incremental":
        if (
            type(parent) is not dict
            or parent.get("generation_id") != queue.backup_decision["generation_id"]
        ):
            refuse()


def admit(db, backup_id):
    from core.scheduler_admission import lock_original_authority
    from core.scheduler_scope import ScopeRefused
    from core.backup_capacity import validate_reserved_capacity

    try:
        _, backup, vm, agent, _, _, _ = lock_original_authority(
            db, backup_id, callback=True
        )
    except ScopeRefused:
        refuse()
    validate_reserved_capacity(db, backup.id, uuid.UUID(str(backup.capacity_id)))
    # An organization scheduler is its own authority, never its enroller.
    actor = (
        db.get(User, backup.initiating_user_id) if backup.initiating_user_id else None
    )
    if (
        vm is None
        or vm.provider != "libvirt"
        or not vm.inventory_present
        or not vm.uuid
        or vm.vm_uid != vm.uuid
    ):
        refuse()
    try:
        if str(uuid.UUID(vm.uuid)) != vm.uuid:
            refuse()
    except (ValueError, TypeError):
        refuse()
    disks = native_source_disks(vm.disks)
    targets = {disk["target"] for disk in disks}
    exclusions = backup.exclude_disks
    if (
        type(exclusions) is not list
        or any(type(x) is not str for x in exclusions)
        or len(set(exclusions)) != len(exclusions)
        or not set(exclusions) < targets
    ):
        refuse()
    if any(d["format"] != "qcow2" for d in disks if d["target"] not in exclusions):
        refuse()
    source = dict(
        vm_id=vm.id,
        domain_uuid=vm.uuid,
        agent_id=agent.id,
        disks=disks,
        exclusions=sorted(exclusions),
        backup_type=backup.backup_type,
        parent_backup_id=backup.parent_backup_id,
    )
    return backup, actor, agent, source


def prepare_job(db, backup_id):
    """Persist before any local native job. Reopen returns original attempt only.

    Only the current accepted native generation can supply an incremental
    parent. Other clients need not share a lock or mutation authority.
    """
    try:
        from core.settings_service import SettingsService
        from core.storage_dispatch import read_target
        from core.storage_encryption import select_encryption

        backup, actor, agent, source = admit(db, backup_id)
        if source["backup_type"] not in {"full", "incremental"}:
            refuse()
        parent = push_parent = None
        if source["backup_type"] == "incremental":
            from core.native_lineage import select_parent

            parent, push_parent = select_parent(db, backup, source)
        elif source["parent_backup_id"] is not None:
            refuse()
        _scheduler_parent(db, backup, parent)
        target = read_target(SettingsService(db))
        if (
            target["capability_profile"] != "db-rooted-consumer-verified/1"
            or not target["region"]
        ):
            refuse()
        encryption = select_encryption(
            db, backup, read_only=backup.native_job_intent is not None
        )
        if backup.native_job_intent is None:
            attempt = str(uuid.uuid4())
            backup.native_job_intent = dict(
                schema=1,
                org_id=backup.org_id,
                actor_id=actor.id if actor else None,
                backup_id=backup.id,
                agent_id=agent.id,
                attempt_id=attempt,
                job_id="vnbui-native-" + attempt,
                checkpoint="vnbui-" + attempt,
                producer=FORMAT,
                parent=parent,
                push_parent=push_parent,
                target=deepcopy(target),
                encryption=deepcopy(encryption),
                source=source,
            )
        elif (
            backup.native_job_intent["source"] != source
            or backup.native_job_intent.get("actor_id") != (actor.id if actor else None)
            or backup.native_job_intent.get("checkpoint")
            != "vnbui-" + backup.native_job_intent.get("attempt_id", "")
            or backup.native_job_intent.get("producer") != FORMAT
            or backup.native_job_intent.get("parent") != parent
            or backup.native_job_intent.get("push_parent") != push_parent
            or backup.native_job_intent.get("target") != target
            or backup.native_job_intent.get("encryption") != encryption
        ):
            refuse()
        result = deepcopy(backup.native_job_intent)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise


def readmit_job(db, backup_id, expected_intent):
    """Readmit the original native attempt only; never allocate or replace it.

    Called before a queued/recovered producer mutates the VM and by explicit
    recovery. Existing storage custody additionally pins target/key identity.
    The caller owns commit/rollback and authenticated transport admission.
    """
    from core.settings_service import SettingsService
    from core.storage_dispatch import read_target
    from core.storage_encryption import select_encryption

    backup, actor, agent, source = admit(db, backup_id)
    intent = backup.native_job_intent
    if (
        not intent
        or not backup.native_job_transaction_id
        or intent != expected_intent
        or intent.get("source") != source
        or intent.get("actor_id") != (actor.id if actor else None)
        or intent.get("agent_id") != agent.id
        or intent.get("producer") != FORMAT
        or intent.get("checkpoint") != "vnbui-" + intent.get("attempt_id", "")
    ):
        refuse()
    target = read_target(SettingsService(db))
    if (
        target["capability_profile"] != "db-rooted-consumer-verified/1"
        or not target["region"]
    ):
        refuse()
    encryption = select_encryption(
        db,
        SimpleNamespace(
            org_id=backup.org_id, encryption_key_id=backup.encryption_key_id
        ),
    )
    if intent.get("target") != target or intent.get("encryption") != encryption:
        refuse()
    if source["backup_type"] == "incremental":
        from core.native_lineage import select_parent

        parent, push = select_parent(db, backup, source)
        if intent.get("parent") != parent or intent.get("push_parent") != push:
            refuse()
    elif (
        source["backup_type"] != "full"
        or intent.get("parent") is not None
        or intent.get("push_parent") is not None
    ):
        refuse()
    _scheduler_parent(db, backup, intent.get("parent"))
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup.id, kind="payload")
        .one_or_none()
    )
    if claim is not None:
        from core.native_storage_plan import commit_native_source_plan

        if not claim.dispatch_token or (claim.expected_plan or {}).get("schema") != 3:
            refuse()
        plan = claim.expected_plan["transaction"]["plan"]
        if plan["encryption"] != encryption:
            refuse()
        commit_native_source_plan(
            db, backup.id, target, revalidate_token=claim.dispatch_token
        )
    return deepcopy(intent)


def admit_producer(db, backup_id, agent_id, value, credential):
    """Authenticated exact-intent re-admission immediately before local effect."""
    try:
        exact(value, {"attempt_id", "intent_sha256", "producer_request_sha256"})
        backup, _, agent, _ = admit(db, backup_id)
        _credential(db, agent_id, credential)
        intent = backup.native_job_intent
        if (
            agent.id != agent_id
            or not intent
            or value["attempt_id"] != intent["attempt_id"]
            or value["intent_sha256"] != digest(intent)
            or type(value["producer_request_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value["producer_request_sha256"]) is None
        ):
            refuse()
        readmit_job(db, backup_id, intent)
        bind_execution(backup, value)
        db.flush()
        db.refresh(backup, ["native_execution"])
        bound = backup.native_execution
        if (
            type(bound) is not dict
            or type(bound.get("bound_xid")) is not int
            or bound["bound_xid"] <= 0
        ):
            refuse()
        db.commit()
        return dict(**value, admitted=True)
    except Exception:
        db.rollback()
        raise


def bind_execution(backup, value):
    """No new execution namespace from lost local custody or changed output path."""
    expected = dict(
        schema=1,
        state="bound",
        request_sha256=value["producer_request_sha256"],
        intent_sha256=value["intent_sha256"],
        intent_canonical=canonical(backup.native_job_intent).decode(),
    )
    existing = backup.native_execution
    if existing is not None and type(existing) is not dict:
        refuse()
    if existing is not None and existing.get("state") == "preexisting":
        if (
            set(existing) != {"schema", "state", "boundary_xid"}
            or existing["schema"] != 1
            or type(existing.get("boundary_xid")) is not int
            or type(backup.native_job_transaction_id) is not int
            or backup.native_job_transaction_id <= existing["boundary_xid"]
        ):
            refuse()
    elif existing is not None:
        if (
            type(existing) is not dict
            or set(existing) != set(expected) | {"bound_xid"}
            or type(existing.get("bound_xid")) is not int
            or existing["bound_xid"] <= 0
            or {k: v for k, v in existing.items() if k != "bound_xid"} != expected
        ):
            refuse()
        return
    backup.native_execution = expected


def validate_closed_job(closed, intent):
    """Sealed attests terminal producer custody, exited observes OS exit zero."""
    exact(closed, {"job_id", "attempt_id", "invocation_id", "exit_code", "state"})
    if (
        closed["job_id"] != intent["job_id"]
        or closed["attempt_id"] != intent["attempt_id"]
        or type(closed["state"]) is not str
        or closed["state"] not in {"exited", "sealed"}
        # The legacy exit_code field is reserved zero for sealed custody.
        or type(closed["exit_code"]) is not int
        or closed["exit_code"] != 0
        or type(closed["invocation_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", closed["invocation_id"]) is None
    ):
        refuse()


def accept_inventory(db, backup_id, agent_id, value, credential):
    """Authentic agent attestation, not independent host or payload verification."""
    try:
        backup, actor, agent, source = admit(db, backup_id)
        _credential(db, agent.id, credential)
        intent = backup.native_job_intent
        if (
            not intent
            or not backup.native_job_transaction_id
            or agent.id != agent_id
            or intent["source"] != source
            or intent["actor_id"] != (actor.id if actor else None)
            or intent.get("checkpoint") != "vnbui-" + intent["attempt_id"]
            or intent.get("producer") != FORMAT
        ):
            refuse()
        exact(value, {"intent_sha256", "inventory", "closed_job", "push_result"})
        inventory = validate(value["inventory"])
        if value["intent_sha256"] != digest(intent):
            refuse()
        for key in ("backup_id", "attempt_id", "job_id", "checkpoint"):
            if inventory[key] != intent[key]:
                refuse()
        if inventory["domain_uuid"] != source["domain_uuid"]:
            refuse()
        # The source-bound target ID is explicit, not inferred from file paths.
        expected = [
            dict(id=d["target"], target=d["target"], bus=d["bus"], serial="")
            for d in source["disks"]
            if d["target"] not in source["exclusions"]
        ]
        if inventory["disks"] != expected:
            refuse()
        bind_inventory(value["push_result"], inventory, intent)
        closed = value["closed_job"]
        validate_closed_job(closed, intent)
        saved = dict(
            inventory=deepcopy(inventory),
            closed_job=deepcopy(closed),
            intent_sha256=digest(intent),
            inventory_sha256=digest(inventory),
            push_result=deepcopy(value["push_result"]),
            push_manifest_canonical=canonical(value["push_result"]["manifest"]).decode(
                "utf-8"
            ),
        )
        if backup.native_inventory is not None and backup.native_inventory != saved:
            refuse()
        backup.native_inventory = saved
        result = dict(
            accepted=True,
            inventory_sha256=saved["inventory_sha256"],
            attempt_id=intent["attempt_id"],
            completed=False,
        )
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
