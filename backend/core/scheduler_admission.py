"""Original owner-bound dispatch/callback admission for scheduled backups.

These primitives return custody only. The connected dispatcher owns its separate
acknowledged send continuation. Caller owns commit/rollback.
"""

from copy import deepcopy
import json
from sqlalchemy import text
from models import (
    Organization,
    OrganizationDefault,
    User,
    Schedule,
    SchedulerGrant,
    ScheduleOccurrence,
    ScheduleOccurrenceMember,
    Backup,
    BackupQueue,
    VM,
    Agent,
    S3Publication,
)
from core.backup_authority import read_authority, HumanAuthority
from core.scheduler_scope import compile_scope, digest, refuse, source_member
from core.scheduler_occurrence import observed_scope
from core.scheduler_policy_decision import resolved_options
from core.tenant_context import identity, commercial_mode

MAX_ORDER = 2**63 - 1


def _locked(db, model, **fields):
    value = (
        db.query(model)
        .filter_by(**fields)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if value is None:
        refuse("binding_unavailable")
    return value


def lock_original_authority(db, backup_id, *, callback=False):
    """Ordered authority/source locks; callback effects may continue uploading.

    Allocation and dispatch retain pending/running admission. Callback admission
    is operation-specific and still requires original live authority and source.
    """
    org_id, actor_id, platform = identity()
    if platform or not org_id or db.new or db.dirty or db.deleted:
        refuse("clean_tenant_transaction_required")
    if not commercial_mode():
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None or org_id not in ("default", assignment.org_id):
            refuse("organization_unavailable")
        org_id = assignment.org_id
    org = _locked(db, Organization, id=org_id)
    if not org.enabled:
        refuse("organization_fenced")
    # Preliminary reads discover lock IDs only. Every binding is checked again
    # after the corresponding ordered lock; ORM cached state is never evidence.
    candidate = (
        db.query(Backup)
        .filter_by(id=backup_id, org_id=org_id)
        .populate_existing()
        .one_or_none()
    )
    if candidate is None:
        refuse()
    authority = read_authority(candidate)
    schedule = grant = occurrence = member = None
    if isinstance(authority, HumanAuthority):
        user = _locked(db, User, id=authority.user_id, org_id=org_id)
        if (
            not user.is_active
            or user.role not in ("admin", "operator")
            or actor_id not in (None, user.id)
        ):
            refuse("human_authority_unavailable")
    else:
        if actor_id is not None:
            refuse("scheduler_context_must_not_impersonate")
        initial = (
            db.query(ScheduleOccurrence)
            .filter_by(id=authority.occurrence_id, org_id=org_id)
            .one_or_none()
        )
        if initial is None:
            refuse()
        schedule = _locked(db, Schedule, id=initial.schedule_id, org_id=org_id)
        grant = _locked(db, SchedulerGrant, id=initial.grant_id, org_id=org_id)
        occurrence = (
            db.query(ScheduleOccurrence)
            .filter_by(id=initial.id, org_id=org_id)
            .populate_existing()
            .one()
        )
        # Occurrences/members are immutable and SELECT-only for runtime. Do not
        # require FOR UPDATE, which would widen their current privilege contract.
        if (
            schedule.retired_at is not None
            or schedule.current_grant_id != grant.id
            or schedule.authority_revision != grant.schedule_revision
            or occurrence.schedule_revision != grant.schedule_revision
            or grant.schedule_id != schedule.id
            or grant.state != "active"
            or grant.org_epoch != org.scheduler_epoch
        ):
            refuse("scheduler_fenced")
    if grant:
        queue = _locked(
            db,
            BackupQueue,
            started_backup_id=backup_id,
            scheduler_occurrence_id=occurrence.id,
            vm_id=candidate.vm_id,
        )
        if queue.status != "claimed" or queue.authority_kind != "scheduler":
            refuse("queue_not_claimed")
    backup = _locked(db, Backup, id=backup_id, org_id=org_id)
    states = ("pending", "running", "uploading") if callback else ("pending", "running")
    if read_authority(backup) != authority or backup.status not in states:
        refuse("original_authority_changed")
    # Inventory snapshots hold Agent before updating any VM. Taking these in
    # reverse order can deadlock a provider callback after partial upload.
    # This read discovers the lock ID only; recheck the binding under both locks.
    candidate_vm = (
        db.query(VM)
        .filter_by(id=backup.vm_id, org_id=org_id)
        .populate_existing()
        .one_or_none()
    )
    if candidate_vm is None:
        refuse("source_unavailable")
    agent_id = candidate_vm.agent_id
    agent = _locked(db, Agent, id=agent_id, org_id=org_id)
    vm = _locked(db, VM, id=backup.vm_id, org_id=org_id)
    if vm.agent_id != agent_id:
        refuse("source_unavailable")
    if not vm.inventory_present or agent.status != "online":
        refuse("source_unavailable")
    if grant:
        scope = compile_scope(grant.scope)
        if (
            digest(scope) != grant.scope_sha256
            or scope["org_id"] != org_id
            or scope["schedule_id"] != schedule.id
            or scope["revision"] != grant.schedule_revision
        ):
            refuse("scope_binding_unavailable")
        member = (
            db.query(ScheduleOccurrenceMember)
            .filter_by(occurrence_id=occurrence.id, vm_id=vm.id, org_id=org_id)
            .one_or_none()
        )
        selected = next((m for m in scope["members"] if m["vm_id"] == vm.id), None)
        live = source_member(vm)
        if (
            member is None
            or selected != live
            or member.source_snapshot != live
            or member.source_sha256 != digest(live)
        ):
            refuse("source_unavailable")
        observed = observed_scope(db, schedule, [vm])
        # Once committed, source loss holds that member, not unrelated members.
        observed["members"] = scope["members"]
        if observed != scope:
            refuse("scope_drift")
    return org, backup, vm, agent, schedule, grant, occurrence


def _binding(db, backup_id, token, request, *, callback=False):
    org, backup, vm, agent, schedule, grant, occurrence = lock_original_authority(
        db, backup_id, callback=callback
    )
    org_id = org.id
    claim = _locked(
        db, S3Publication, backup_id=backup.id, kind="payload", org_id=org_id
    )
    if (
        claim.state != "reserved"
        or not token
        or claim.dispatch_token != token
        or (claim.expected_plan or {}).get("transaction") != request
        or request.get("backup_id") != backup.id
        or request.get("org_id") != org_id
        or request.get("agent_id") != agent.id
        or request.get("reservation_id") != claim.id
        or (claim.prepared_receipt is not None and not callback)
    ):
        refuse("dispatch_binding_unavailable")
    from core.storage_wire import validate_transaction

    # Pydantic validation is additional protocol validation, not canonical coercion.
    validate_transaction(request)
    from core.storage_wire import plan_digest

    plan = request["plan"]
    if request["plan_sha256"] != plan_digest(plan):
        refuse("request_digest_mismatch")
    if grant:
        scope = compile_scope(grant.scope)
        queue = (
            db.query(BackupQueue)
            .filter_by(
                started_backup_id=backup.id,
                scheduler_occurrence_id=occurrence.id,
                vm_id=vm.id,
            )
            .one()
        )
        options = resolved_options(
            scope["options"], queue.backup_decision, claimed=True
        )
        if queue.backup_type != options["backup_type"]:
            refuse("decision_binding_unavailable")
        if (
            scope["options"]["backup_type"] == "automatic"
            and options["backup_type"] == "incremental"
        ):
            parent = plan.get("parent")
            if (
                not isinstance(parent, dict)
                or parent.get("generation_id") != queue.backup_decision["generation_id"]
            ):
                refuse("decision_parent_changed")
        live = source_member(vm)
        target = dict(plan["target"])
        target["prefix"] = target.pop("configuration_prefix")
        target["capability_profile"] = plan["capability_profile"]
        if (
            target != scope["target"]
            or plan["encryption"] != scope["encryption"]
            or plan["provider"] != live["provider"]
            or plan["backup_type"] != options["backup_type"]
            or sorted(plan["exclusions"]) != scope["options"]["exclude_disks"]
            or backup.retention_days != scope["options"]["retention_days"]
            or backup.workers != scope["options"]["workers"]
            or sorted(backup.exclude_disks or []) != scope["options"]["exclude_disks"]
        ):
            refuse("request_scope_drift")
    if (
        backup.backup_type != plan["backup_type"]
        or sorted(backup.exclude_disks or []) != plan["exclusions"]
    ):
        refuse("request_source_drift")
    _validate_source(backup, vm, agent, plan)
    return (
        org,
        claim,
        dict(
            schema=1,
            effect_kind="storage_dispatch",
            dispatch_token=token,
            backup_id=backup.id,
            reservation_id=claim.id,
            attempt_id=plan["attempt_id"],
            request_sha256=db.execute(
                text(
                    "SELECT encode(sha256(convert_to(CAST(:request AS jsonb)::text,'UTF8')),'hex')"
                ),
                {"request": json.dumps(request, allow_nan=False)},
            ).scalar_one(),
            authority_kind=backup.authority_kind,
            user_id=backup.initiating_user_id,
            occurrence_id=backup.scheduler_occurrence_id,
            grant_id=grant.id if grant else None,
            scope_sha256=grant.scope_sha256 if grant else None,
            org_epoch=org.scheduler_epoch,
        ),
    )


def record_dispatch_admission(db, backup_id, token, request):
    """Flush one immutable attachment; caller commits. No send permission returned."""
    org, claim, binding = _binding(db, backup_id, token, request)
    if claim.dispatch_admission is not None:
        prior = claim.dispatch_admission
        if {k: v for k, v in prior.items() if k != "admission_order"} != binding:
            refuse("conflicting_admission")
        return deepcopy(prior)
    if org.scheduler_order >= MAX_ORDER:
        refuse("admission_order_exhausted")
    claim.dispatch_admission = dict(binding, admission_order=org.scheduler_order + 1)
    db.flush()
    db.refresh(org)
    return deepcopy(claim.dispatch_admission)


def validate_same_intent(db, backup_id, token, request, *, callback=False):
    """Read-validate existing admission only, never mint or repeat a send right."""
    _, claim, binding = _binding(db, backup_id, token, request, callback=callback)
    prior = claim.dispatch_admission
    if (
        prior is None
        or {k: v for k, v in prior.items() if k != "admission_order"} != binding
    ):
        refuse("admission_unavailable")
    return deepcopy(prior)


def _validate_source(backup, vm, agent, plan):
    """Compare the validated request with current locked source evidence."""
    source = plan["source"]
    if (
        source["vm_id"] != vm.id
        or source["agent_id"] != agent.id
        or plan["provider"] != vm.provider
    ):
        refuse("request_source_drift")
    if vm.provider == "libvirt":
        from core.native_inventory import native_source_disks
        from core.s3_ownership import StorageOwnershipError

        try:
            disks = native_source_disks(vm.disks)
        except StorageOwnershipError:
            refuse("request_source_drift")
        intent = backup.native_job_intent
        if (
            (backup.native_inventory or {}).get("inventory") != source["inventory"]
            or intent is None
            or source["inventory"]["domain_uuid"] != vm.uuid
            or vm.vm_uid != vm.uuid
            or intent["source"]
            != dict(
                vm_id=vm.id,
                agent_id=agent.id,
                domain_uuid=vm.uuid,
                disks=disks,
                exclusions=sorted(backup.exclude_disks or []),
                backup_type=backup.backup_type,
                parent_backup_id=backup.parent_backup_id,
            )
        ):
            refuse("request_source_drift")
    else:
        expected, native = [], []
        for disk in vm.disks or []:
            persistent = disk.get("source_type") in {
                "persistentVolumeClaim",
                "dataVolume",
            }
            excluded = disk.get("target") in (backup.exclude_disks or [])
            if excluded and not persistent:
                continue
            if (
                disk.get("source_type") not in {"persistentVolumeClaim", "dataVolume"}
                or disk.get("backup_eligible") is not True
                or disk.get("pvc_namespace") != vm.namespace
            ):
                refuse("request_source_drift")
            native.append(
                dict(
                    name=disk.get("target"),
                    mapping=disk.get("mapping"),
                    **{
                        k: disk.get(k)
                        for k in (
                            "pvc_name",
                            "pvc_uid",
                            "pvc_resource_version",
                            "capacity_bytes",
                        )
                    }
                )
            )
            if not excluded:
                expected.append(native[-1])
        if source["schema"] == 2:
            if sorted(source["native_volumes"], key=lambda v: v["name"]) != sorted(
                native, key=lambda v: v["name"]
            ):
                refuse("request_source_drift")
        elif len(expected) != len(native):
            refuse("unsupported_native_disk_selection")
        if (
            source["vm_uid"] != vm.vm_uid
            or source["namespace"] != vm.namespace
            or source["vmi_uid"] != vm.vmi_uid
            or plan["vm_name"] != vm.name
            or sorted(source["volumes"], key=lambda v: v["name"])
            != sorted(expected, key=lambda v: v["name"])
        ):
            refuse("request_source_drift")
