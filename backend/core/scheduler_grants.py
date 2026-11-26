"""Organization-owned schedule enrollment and revocation.

The enrolling administrator is audit provenance, not the future run principal.
Changing an execution-affecting option detaches the grant and requires explicit
re-enrollment; disabling a schedule only pauses future occurrences.
"""

from datetime import datetime, timezone

from models import (
    Organization,
    OrganizationDefault,
    Schedule,
    SchedulerGrant,
    SchedulerPrincipal,
    User,
    VM,
    VMGroup,
)
from core.scheduler_scope import digest, refuse
from core.scheduler_occurrence import observed_scope
from core.tenant_context import identity


def _lock(db, model, **where):
    row = (
        db.query(model)
        .filter_by(**where)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if row is None:
        refuse("binding_unavailable")
    return row


def _actor(db, *, admin=False):
    org_id, actor_id, platform = identity()
    if platform or not actor_id:
        refuse("organization_administrator_required" if admin else "operator_required")
    actor = db.query(User).filter_by(id=actor_id).populate_existing().one_or_none()
    if (
        actor is None
        or not actor.is_active
        or actor.role not in (("admin",) if admin else ("admin", "operator"))
    ):
        refuse("organization_administrator_required" if admin else "operator_required")
    if org_id is None or org_id == "default":
        # OSS requests keep the tenant implicit. Compare against the persisted
        # installation assignment, never an arbitrary authenticated user's org.
        assignment = db.get(OrganizationDefault, "oss")
        if assignment is None or assignment.org_id != actor.org_id:
            refuse("foreign_organization")
    elif org_id != actor.org_id:
        refuse("foreign_organization")
    org = _lock(db, Organization, id=actor.org_id)
    actor = _lock(db, User, id=actor_id, org_id=org.id)
    if not actor.is_active or actor.role not in (
        ("admin",) if admin else ("admin", "operator")
    ):
        refuse("organization_administrator_required" if admin else "operator_required")
    if not org.enabled:
        refuse("organization_fenced")
    return org, actor


def scope_for_schedule(db, schedule):
    """Snapshot all current members; enrollment never resolves credentials."""
    if schedule.retired_at is not None:
        refuse("schedule_retired")
    if bool(schedule.vm_id) == bool(schedule.vm_group_id):
        refuse("membership_drift")
    if schedule.vm_id:
        members = (
            db.query(VM).filter_by(id=schedule.vm_id, org_id=schedule.org_id).all()
        )
    else:
        from core.group_rules import resolve_group_members

        group = (
            db.query(VMGroup)
            .filter_by(id=schedule.vm_group_id, org_id=schedule.org_id)
            .one_or_none()
        )
        if group is None:
            refuse("membership_drift")
        members = resolve_group_members(db, group)
    if not members or any(not vm.inventory_present for vm in members):
        refuse("source_unavailable")
    if any(vm.provider not in {"kubevirt", "libvirt"} for vm in members):
        refuse("unsupported_scheduled_provider")
    scope = observed_scope(db, schedule, members)
    if not scope["target"]["region"]:
        refuse("explicit_s3_region_required")
    if scope["target"]["capability_profile"] != "db-rooted-consumer-verified/1":
        refuse("unsupported_storage_profile")
    return scope


def preview_grant(db, schedule):
    scope = scope_for_schedule(db, schedule)
    return dict(
        scope=scope,
        scope_sha256=digest(scope),
        revision=schedule.authority_revision,
        current_grant_id=schedule.current_grant_id,
    )


def revoke_grant_flush(db, schedule, actor_id, reason):
    """Detach in the same transaction as an option edit or explicit revocation."""
    if schedule.current_grant_id:
        grant = _lock(
            db, SchedulerGrant, id=schedule.current_grant_id, org_id=schedule.org_id
        )
        if grant.state != "active":
            refuse("binding_conflict")
        grant.state = "revoked"
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revoked_by = actor_id
        grant.revoke_reason = reason
        # The PostgreSQL trigger owns the revoke order, never the application.
        schedule.current_grant_id = None
        db.flush()


def enroll_grant(
    db,
    schedule_id,
    *,
    request_id,
    expected_revision,
    scope_sha256,
    replace_grant_id=None,
    enable=True
):
    org, actor = _actor(db, admin=True)
    schedule = _lock(db, Schedule, id=schedule_id, org_id=org.id)
    prior = (
        db.query(SchedulerGrant)
        .filter_by(
            org_id=org.id, schedule_id=schedule.id, enrollment_request_id=request_id
        )
        .one_or_none()
    )
    if prior is not None:
        if (
            prior.scope_sha256 != scope_sha256
            or prior.schedule_revision != expected_revision
            or prior.enrolled_by != actor.id
            or prior.state != "active"
            or schedule.current_grant_id != prior.id
        ):
            refuse("enrollment_request_conflict")
        return prior
    if (
        schedule.authority_revision != expected_revision
        or schedule.current_grant_id != replace_grant_id
    ):
        refuse("schedule_changed")
    scope = scope_for_schedule(db, schedule)
    if digest(scope) != scope_sha256:
        refuse("scope_changed_preview_again")
    revoke_grant_flush(db, schedule, actor.id, "replaced_by_administrator")
    principal = (
        db.query(SchedulerPrincipal)
        .filter_by(org_id=org.id, schedule_id=schedule.id)
        .one_or_none()
    )
    if principal is None:
        principal = SchedulerPrincipal(org_id=org.id, schedule_id=schedule.id)
        db.add(principal)
        db.flush()
    grant = SchedulerGrant(
        org_id=org.id,
        principal_id=principal.id,
        schedule_id=schedule.id,
        schedule_revision=schedule.authority_revision,
        org_epoch=org.scheduler_epoch,
        scope=scope,
        scope_sha256=scope_sha256,
        enrolled_by=actor.id,
        enrollment_request_id=request_id,
        state="active",
    )
    db.add(grant)
    db.flush()
    schedule.current_grant_id = grant.id
    schedule.enabled = enable
    db.commit()
    db.refresh(grant)
    return grant


def require_current_grant(db, schedule):
    from core.backup_authority import schedule_authority_state

    grant = (
        db.get(SchedulerGrant, schedule.current_grant_id)
        if schedule.current_grant_id
        else None
    )
    org = db.get(Organization, schedule.org_id)
    if org is None or schedule_authority_state(schedule, grant, org) not in {
        "active",
        "paused",
    }:
        refuse("active_grant_required")
    if scope_for_schedule(db, schedule) != grant.scope:
        refuse("scope_changed_reenroll")
    return grant
