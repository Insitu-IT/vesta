"""Non-writing occurrence preparation. No queue producer or activation switch."""

import os
from types import SimpleNamespace

from models import EncryptionKey, VMGroup
from core.scheduler_scope import (
    compile_scope,
    digest,
    refuse,
    source_member,
    validate_drift,
)


def configuration(schedule, group=None):
    return digest(
        dict(
            vm_id=schedule.vm_id,
            vm_group_id=schedule.vm_group_id,
            cron=schedule.cron_expression,
            tags=schedule.tags,
            group=(
                None
                if group is None
                else dict(
                    type=group.group_type, rules=group.rules, match=group.rules_match
                )
            ),
        )
    )


def encryption_selection(db, org_id):
    """Read identity only; never select encrypted material or mutate a Backup."""
    if os.getenv("ENABLE_ENCRYPTION", "false").lower() != "true":
        return dict(format="none", key_ref=None)
    from core.storage_encryption import FORMAT

    keys = (
        db.query(
            EncryptionKey.id,
            EncryptionKey.key_hash,
            EncryptionKey.algorithm,
            EncryptionKey.provider,
            EncryptionKey.provider_key_ref,
            EncryptionKey.encrypted_material.isnot(None).label("has_material"),
        )
        .filter_by(org_id=org_id, status="active")
        .all()
    )
    if len(keys) != 1:
        refuse("encryption_drift")
    key = keys[0]
    if (
        key.algorithm != "aes-256-gcm"
        or key.provider != "local"
        or key.provider_key_ref is not None
        or not key.has_material
    ):
        refuse("encryption_drift")
    return dict(format=FORMAT, key_ref=f"kek:{key.id}:{key.key_hash}")


def observed_scope(db, schedule, members):
    from core.storage_dispatch import read_target
    from core.settings_service import SettingsService

    group = None
    if schedule.vm_group_id:
        group = (
            db.query(VMGroup)
            .filter_by(id=schedule.vm_group_id, org_id=schedule.org_id)
            .one_or_none()
        )
        if group is None:
            refuse("membership_drift")
    if any(vm.org_id != schedule.org_id for vm in members):
        refuse("foreign_source")
    options = dict(
        backup_type=schedule.backup_type,
        retention_days=schedule.retention_days,
        exclude_disks=schedule.exclude_disks,
        workers=schedule.workers,
    )
    if schedule.backup_type == "automatic":
        options["backup_policy"] = schedule.backup_policy
    return compile_scope(
        dict(
            schema=1,
            org_id=schedule.org_id,
            schedule_id=schedule.id,
            revision=schedule.authority_revision,
            configuration_sha256=configuration(schedule, group),
            members=[source_member(vm) for vm in members],
            target=read_target(SettingsService(db)),
            encryption=encryption_selection(db, schedule.org_id),
            options=options,
        )
    )


def prepare_occurrence(db, schedule, enrolled):
    """Read-only whole-set validation; caller owns isolation, no admission is minted."""
    from models import VM
    from core.group_rules import resolve_group_members

    if db.new or db.dirty or db.deleted:
        refuse("clean_transaction_required")
    with db.no_autoflush:
        if bool(schedule.vm_id) == bool(schedule.vm_group_id):
            refuse("membership_drift")
        if schedule.vm_id:
            members = (
                db.query(VM).filter_by(id=schedule.vm_id, org_id=schedule.org_id).all()
            )
        else:
            group = (
                db.query(VMGroup)
                .filter_by(id=schedule.vm_group_id, org_id=schedule.org_id)
                .one_or_none()
            )
            if group is None:
                refuse("membership_drift")
            members = resolve_group_members(db, group)
        if not members or any(vm.inventory_present is not True for vm in members):
            refuse("membership_drift")
        scope = validate_drift(enrolled, observed_scope(db, schedule, members))
        return SimpleNamespace(
            scope=scope,
            scope_sha256=digest(scope),
            members=tuple(m["vm_id"] for m in scope["members"]),
        )
