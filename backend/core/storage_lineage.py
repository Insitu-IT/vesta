"""D02 read/admission interface. No accepted-fact publication or backfill.

Caller holds the VM row lock throughout selection/final admission. Database
triggers acquire that same lock for all generation/head writes, including the
previously absent-head case. Runtime grants are SELECT only on both tables.
"""

from copy import deepcopy
import re

from core.legacy_recovery import legacy_s3_unverified
from core.s3_ownership import StorageOwnershipError
from core.storage_semantics import UUID, IDENTITY
from core.storage_wire import TransactionRequest
from models import Backup, StorageLineageGeneration, StorageLineageHead


def stable_source(source):
    value = deepcopy(source)
    # A VMI is one running incarnation of the same VM. The selected attempt
    # still fences its current VMI UID; lineage binds the stable VM/PVCs and
    # the accepted tracker/checkpoint across an ordinary restart.
    value.pop("vmi_uid", None)
    for key in ("volumes", "native_volumes"):
        if key in value:
            for volume in value[key]:
                volume.pop("pvc_resource_version", None)
            value[key] = sorted(value[key], key=lambda v: v["name"])
    return value


def select_parent(db, backup, vm, plan):
    """Select only explicit accepted current authority, never backup metadata."""

    def refuse():
        raise StorageOwnershipError("Accepted current incremental lineage unavailable")

    head = (
        db.query(StorageLineageHead)
        .filter_by(vm_id=vm.id, org_id=backup.org_id)
        .populate_existing()
        .one_or_none()
    )
    if head is None or head.state != "current":
        refuse()
    generation = (
        db.query(StorageLineageGeneration)
        .filter_by(id=head.generation_id, vm_id=vm.id, org_id=backup.org_id)
        .populate_existing()
        .one_or_none()
    )
    if generation is None or generation.state != "accepted":
        refuse()
    if any(
        getattr(head, key) != getattr(generation, key)
        for key in (
            "root_backup_id",
            "tracker_uid",
            "checkpoint",
            "manifest_receipt_sha256",
        )
    ):
        refuse()
    for value in (generation.id, generation.backup_id, generation.root_backup_id):
        if not UUID.fullmatch(value):
            refuse()
    for value in (
        generation.receipt_sha256,
        generation.root_receipt_sha256,
        generation.manifest_receipt_sha256,
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            refuse()
    if not IDENTITY.fullmatch(generation.tracker_uid) or not IDENTITY.fullmatch(
        generation.checkpoint
    ):
        refuse()
    if backup.id in (generation.backup_id, generation.root_backup_id):
        refuse()
    # Status can veto, never establish acceptance. No completed row can supply
    # a generation, root, receipt, tracker or checkpoint missing from this table.
    for backup_id in {generation.backup_id, generation.root_backup_id}:
        member = (
            db.query(Backup)
            .filter_by(id=backup_id, org_id=backup.org_id, vm_id=vm.id)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )
        if member is None or member.status != "completed":
            refuse()
    try:
        accepted = TransactionRequest.model_validate(
            generation.accepted_request
        ).model_dump()
    except (ValueError, TypeError):
        refuse()
    if (
        accepted["org_id"] != backup.org_id
        or accepted["agent_id"] != vm.agent_id
        or accepted["backup_id"] != generation.backup_id
        or stable_source(accepted["plan"]["source"]) != stable_source(plan["source"])
        or any(
            accepted["plan"][key] != plan[key]
            for key in (
                "provider",
                "vm_name",
                "target",
                "capability_profile",
                "encryption",
                "exclusions",
            )
        )
    ):
        refuse()
    # A selected generation must lead back to its exact accepted root, not just
    # to a completed Backup bearing the same ID. The bound refuses oversized or
    # cyclic ancestry; it never truncates a chain into an apparently valid one.
    cursor, request, seen = generation, accepted, set()
    for _ in range(256):
        if cursor.id in seen:
            refuse()
        seen.add(cursor.id)
        previous = request["plan"]["parent"]
        if previous is None:
            if (
                cursor.backup_id != generation.root_backup_id
                or cursor.receipt_sha256 != generation.root_receipt_sha256
            ):
                refuse()
            break
        ancestor = (
            db.query(StorageLineageGeneration)
            .filter_by(id=previous["generation_id"], vm_id=vm.id, org_id=backup.org_id)
            .populate_existing()
            .one_or_none()
        )
        if (
            ancestor is None
            or ancestor.state != "accepted"
            or any(
                getattr(ancestor, key) != previous[key]
                for key in (
                    "backup_id",
                    "root_backup_id",
                    "receipt_sha256",
                    "tracker_uid",
                    "checkpoint",
                )
            )
        ):
            refuse()
        if (
            ancestor.root_backup_id != generation.root_backup_id
            or ancestor.root_receipt_sha256 != generation.root_receipt_sha256
            or ancestor.tracker_uid != generation.tracker_uid
        ):
            refuse()
        if not re.fullmatch(r"[0-9a-f]{64}", ancestor.manifest_receipt_sha256):
            refuse()
        ancestor_backup = (
            db.query(Backup)
            .filter_by(id=ancestor.backup_id, org_id=backup.org_id, vm_id=vm.id)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )
        if (
            ancestor_backup is None
            or ancestor_backup.status != "completed"
            or legacy_s3_unverified(ancestor_backup)
        ):
            refuse()
        try:
            request = TransactionRequest.model_validate(
                ancestor.accepted_request
            ).model_dump()
        except (ValueError, TypeError):
            refuse()
        if (
            request["backup_id"] != ancestor.backup_id
            or request["org_id"] != backup.org_id
            or request["agent_id"] != vm.agent_id
            or stable_source(request["plan"]["source"]) != stable_source(plan["source"])
            or any(
                request["plan"][key] != plan[key]
                for key in (
                    "provider",
                    "vm_name",
                    "target",
                    "capability_profile",
                    "encryption",
                    "exclusions",
                )
            )
        ):
            refuse()
        cursor = ancestor
    else:
        refuse()
    return dict(
        backup_id=generation.backup_id,
        root_backup_id=generation.root_backup_id,
        receipt_sha256=generation.receipt_sha256,
        generation_id=generation.id,
        tracker_uid=generation.tracker_uid,
        checkpoint=generation.checkpoint,
    )
