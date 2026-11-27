"""Retain exact local signed ancestry while an admitted restore can read it."""

from core.recovery_evidence import accepted_evidence
from core.recovery_signing import (
    RecoveryUnavailable,
    installation_id,
    verify_point_envelope,
)
from core.s3_ownership import StorageOwnershipError
from models import (
    Backup,
    Organization,
    RecoveryPublication,
    StorageLineageGeneration,
    VM,
)


def check_recovery_source_scope(db, org_id, source):
    """Permit foreign installations, while local points stay in their source organization."""
    try:
        local_installation = installation_id(db)
    except RecoveryUnavailable:
        raise StorageOwnershipError(
            "Recovery installation identity is unavailable"
        ) from None
    if source["installation_id"] != local_installation:
        return False
    if source["org_id"] != org_id:
        raise StorageOwnershipError(
            "Use the original organization to recover a point from this installation"
        )
    return True


def retain_local_recovery_chain(db, org_id, trust, point, bundle):
    """Lock local custody before the caller atomically records an active hold."""

    def refuse():
        raise StorageOwnershipError("The local signed recovery chain is unavailable")

    if not check_recovery_source_scope(db, org_id, point):
        return []

    # Use the same order as accepted-object deletion. The organization lock
    # bridges the existence check through the commit of the active restore.
    org = (
        db.query(Organization)
        .filter_by(id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if org is None or not org.enabled:
        refuse()
    selected = (
        db.query(StorageLineageGeneration)
        .filter_by(
            id=point["generation_id"],
            org_id=org_id,
            backup_id=point["backup_id"],
            state="accepted",
        )
        .one_or_none()
    )
    if selected is None or (
        db.query(VM.id)
        .filter_by(id=selected.vm_id, org_id=org_id)
        .with_for_update()
        .one_or_none()
        is None
    ):
        refuse()
    backup_ids = [member["request"]["backup_id"] for member in bundle["members"]]
    rows = (
        db.query(Backup)
        .filter(
            Backup.org_id == org_id,
            Backup.vm_id == selected.vm_id,
            Backup.id.in_(backup_ids),
        )
        .order_by(Backup.id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    if len(rows) != len(backup_ids) or any(row.status != "completed" for row in rows):
        refuse()
    record = (
        db.query(RecoveryPublication)
        .filter_by(
            generation_id=selected.id, org_id=org_id, backup_id=selected.backup_id
        )
        .one_or_none()
    )
    if record is None or record.envelope is None:
        refuse()
    try:
        proof = accepted_evidence(db, org_id, selected.backup_id)
        if (
            verify_point_envelope(record.envelope.encode("ascii"), trust) != point
            or {**proof.point, "name": point["name"]} != point
        ):
            refuse()
    except RecoveryUnavailable:
        refuse()
    return backup_ids
