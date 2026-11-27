"""Retryable deletion of accepted transaction objects, never a bucket prefix.

The catalog remains as a tombstone. The committed deleting state fences new
restore/parent selection before provider IO; receipts remain the exact authority
for a retry after an interrupted delete.
"""

from datetime import datetime, timezone
import hashlib
from types import SimpleNamespace

from sqlalchemy import func, or_

from core.legacy_recovery import LEGACY_RECOVERY_REFUSAL, legacy_s3_unverified
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import validate, canonical
from models import (
    Backup,
    Organization,
    Restore,
    S3Publication,
    StorageLineageGeneration,
    VM,
)

ACTIVE_RESTORES = ("pending", "dispatching", "running", "cleanup_required")


def is_transaction_backup(db, backup):
    return (
        db.query(StorageLineageGeneration.id)
        .filter_by(org_id=backup.org_id, backup_id=backup.id)
        .first()
        is not None
    )


def _locked_plan(db, backup_id):
    from core.backup_deletion import BackupDependencyError

    initial = db.query(Backup).filter_by(id=backup_id).one_or_none()
    if initial is None:
        raise StorageOwnershipError("Backup is unavailable")
    org = (
        db.query(Organization)
        .filter_by(id=initial.org_id)
        .populate_existing()
        .with_for_update()
        .one()
    )
    db.query(VM).filter_by(
        id=initial.vm_id, org_id=org.id
    ).populate_existing().with_for_update().one()
    backup = (
        db.query(Backup)
        .filter_by(id=backup_id, org_id=org.id)
        .populate_existing()
        .with_for_update()
        .one()
    )
    if legacy_s3_unverified(backup):
        raise BackupDependencyError(LEGACY_RECOVERY_REFUSAL)
    if (
        not org.enabled
        or backup.capacity_state != "released"
        or backup.status not in ("completed", "deleting", "deleted")
    ):
        raise StorageOwnershipError(
            "Only an accepted completed backup can be deleted; active or uncertain custody is retained"
        )
    if backup.status == "deleted":
        return backup, None, None, []
    # Conservative source fence covers descendants selected but not yet
    # checkpointed, uncertain attempts whose chain metadata may not exist yet,
    # and restores whose worker may be reading any ancestor. A failed status
    # does not settle a still-reserved capacity claim.
    if (
        db.query(Backup.id)
        .filter(
            Backup.org_id == org.id,
            Backup.vm_id == backup.vm_id,
            Backup.id != backup.id,
            or_(
                Backup.status.in_(
                    (
                        "pending",
                        "running",
                        "uploading",
                        "upload_failed",
                        "cleanup_required",
                    )
                ),
                Backup.capacity_state.in_(("reserved", "legacy_held")),
            ),
        )
        .first()
    ):
        raise BackupDependencyError(
            "An active or uncertain backup still owns this VM's chain"
        )
    if (
        db.query(Restore.id)
        .join(Backup, Restore.backup_id == Backup.id)
        .filter(
            Restore.org_id == org.id,
            Backup.vm_id == backup.vm_id,
            Restore.status.in_(ACTIVE_RESTORES),
        )
        .first()
    ):
        raise BackupDependencyError(
            "An active or uncertain restore still needs this VM's chain"
        )
    recovery_holds = db.query(Restore.id).filter(
        Restore.org_id == org.id,
        Restore.status.in_(ACTIVE_RESTORES),
        Restore.s3_recovery.is_not(None),
    )
    if db.get_bind().dialect.name == "postgresql":
        recovery_holds = recovery_holds.filter(
            Restore.s3_recovery.contains({"local_chain": [backup.id]})
        )
    else:
        members = func.json_each(Restore.s3_recovery, "$.local_chain").table_valued(
            "value", joins_implicitly=True
        )
        recovery_holds = recovery_holds.filter(members.c.value == backup.id)
    if recovery_holds.first():
        raise BackupDependencyError(
            "An active or uncertain signed recovery still needs this backup"
        )
    if backup.chain_id and backup.chain_position is not None:
        if (
            db.query(Backup.id)
            .filter(
                Backup.org_id == org.id,
                Backup.chain_id == backup.chain_id,
                Backup.id != backup.id,
                Backup.chain_position > backup.chain_position,
                Backup.status != "deleted",
                or_(
                    Backup.native_no_effect.is_(None),
                    Backup.status != "failed",
                    Backup.capacity_state != "released",
                ),
            )
            .first()
        ):
            raise BackupDependencyError(
                "Delete retained chain descendants before their parent"
            )
    generation = (
        db.query(StorageLineageGeneration)
        .filter_by(org_id=org.id, backup_id=backup.id, state="accepted")
        .one()
    )
    claims = (
        db.query(S3Publication)
        .filter_by(org_id=org.id, backup_id=backup.id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    payload = next((c for c in claims if c.kind == "payload"), None)
    manifest = next(
        (c for c in claims if c.id == generation.id and c.kind == "chain_manifest"),
        None,
    )
    if (
        len(claims) != 2
        or payload is None
        or manifest is None
        or any(c.state != "published" for c in claims)
    ):
        raise StorageOwnershipError("Exact published transaction receipts are required")
    view = SimpleNamespace(
        id=payload.id,
        backup_id=backup.id,
        org_id=org.id,
        endpoint=payload.endpoint,
        bucket=payload.bucket,
        state="reserved",
        dispatch_token=payload.dispatch_token,
        expected_plan=payload.expected_plan,
    )
    request, receipt, receipt_hash = validate(view, payload.prepared_receipt["receipt"])
    if (
        request != generation.accepted_request
        or receipt_hash != generation.receipt_sha256
        or receipt_hash != payload.prepared_receipt.get("receipt_sha256")
        or manifest.prepared_receipt.get("receipt_sha256")
        != generation.manifest_receipt_sha256
        or manifest.expected_plan.get("schema") != 4
    ):
        raise StorageOwnershipError(
            "Accepted generation differs from deletion receipts"
        )
    objects = [
        dict(key=item["key"], etag=item["etag"], version_id=item["version_id"])
        for item in receipt["objects"]
    ]
    m = manifest.prepared_receipt["receipt"]
    if (
        m.get("key") != manifest.object_key
        or m.get("bucket") != payload.bucket
        or m.get("endpoint") != payload.endpoint
        or m.get("generation_id") != generation.id
        or hashlib.sha256(canonical(m)).hexdigest()
        != generation.manifest_receipt_sha256
        or payload.prepared_receipt.get("response", {}).get("accepted") is not True
    ):
        raise StorageOwnershipError("Generation object receipt is unavailable")
    # Withdraw the exact generation before removing any payload version. Signed
    # records remain immutable and discovery can observe the withdrawal.
    objects.insert(0, dict(key=m["key"], etag=m["etag"], version_id=m["version_id"]))
    return backup, payload, request["plan"]["target"], objects


def _require_immutable_versions(objects):
    if any(
        not isinstance(item.get("version_id"), str)
        or item["version_id"] in {"", "null"}
        for item in objects
    ):
        raise StorageOwnershipError(
            "Immutable S3 version IDs are required for safe deletion; enable bucket "
            "versioning for new backups. Retained unversioned backups remain readable."
        )


def _delete_object(client, bucket, item):
    from botocore.exceptions import ClientError

    _require_immutable_versions([item])
    args = dict(Bucket=bucket, Key=item["key"], IfMatch=item["etag"])
    if item["version_id"] is not None:
        args["VersionId"] = item["version_id"]
    try:
        client.delete_object(**args)
    except ClientError as exc:
        if str(exc.response.get("Error", {}).get("Code")) not in {
            "NoSuchKey",
            "NoSuchVersion",
            "404",
        }:
            raise
    # A lost delete ACK can retry the same version/ETag. Explicit absence after
    # the call establishes deletion; a replacement with different ETag is not
    # deleted and is not treated as the accepted object.
    head = {k: v for k, v in args.items() if k != "IfMatch"}
    try:
        client.head_object(**head)
    except ClientError as exc:
        if str(exc.response.get("Error", {}).get("Code")) in {
            "NoSuchKey",
            "NoSuchVersion",
            "404",
        }:
            return
        raise
    raise StorageOwnershipError(
        "Object still exists after conditional deletion; retain deletion custody"
    )


def delete_transaction_payload(db, backup_id, *, client=None):
    """Synchronous bounded provider calls; caller retains the immutable catalog."""
    owned_client = None
    backup, claim, target, objects = _locked_plan(db, backup_id)
    if backup.status == "deleted":
        db.rollback()
        return 0
    _require_immutable_versions(objects)
    if client is None:
        from core.storage_transaction import _recorded_target_client

        owned_client = _recorded_target_client(db, claim)
        client = owned_client
    try:
        backup.status = "deleting"
        backup.tags = dict(
            backup.tags or {}, storage_deletion={"schema": 1, "state": "deleting"}
        )
        db.commit()
        for item in objects:
            _delete_object(client, target["bucket"], item)
        backup, _, _, _ = _locked_plan(db, backup_id)
        backup.status = "deleted"
        backup.tags = dict(
            backup.tags or {},
            storage_deletion={
                "schema": 1,
                "state": "deleted",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        backup.tags.pop("deletion_error", None)
        backup.tags.pop("deletion_failed_at", None)
        db.commit()
        return backup.size_bytes or 0
    except BaseException:
        db.rollback()
        raise
    finally:
        if owned_client is not None:
            owned_client.close()
