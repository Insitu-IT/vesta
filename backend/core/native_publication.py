"""Publish an admitted native push only from its exact durable receipt ledger."""

from core.s3_ownership import StorageOwnershipError
from models import Backup, S3Publication


def admit(db, backup_id, agent_id, credential):
    from core.native_storage_plan import commit_native_source_plan
    from core.native_manifest import validate_receipt_binding
    from core.settings_service import SettingsService
    from core.storage_attempt_key import _credential
    from core.storage_dispatch import read_target
    from core.storage_wire import validate_transaction

    if db.new or db.dirty or db.deleted:
        raise StorageOwnershipError("Clean native publication transaction required")
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .one_or_none()
    )
    if claim is None or (claim.expected_plan or {}).get("schema") != 3:
        raise StorageOwnershipError("Native transaction unavailable")
    request = claim.expected_plan["transaction"]
    validate_transaction(request)
    if (
        request["plan"]["provider"] != "libvirt"
        or request["agent_id"] != agent_id
        or not claim.dispatch_token
    ):
        raise StorageOwnershipError("Native publication owner unavailable")
    admitted = commit_native_source_plan(
        db,
        backup_id,
        read_target(SettingsService(db)),
        revalidate_token=claim.dispatch_token,
    )
    _credential(db, agent_id, credential)
    saved = admitted.prepared_receipt
    if (
        admitted.id != claim.id
        or admitted.expected_plan["transaction"] != request
        or admitted.state != "reserved"
        or not saved
    ):
        raise StorageOwnershipError("Native receipt unavailable")
    if (
        saved.get("plan_sha256") != request["plan_sha256"]
        or saved.get("response", {}).get("accepted") is not True
    ):
        raise StorageOwnershipError("Native receipt unavailable")
    backup = db.get(Backup, backup_id)
    validate_receipt_binding(request, saved["receipt"], backup.native_inventory)
    return admitted, request, saved


def publish_native_backup(db, backup_id, agent_id, value, credential):
    """Exact acceptance replay is safe both before and after atomic completion."""
    from core.storage_attempt_key import _credential
    from core.storage_publication import publish_checkpointed_backup

    try:
        claim = (
            db.query(S3Publication)
            .filter_by(backup_id=backup_id, kind="payload")
            .one_or_none()
        )
        if (
            claim is None
            or (claim.expected_plan or {}).get("schema") != 3
            or not claim.prepared_receipt
        ):
            raise StorageOwnershipError("Native receipt unavailable")
        request, saved = claim.expected_plan["transaction"], claim.prepared_receipt
        if (
            request["plan"]["provider"] != "libvirt"
            or request["agent_id"] != agent_id
            or value
            != dict(
                reservation_id=claim.id,
                receipt_sha256=saved["receipt_sha256"],
                acceptance_id=saved["response"]["acceptance_id"],
            )
        ):
            raise StorageOwnershipError("Native acceptance binding differs")
        _credential(db, agent_id, credential)
        result = publish_checkpointed_backup(db, backup_id, agent_id, credential)
        return dict(
            reservation_id=claim.id,
            status=result["status"],
            completed=result["completed"],
        )
    except Exception:
        db.rollback()
        raise
