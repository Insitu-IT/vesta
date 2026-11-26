"""Durable prepared-receipt acceptance, separate from checkpoint publication.

The authenticated agent identity is supplied by the request dependency, never
by the receipt. Acknowledgement is returned only after committing acceptance.
This service performs no checkpoint finalization or manifest publication.
"""

from copy import deepcopy

from models import Backup, VM, S3Publication
from core.s3_ownership import StorageOwnershipError, storage_identity
from core.storage_receipt import validate_receipt, verify_stored_receipt


def _recorded_target_client(db, claim):
    """Credentials may rotate; their current target cannot redirect verification."""
    import boto3
    from botocore.config import Config
    from core.settings_service import SettingsService

    config = SettingsService(db).get_s3_config()
    if not config or storage_identity(config) != (claim.endpoint, claim.bucket):
        raise StorageOwnershipError("Recorded target credentials are unavailable")
    return boto3.client(
        "s3",
        endpoint_url=claim.endpoint,
        aws_access_key_id=config["access_key"],
        aws_secret_access_key=config["secret_key"],
        region_name=config.get("region") or "us-east-1",
        config=Config(
            connect_timeout=5,
            read_timeout=30,
            retries={"max_attempts": 1},
            # The transaction verifies full object SHA-256 itself. Keep generation
            # requests fixed-length instead of the SDK's optional aws-chunked trailer.
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def accept_prepared_receipt(db, backup_id, agent_id, receipt, client=None):
    if db.new or db.dirty or db.deleted:
        raise StorageOwnershipError("Receipt acceptance requires a clean transaction")
    candidate = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .populate_existing()
        .one_or_none()
    )
    if candidate is not None and (candidate.expected_plan or {}).get("schema") == 3:
        return _accept_transaction_receipt(db, candidate, agent_id, receipt, client)
    backup = (
        db.query(Backup)
        .filter(Backup.id == backup_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if backup is None or not backup.org_id:
        raise StorageOwnershipError(
            "Backup is not visible to the authenticated organization"
        )
    vm = db.query(VM).filter(VM.id == backup.vm_id).populate_existing().one_or_none()
    if vm is None or vm.org_id != backup.org_id or vm.agent_id != agent_id:
        raise StorageOwnershipError(
            "Authenticated agent does not own this backup source"
        )
    claim = (
        db.query(S3Publication)
        .filter(
            S3Publication.backup_id == backup.id,
            S3Publication.kind == "payload",
            S3Publication.org_id == backup.org_id,
        )
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if claim is None or claim.state in {"cleanup_required", "deleted"}:
        raise StorageOwnershipError(
            "No active planned reservation; retain cleanup authority"
        )
    # A conflicting retry must never overwrite previous durable acceptance or
    # compensate data already accepted by another invocation.
    if claim.prepared_receipt is not None:
        validated = validate_receipt(claim, receipt)
        if validated != claim.prepared_receipt["receipt"]:
            raise StorageOwnershipError("Receipt conflicts with durable acceptance")
        acceptance = deepcopy(claim.prepared_receipt)
        db.commit()
        return {
            "reservation_id": claim.id,
            "accepted": True,
            "verification": acceptance,
        }
    if claim.state != "reserved" or backup.status not in {
        "pending",
        "running",
        "uploading",
    }:
        raise StorageOwnershipError("Backup is not awaiting prepared publication")
    owned_client = None
    try:
        # Reject malformed receipts before resolving any installation credential.
        validate_receipt(claim, receipt)
        if client is None:
            owned_client = _recorded_target_client(db, claim)
            client = owned_client
        acceptance = verify_stored_receipt(claim, receipt, client)
    except Exception:
        # Only the already-authorized exact reservation is marked. Never derive
        # cleanup keys from an invalid receipt or delete on a filtered DB miss.
        claim.state = "cleanup_required"
        db.commit()
        raise
    finally:
        if owned_client is not None:
            owned_client.close()
    claim.prepared_receipt = acceptance
    db.commit()
    return {
        "reservation_id": claim.id,
        "accepted": True,
        "verification": deepcopy(acceptance),
    }


def _accept_transaction_receipt(db, claim, agent_id, receipt, client):
    """Schema-2 acceptance only; no checkpoint/manifest/completion transition.

    Re-admit the original actor and one-way custody under the D02 locks before
    credentials or HEAD. Identical retry returns the originally committed proof,
    never a newly manufactured acceptance or a fresh storage observation.
    """
    import uuid
    from core.storage_receipt_v2 import validate, verify
    from core.storage_source import readmit_kubevirt_callback
    from core.storage_dispatch import read_target
    from core.settings_service import SettingsService
    from core.storage_wire import PROTOCOL

    owned_client = None
    try:
        request, validated, receipt_hash = validate(claim, receipt)
        if request["agent_id"] != agent_id:
            raise StorageOwnershipError("Agent does not own this transaction")
        config = read_target(SettingsService(db))
        readmit = readmit_kubevirt_callback
        options = {}
        if request["plan"]["provider"] == "libvirt":
            from core.native_storage_plan import commit_native_source_plan

            readmit, options = commit_native_source_plan, {}
        admitted = readmit(
            db,
            claim.backup_id,
            config,
            **options,
            revalidate_token=claim.dispatch_token,
        )
        # The initial lookup may precede another acceptance waiting on the same
        # backup lock. Do not trust its identity-map copy after lock acquisition.
        db.refresh(admitted)
        from core.callback_intents import require_no_intent_consumer

        require_no_intent_consumer(admitted)
        if admitted.id != claim.id or admitted.expected_plan["transaction"] != request:
            raise StorageOwnershipError("Transaction changed during acceptance")
        # Refresh and revalidate after acquiring custody/source locks. This also
        # serializes concurrent duplicate receipts; only the first installs one.
        request, validated, receipt_hash = validate(admitted, receipt)
        if admitted.prepared_receipt is not None:
            saved = admitted.prepared_receipt
            if (
                saved.get("receipt") != validated
                or saved.get("receipt_sha256") != receipt_hash
                or "response" not in saved
            ):
                raise StorageOwnershipError("Conflicting or legacy acceptance evidence")
            response = deepcopy(saved["response"])
            db.commit()
            return response
        if client is None:
            owned_client = _recorded_target_client(db, admitted)
            client = owned_client
        verification = verify(admitted, request, validated, client)
        response = dict(
            protocol=PROTOCOL,
            reservation_id=admitted.id,
            receipt_sha256=receipt_hash,
            accepted=True,
            acceptance_id=str(uuid.uuid4()),
            verification=verification,
            scrub_required=any(
                v["assurance"] != "provider_checksum_verified" for v in verification
            ),
        )
        admitted.prepared_receipt = dict(
            receipt=validated,
            receipt_sha256=receipt_hash,
            plan_sha256=request["plan_sha256"],
            attempt_id=request["plan"]["attempt_id"],
            agent_id=agent_id,
            response=deepcopy(response),
        )
        db.commit()
        return response
    except Exception:
        db.rollback()
        raise
    finally:
        if owned_client is not None:
            owned_client.close()
