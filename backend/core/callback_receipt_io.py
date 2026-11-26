"""Unmounted receipt callback: admitted IO, immutable response, no publication.

Only this call's acknowledged creator stack performs IO. Persisted custody is
never converted into another verification run, including after uncertain IO.
"""

from copy import deepcopy
from types import SimpleNamespace
import uuid

from sqlalchemy import text

from core.backup_capacity import validate_reserved_capacity
from core.callback_identity import validate_identity
from core.callback_intents import _claim, admit_intent, require_committed_key
from core.scheduler_admission import lock_original_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical, validate, verify
from core.storage_wire import PROTOCOL
from core.tenant_context import TenantContext


def _snapshot(claim):
    return SimpleNamespace(
        **{
            key: deepcopy(getattr(claim, key))
            for key in (
                "id",
                "org_id",
                "backup_id",
                "endpoint",
                "bucket",
                "state",
                "expected_plan",
                "dispatch_token",
            )
        }
    )


def _read(factory, identity, backup_id, receipt):
    with TenantContext(identity.org_id), factory() as db:
        validate_identity(db, identity)
        claim, _ = _claim(db, backup_id, identity)
        request, validated, digest = validate(claim, receipt)
        if request["plan"]["provider"] != "kubevirt":
            raise StorageOwnershipError("Callback receipt provider unsupported")
        saved = deepcopy(claim.prepared_receipt)
        intent = deepcopy(claim.receipt_verification_intent)
        if saved is not None:
            if (
                saved.get("receipt") != validated
                or saved.get("receipt_sha256") != digest
                or intent is None
                or saved.get("callback_intent") != intent
            ):
                raise StorageOwnershipError("Callback response custody conflict")
            return request, validated, digest, deepcopy(saved["response"])
        return request, validated, digest, None


def _boundary(factory, identity, backup_id, intent, *, require_start_window):
    """Admit one effect; expiry bounds creator startup, not its active batch.

    This helper performs no IO and returns no resumable permission. Only the
    acknowledged creator stack below can traverse the committed object list.
    Every traversal step still checks current original authority and custody.
    """
    with TenantContext(identity.org_id), factory() as db:
        db.connection(execution_options={"isolation_level": "READ COMMITTED"})
        lock_original_authority(db, backup_id, callback=True)
        validate_identity(db, identity)
        claim, request = _claim(db, backup_id, identity)
        require_committed_key(db, claim, request)
        startup_expired = (
            require_start_window
            and db.scalar(
                text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            )
            >= intent["expires_at"]
        )
        if (
            claim.receipt_verification_intent != intent
            or claim.prepared_receipt is not None
            or intent["credential_kind"] != identity.credential_kind
            or intent["credential_id"] != identity.credential_id
            or startup_expired
        ):
            raise StorageOwnershipError("Callback continuation unavailable")
        validate_reserved_capacity(db, backup_id, uuid.UUID(intent["capacity_id"]))
        snapshot = _snapshot(claim)
        db.commit()
        return snapshot, deepcopy(request)


def _client(factory, claim):
    import boto3
    from botocore.config import Config
    from core.settings_service import SettingsService
    from core.s3_ownership import storage_identity

    # SettingsService uses separate read-only configuration connections. This
    # fresh, otherwise unused session never acquires owner locks or starts a
    # tenant transaction around decryption or client construction.
    with factory() as db:
        if db.in_transaction():
            raise StorageOwnershipError("Fresh configuration reader required")
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
                connect_timeout=5, read_timeout=30, retries={"total_max_attempts": 1}
            ),
        )


def verify_callback_receipt(factory, identity, backup_id, receipt):
    """Return only committed exact response; retries cannot authorize HEADs.

    No HTTP route invokes this until the remaining B/C integration is reviewed.
    Failure after admission retains the intent. No auto-retry, reset or new
    verification is performed when the outcome or response commit is uncertain.
    """
    request, validated, digest, saved = _read(factory, identity, backup_id, receipt)
    if saved is not None:
        return saved
    if "capability_evidence" in request["plan"]:
        raise StorageOwnershipError("Qualified receipt publication remains dormant")
    if [o["key"] for o in validated["objects"]] != [
        a["key"] for a in request["plan"]["artifacts"]
    ]:
        raise StorageOwnershipError("Callback receipt order differs from plan")
    by_key = {obj["key"]: obj for obj in validated["objects"]}
    details = dict(
        receipt_sha256=digest,
        objects=[
            dict(
                artifact_key=artifact["key"],
                version_id=by_key[artifact["key"]]["version_id"],
                etag=by_key[artifact["key"]]["etag"],
            )
            for artifact in request["plan"]["artifacts"]
        ],
    )
    admitted = admit_intent(
        factory, identity, backup_id, "receipt_verification", details
    )
    if admitted["disposition"] != "created":
        # Readback can recover a concurrently committed response, never IO.
        _, _, _, saved = _read(factory, identity, backup_id, receipt)
        if saved is not None:
            return saved
        raise StorageOwnershipError("Callback verification outcome unresolved")
    intent = admitted["intent"]
    claim, request = _boundary(
        factory, identity, backup_id, intent, require_start_window=True
    )
    client = None
    try:
        client = _client(factory, claim)
        verification = []
        for obj in validated["objects"]:
            # The sole live creator has already started inside its admission
            # window. It may finish this finite one-pass batch after that window,
            # but cannot reconstruct it from custody or retry any object.
            claim, current = _boundary(
                factory, identity, backup_id, intent, require_start_window=False
            )
            if current != request:
                raise StorageOwnershipError("Callback plan changed")
            # Verification's provider call happens after the admission session
            # has closed. Each object gets its own live admission boundary.
            verification.extend(
                verify(claim, request, dict(validated, objects=[obj]), client)
            )
    finally:
        if client is not None:
            client.close()
    response = dict(
        protocol=PROTOCOL,
        reservation_id=claim.id,
        receipt_sha256=digest,
        accepted=True,
        acceptance_id=str(uuid.uuid4()),
        verification=verification,
        scrub_required=any(
            v["assurance"] != "provider_checksum_verified" for v in verification
        ),
    )
    with TenantContext(identity.org_id), factory() as db:
        db.connection(execution_options={"isolation_level": "READ COMMITTED"})
        lock_original_authority(db, backup_id, callback=True)
        validate_identity(db, identity)
        row, current = _claim(db, backup_id, identity)
        require_committed_key(db, row, current)
        validate_reserved_capacity(db, backup_id, uuid.UUID(intent["capacity_id"]))
        if (
            row.receipt_verification_intent != intent
            or current != request
            or row.prepared_receipt is not None
        ):
            raise StorageOwnershipError("Callback response custody changed")
        row.prepared_receipt = dict(
            receipt=validated,
            receipt_canonical=canonical(validated).decode(),
            receipt_sha256=digest,
            plan_sha256=request["plan_sha256"],
            attempt_id=request["plan"]["attempt_id"],
            agent_id=identity.agent_id,
            callback_intent=deepcopy(intent),
            response=deepcopy(response),
        )
        db.commit()
    return response
