"""Unmounted multipart creation: one acknowledged creator, exact result custody.

No retry/recovery from an intent lacking a committed result. In particular,
prefix listing is not proof of an attributable multipart upload.
"""

from copy import deepcopy
import hashlib
import time
import uuid

from sqlalchemy import text
from core.storage_capability_evidence import require_evidence

from core.backup_capacity import validate_reserved_capacity
from core.callback_identity import validate_identity
from core.callback_intents import _claim, _digest, require_committed_key
from core.callback_key_preparation import _binding
from core.scheduler_admission import lock_original_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_control import authority, metadata
from core.storage_signing import control_call, xml_fields
from core.tenant_context import TenantContext
from models import Backup, BackupQueue, S3UploadPart, S3UploadResult


def _custody_authority(db, identity, backup_id, binding, artifact_key):
    if db.in_transaction() or db.new or db.dirty or db.deleted:
        raise StorageOwnershipError("Fresh provider transaction required")
    if db.get_bind().dialect.name != "postgresql":
        raise StorageOwnershipError("PostgreSQL provider authority required")
    db.connection(execution_options={"isolation_level": "READ COMMITTED"})
    lock_original_authority(db, backup_id, callback=True)
    claim, request = _claim(db, backup_id, identity)
    require_committed_key(db, claim, request)
    if (
        binding != _binding(claim, request)
        or claim.state != "reserved"
        or claim.expected_plan.get("schema") != 3
        or claim.dispatch_admission is None
        or claim.dispatch_token is None
        or claim.provider_control is not None
        or claim.prepared_receipt is not None
        or claim.receipt_verification_intent is not None
        or claim.finalize_intent is not None
        or claim.checkpoint_proof is not None
    ):
        raise StorageOwnershipError("Provider create custody unavailable")
    artifacts = [a for a in request["plan"]["artifacts"] if a["key"] == artifact_key]
    if len(artifacts) != 1:
        raise StorageOwnershipError("Provider create artifact unavailable")
    backup = db.get(Backup, backup_id)
    validate_reserved_capacity(db, backup_id, uuid.UUID(str(backup.capacity_id)))
    return claim, deepcopy(request), deepcopy(artifacts[0]), backup


def _admit(db, identity, backup_id, binding, artifact_key):
    result = _custody_authority(db, identity, backup_id, binding, artifact_key)
    validate_identity(db, identity)
    return result


def _first(factory, identity, backup_id, binding, key):
    with TenantContext(identity.org_id), factory() as db:
        claim, request, artifact, backup = _admit(db, identity, backup_id, binding, key)
        state = deepcopy(claim.provider_create or {})
        if key in state:
            if "capability_evidence" in request["plan"]:
                require_evidence(db, request, "create")
            if state[key]["response"] is None and (
                state[key]["intent"]["credential_kind"] != identity.credential_kind
                or state[key]["intent"]["credential_id"] != identity.credential_id
            ):
                raise StorageOwnershipError(
                    "Provider create original credential required"
                )
            db.commit()
            return False, state[key], request, artifact
        require_evidence(db, request, "create")
        if (
            db.query(S3UploadResult)
            .filter_by(publication_id=claim.id, response=None)
            .first()
        ):
            raise StorageOwnershipError("Provider result attempt effect-held")
        if any(entry["response"] is None for entry in state.values()):
            raise StorageOwnershipError("Provider create attempt effect-held")
        if (
            db.query(S3UploadPart)
            .filter_by(publication_id=claim.id, acknowledgment=None)
            .first()
        ):
            raise StorageOwnershipError("Part attempt effect-held")
        queue = (
            db.query(BackupQueue)
            .filter_by(
                started_backup_id=backup_id,
                scheduler_occurrence_id=backup.scheduler_occurrence_id,
                vm_id=backup.vm_id,
            )
            .one_or_none()
        )
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        intent = dict(
            schema=1,
            operation="provider_create",
            nonce=str(uuid.uuid4()),
            org_id=identity.org_id,
            agent_id=identity.agent_id,
            backup_id=backup_id,
            reservation_id=claim.id,
            attempt_id=request["plan"]["attempt_id"],
            claim_id=queue.claim_id if queue else None,
            capacity_id=str(backup.capacity_id),
            plan_sha256=request["plan_sha256"],
            dispatch_sha256=_digest(db, claim.dispatch_admission),
            target_sha256=_digest(db, request["plan"]["target"]),
            credential_kind=identity.credential_kind,
            credential_id=identity.credential_id,
            created_at=now,
            expires_at=now + 60,
            artifact_key=key,
            wrapped_key_sha256=_digest(db, claim.wrapped_attempt_key),
        )
        state[key] = dict(intent=intent, xid=None, response=None)
        claim.provider_create = state
        db.flush()
        db.refresh(claim)
        entry = deepcopy(claim.provider_create[key])
        db.commit()
        return True, entry, request, artifact


def _boundary(factory, identity, backup_id, binding, key, entry):
    with TenantContext(identity.org_id), factory() as db:
        claim, request, artifact, _ = _admit(db, identity, backup_id, binding, key)
        require_evidence(db, request, "create")
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        if (
            (claim.provider_create or {}).get(key) != entry
            or entry["response"] is not None
            or entry["intent"]["credential_kind"] != identity.credential_kind
            or entry["intent"]["credential_id"] != identity.credential_id
            or now >= entry["intent"]["expires_at"]
        ):
            raise StorageOwnershipError("Provider create continuation unavailable")
        db.commit()
        return request, artifact


def _sign(factory, identity, request, artifact):
    # SettingsService reads through its separate configuration reader. This
    # otherwise-unused session must not borrow an owner admission transaction.
    with TenantContext(identity.org_id), factory() as db:
        if db.in_transaction():
            raise StorageOwnershipError("Fresh provider configuration required")
        headers = {"x-amz-meta-" + k: v for k, v in metadata(request, artifact).items()}
        headers.update(
            {
                "content-type": "application/octet-stream",
                "x-amz-checksum-algorithm": "SHA256",
            }
        )
        return authority(
            db,
            request,
            artifact["key"],
            "POST",
            {"uploads": ""},
            headers,
            callback_identity=identity,
            operation="create",
        )


def _response(request, key, headers, data):
    if not isinstance(data, bytes) or len(data) > 1024 * 1024:
        raise StorageOwnershipError("Provider create response unavailable")
    fields = xml_fields(data, "InitiateMultipartUploadResult")
    upload = fields.get("UploadId")
    if (
        fields.get("Bucket") != request["plan"]["target"]["bucket"]
        or fields.get("Key") != key
        or not isinstance(upload, str)
        or not 1 <= len(upload.encode("utf-8")) <= 1024
        or any(ord(c) < 32 or ord(c) == 127 for c in upload)
    ):
        raise StorageOwnershipError("Provider create response unavailable")
    ids = {}
    for field in ("x-amz-request-id", "x-amz-id-2"):
        value = headers.get(field)
        if value is not None and (
            not isinstance(value, str)
            or not 1 <= len(value.encode("utf-8")) <= 1024
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise StorageOwnershipError("Provider create response unavailable")
        ids[field] = value
    return dict(
        schema=1,
        bucket=fields["Bucket"],
        key=key,
        upload_id=upload,
        request_id=ids["x-amz-request-id"],
        host_id=ids["x-amz-id-2"],
        body_sha256=hashlib.sha256(data).hexdigest(),
    )


def create_callback_upload(factory, identity, backup_id, binding, artifact_key):
    """Result is custody only; does not sign parts or activate an uploader."""
    created, entry, request, artifact = _first(
        factory, identity, backup_id, binding, artifact_key
    )
    if not created:
        if entry["response"] is None:
            raise StorageOwnershipError("Provider create outcome unresolved")
        return deepcopy(entry["response"])
    current, current_artifact = _boundary(
        factory, identity, backup_id, binding, artifact_key, entry
    )
    if current != request or current_artifact != artifact:
        raise StorageOwnershipError("Provider create plan changed")
    try:
        signed = _sign(factory, identity, request, artifact)
    except Exception:
        raise StorageOwnershipError("Provider create signing unavailable") from None
    # Signing and provider send are separate effects. Recheck before the send,
    # without keeping that transaction open around the network operation.
    _boundary(factory, identity, backup_id, binding, artifact_key, entry)
    if int(time.time()) >= signed["expires_at"]:
        raise StorageOwnershipError("Provider create signature expired")
    try:
        headers, data = control_call(signed)
        response = _response(request, artifact_key, headers, data)
    except Exception:
        raise StorageOwnershipError("Provider create outcome unresolved") from None
    with TenantContext(identity.org_id), factory() as db:
        # Only this acknowledged creator's in-memory continuation reaches R2.
        # Retaining its observed response grants no IO or delivery authority.
        claim, current, _, _ = _custody_authority(
            db, identity, backup_id, binding, artifact_key
        )
        if (
            current != request
            or (claim.provider_create or {}).get(artifact_key) != entry
        ):
            raise StorageOwnershipError("Provider create result conflict")
        state = deepcopy(claim.provider_create)
        state[artifact_key]["response"] = response
        claim.provider_create = state
        db.commit()
    # Fresh authority/current-credential check and acknowledged transaction
    # before returning the exact saved result, including on ordinary readback.
    _, saved, _, _ = _first(factory, identity, backup_id, binding, artifact_key)
    return deepcopy(saved["response"])
