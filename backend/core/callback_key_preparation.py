"""Unmounted preparation only: one creator wraps once, no DEK disclosure."""

import base64
from copy import deepcopy
import hashlib
import hmac
import os
import uuid

from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from sqlalchemy import text

from core.backup_capacity import validate_reserved_capacity
from core.callback_identity import validate_identity
from core.callback_intents import _claim, admit_intent, require_preparation_order
from core.kms.local import _get_fernet
from core.scheduler_admission import lock_original_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_wire import validate_transaction
from core.tenant_context import TenantContext
from models import EncryptionKey

KIND = "attempt_key_preparation"


def _binding(claim, request):
    validate_transaction(request)
    encryption = request["plan"]["encryption"]
    if (
        request["plan"]["provider"] != "kubevirt"
        or encryption["format"] != "vnbu1-aes256gcm-chunk5242880"
    ):
        raise StorageOwnershipError("Callback key preparation unsupported")
    return dict(
        reservation_id=claim.id,
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        key_ref=encryption["key_ref"],
    )


def _read(factory, identity, backup_id, binding):
    with TenantContext(identity.org_id), factory() as db:
        validate_identity(db, identity)
        claim, request = _claim(db, backup_id, identity)
        if binding != _binding(claim, request):
            raise StorageOwnershipError("Callback key binding unavailable")
        intent = deepcopy(claim.attempt_key_preparation_intent)
        if claim.wrapped_attempt_key is not None:
            if intent is None:
                raise StorageOwnershipError("Callback key custody conflict")
            # This is a nonsecret preparation acknowledgment, never unwrap or
            # disclosure authority. The exact ciphertext remains database-only.
            return request, dict(
                **binding,
                format=intent["format"],
                prepared=True,
                preparation_nonce=intent["nonce"],
            )
        return deepcopy(request), None


def _key_snapshot(db, identity, request):
    _, key_id, fingerprint = request["plan"]["encryption"]["key_ref"].split(":")
    key = (
        db.query(EncryptionKey)
        .filter_by(id=key_id, org_id=identity.org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        key is None
        or key.status != "active"
        or key.provider != "local"
        or key.algorithm != "aes-256-gcm"
        or key.provider_key_ref is not None
        or key.key_hash != fingerprint
    ):
        raise StorageOwnershipError("Callback KEK unavailable")
    return key.encrypted_material, fingerprint


def _admission(db, identity, backup_id, binding, intent):
    db.connection(execution_options={"isolation_level": "READ COMMITTED"})
    lock_original_authority(db, backup_id, callback=True)
    validate_identity(db, identity)
    claim, request = _claim(db, backup_id, identity)
    require_preparation_order(claim)
    if (
        _binding(claim, request) != binding
        or claim.attempt_key_preparation_intent != intent
        or claim.wrapped_attempt_key is not None
        or claim.prepared_receipt is not None
        or intent["credential_kind"] != identity.credential_kind
        or intent["credential_id"] != identity.credential_id
    ):
        raise StorageOwnershipError("Callback key continuation unavailable")
    validate_reserved_capacity(db, backup_id, uuid.UUID(intent["capacity_id"]))
    return claim, request, _key_snapshot(db, identity, request)


def _wrap(snapshot):
    """Local crypto only, called after acknowledged startup and session close."""
    try:
        encrypted, fingerprint = snapshot
        kek = _get_fernet().decrypt(encrypted.encode())
        if len(kek) != 32 or not hmac.compare_digest(
            hashlib.sha256(kek).hexdigest()[: len(fingerprint)], fingerprint
        ):
            raise ValueError("Invalid KEK")
        return base64.b64encode(aes_key_wrap(kek, os.urandom(32))).decode("ascii")
    except Exception:
        # No crypto exception, material or raw DEK leaves this boundary.
        raise StorageOwnershipError("Callback key preparation unavailable") from None


def prepare_callback_key(factory, identity, backup_id, binding):
    request, saved = _read(factory, identity, backup_id, binding)
    if saved is not None:
        return saved
    encryption = request["plan"]["encryption"]
    admitted = admit_intent(
        factory,
        identity,
        backup_id,
        KIND,
        dict(key_ref=encryption["key_ref"], format=encryption["format"]),
    )
    if admitted["disposition"] != "created":
        _, saved = _read(factory, identity, backup_id, binding)
        if saved is not None:
            return saved
        raise StorageOwnershipError("Callback key preparation outcome unresolved")
    intent = admitted["intent"]
    with TenantContext(identity.org_id), factory() as db:
        _, current, snapshot = _admission(db, identity, backup_id, binding, intent)
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        if current != request or now >= intent["expires_at"]:
            raise StorageOwnershipError("Callback key startup unavailable")
        db.commit()
    ciphertext = _wrap(snapshot)
    with TenantContext(identity.org_id), factory() as db:
        claim, current, current_key = _admission(
            db, identity, backup_id, binding, intent
        )
        if current != request or current_key != snapshot:
            raise StorageOwnershipError("Callback key preparation custody changed")
        claim.wrapped_attempt_key = dict(
            schema=1,
            org_id=identity.org_id,
            backup_id=backup_id,
            **binding,
            format=encryption["format"],
            wrapping="aes256-keywrap/1",
            ciphertext=ciphertext,
        )
        db.commit()
    # Readback cannot unwrap. It also rechecks the current agent credential.
    _, response = _read(factory, identity, backup_id, binding)
    return response
