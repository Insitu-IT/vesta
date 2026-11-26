"""Attempt-bound DEK custody, separate from finite provider signing/control.

Only KEK-wrapped ciphertext survives a request. No logging, audit payload, or
exception includes key material. An unsuccessful commit never returns a DEK.
"""

import base64
import hashlib
import hmac
import os
from datetime import datetime

from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from core.kms.local import _get_fernet
from core.s3_ownership import StorageOwnershipError
from core.settings_service import SettingsService
from core.storage_dispatch import read_target
from core.storage_source import readmit_kubevirt_callback
from core.storage_wire import validate_transaction
from models import Agent, AgentCertificate, EncryptionKey, S3Publication


def _credential(db, agent_id, proof):
    """Recheck the admitted credential under locks; no raw bearer is retained."""
    kind, value = proof
    if kind == "api-key":
        agent = db.get(Agent, agent_id, populate_existing=True)
        from deps import agent_key_usable

        if not agent_key_usable(db, agent, value, lock=True):
            raise StorageOwnershipError("Credential unavailable")
    elif kind == "certificate":
        certs = (
            db.query(AgentCertificate)
            .filter_by(fingerprint=value)
            .populate_existing()
            .with_for_update()
            .limit(2)
            .all()
        )
        agent = db.get(Agent, agent_id, populate_existing=True)
        if (
            len(certs) != 1
            or agent is None
            or agent.cert_fingerprint != value
            or certs[0].agent_id != agent_id
            or certs[0].status != "active"
            or certs[0].expires_at is None
            or certs[0].expires_at <= datetime.utcnow()
        ):
            raise StorageOwnershipError("Credential unavailable")
    else:
        raise StorageOwnershipError("Credential unavailable")


def _admit(db, backup_id, agent_id, binding):
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .populate_existing()
        .one_or_none()
    )
    if claim is None or (claim.expected_plan or {}).get("schema") != 3:
        raise StorageOwnershipError("Attempt unavailable")
    request = claim.expected_plan["transaction"]
    validate_transaction(request)
    expected = dict(
        reservation_id=claim.id,
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        key_ref=request["plan"]["encryption"]["key_ref"],
    )
    if (
        binding != expected
        or request["agent_id"] != agent_id
        or not claim.dispatch_token
    ):
        raise StorageOwnershipError("Attempt unavailable")
    readmit = readmit_kubevirt_callback
    options = {}
    if request["plan"]["provider"] == "libvirt":
        from core.native_storage_plan import commit_native_source_plan

        readmit, options = commit_native_source_plan, {}
    admitted = readmit(
        db,
        backup_id,
        read_target(SettingsService(db)),
        **options,
        revalidate_token=claim.dispatch_token,
    )
    db.refresh(admitted)
    if (
        admitted.id != claim.id
        or admitted.expected_plan["transaction"] != request
        or admitted.state != "reserved"
        or admitted.prepared_receipt is not None
    ):
        raise StorageOwnershipError("Attempt unavailable")
    from core.callback_intents import require_no_intent_consumer

    require_no_intent_consumer(admitted)
    return admitted, request


def _kek(db, claim, request, *, retained=False):
    encryption = request["plan"]["encryption"]
    _, key_id, fingerprint = encryption["key_ref"].split(":")
    key = (
        db.query(EncryptionKey)
        .filter_by(id=key_id, org_id=claim.org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        key is None
        or key.status not in (("active", "rotated") if retained else ("active",))
        or key.provider != "local"
        or key.algorithm != "aes-256-gcm"
        or key.provider_key_ref is not None
        or key.key_hash != fingerprint
    ):
        raise StorageOwnershipError("Attempt unavailable")
    raw = _get_fernet().decrypt(key.encrypted_material.encode())
    if len(raw) != 32 or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest()[: len(fingerprint)], fingerprint
    ):
        raise StorageOwnershipError("Attempt unavailable")
    return raw


def unwrap_retained_attempt_key(db, claim, request):
    """Unwrap only exact retained accepted custody after caller restore admission.

    This helper confers no restore authorization. The caller must first lock and
    authorize its selected accepted chain and restore principal in tenant scope.
    Rotation preserves old backups; revocation/deletion prevents disclosure.
    """
    try:
        validate_transaction(request)
        encryption = request["plan"]["encryption"]
        if claim.state != "published" or claim.prepared_receipt is None:
            raise ValueError()
        if (claim.expected_plan or {}).get("transaction") != request:
            raise ValueError()
        if encryption["format"] == "none":
            if claim.wrapped_attempt_key is not None:
                raise ValueError()
            return None
        saved = dict(claim.wrapped_attempt_key or {})
        ciphertext = saved.pop("ciphertext", None)
        expected = dict(
            schema=1,
            org_id=claim.org_id,
            backup_id=claim.backup_id,
            reservation_id=claim.id,
            attempt_id=request["plan"]["attempt_id"],
            plan_sha256=request["plan_sha256"],
            key_ref=encryption["key_ref"],
            format=encryption["format"],
            wrapping="aes256-keywrap/1",
        )
        if saved != expected or not isinstance(ciphertext, str):
            raise ValueError()
        raw = aes_key_unwrap(
            _kek(db, claim, request, retained=True),
            base64.b64decode(ciphertext, validate=True),
        )
        if len(raw) != 32:
            raise ValueError()
        return raw
    except Exception:
        raise StorageOwnershipError("Retained attempt key unavailable") from None


def resolve_attempt_key(db, backup_id, agent_id, binding, credential_proof):
    """Commit immutable wrapped custody, then re-admit before memory-only unwrap.

    The second admission closes the commit/revocation race as far as database
    locks permit. Previously disclosed keys cannot be remotely erased. No key
    is disclosed on either commit failure, including a lost acknowledgement;
    a retry reopens durable ciphertext rather than generating another DEK.
    """
    try:
        db.info["attempt_key_resolution"] = True
        if db.new or db.dirty or db.deleted:
            raise StorageOwnershipError("Clean transaction required")
        claim, request = _admit(db, backup_id, agent_id, binding)
        _credential(db, agent_id, credential_proof)
        encryption = request["plan"]["encryption"]
        if encryption["format"] == "none":
            db.commit()
            return dict(**binding, format="none", dek=None)
        expected = dict(
            schema=1,
            org_id=claim.org_id,
            backup_id=backup_id,
            **binding,
            format=encryption["format"],
            wrapping="aes256-keywrap/1",
        )
        if claim.wrapped_attempt_key is None:
            kek = _kek(db, claim, request)
            # No raw DEK is retained between the durable-commit and unwrap legs.
            ciphertext = aes_key_wrap(kek, os.urandom(32))
            claim.wrapped_attempt_key = dict(
                **expected, ciphertext=base64.b64encode(ciphertext).decode("ascii")
            )
        db.commit()
        claim, request = _admit(db, backup_id, agent_id, binding)
        _credential(db, agent_id, credential_proof)
        saved = dict(claim.wrapped_attempt_key or {})
        ciphertext = saved.pop("ciphertext", None)
        if saved != expected or not isinstance(ciphertext, str):
            raise StorageOwnershipError("Attempt unavailable")
        raw = aes_key_unwrap(
            _kek(db, claim, request), base64.b64decode(ciphertext, validate=True)
        )
        if len(raw) != 32:
            raise StorageOwnershipError("Attempt unavailable")
        db.commit()
        return dict(
            **binding,
            format=encryption["format"],
            dek=base64.b64encode(raw).decode("ascii"),
        )
    except Exception:
        # A lost post-commit acknowledgement can leave SQLAlchemy's transaction
        # object committed. Close it without exposing a secondary rollback error.
        try:
            db.rollback()
        except Exception:
            db.close()
        # Do not retain crypto/provider exception details in an HTTP exception chain.
        raise StorageOwnershipError("Attempt key unavailable") from None
    finally:
        db.info.pop("attempt_key_resolution", None)
