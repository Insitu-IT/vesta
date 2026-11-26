"""Unmounted one-stack part signing and authenticated agent result custody.

Signed capabilities are memory-only. Durable digest/expiry is not a capability
and never permits replay, re-signing, a provider PUT, or terminal release.
"""

import base64
from copy import deepcopy
import hashlib
import json
import re
import time
import uuid

from sqlalchemy import text
from core.storage_capability_evidence import require_evidence
from core.callback_intents import _digest
from core.callback_provider_create import _admit, _custody_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_control import authority, part_size
from core.storage_signing import SigningWindow
from core.tenant_context import TenantContext
from models import S3UploadPart, S3UploadResult


def _request(args, *, ack=False):
    fields = {"upload_id", "number", "bytes", "sha256"} | ({"etag"} if ack else set())
    if (
        type(args) is not dict
        or set(args) != fields
        or type(args["upload_id"]) is not str
        or not 1 <= len(args["upload_id"].encode()) <= 1024
        or any(ord(c) < 32 or ord(c) == 127 for c in args["upload_id"])
        or type(args["number"]) is not int
        or not 1 <= args["number"] <= 10000
        or type(args["bytes"]) is not int
        or args["bytes"] < 0
        or type(args["sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", args["sha256"])
        or ack
        and (
            type(args["etag"]) is not str
            or not 1 <= len(args["etag"].encode()) <= 1022
            or any(ord(c) < 32 or ord(c) == 127 or c == '"' for c in args["etag"])
        )
    ):
        raise StorageOwnershipError("Part request invalid")
    return deepcopy(args)


def _part(db, claim, key, args):
    row = (
        db.query(S3UploadPart)
        .filter_by(publication_id=claim.id, artifact_key=key, number=args["number"])
        .populate_existing()
        .one_or_none()
    )
    if row and (
        row.byte_count != args["bytes"]
        or row.sha256 != args["sha256"]
        or row.intent["upload_id"] != args["upload_id"]
    ):
        raise StorageOwnershipError("Part tuple conflict")
    return row


def _create(claim, key, args):
    state = claim.provider_create or {}
    entry = state.get(key)
    if (
        not entry
        or not entry["response"]
        or any(e["response"] is None for e in state.values())
    ):
        raise StorageOwnershipError("Part requires committed exact create")
    if entry["response"]["upload_id"] != args["upload_id"]:
        raise StorageOwnershipError("Part upload binding unavailable")
    return entry


def _first(factory, identity, backup_id, binding, key, args):
    with TenantContext(identity.org_id), factory() as db:
        claim, request, artifact, _ = _admit(db, identity, backup_id, binding, key)
        require_evidence(db, request, "part_sign")
        if (
            db.query(S3UploadResult)
            .filter(
                S3UploadResult.publication_id == claim.id,
                (S3UploadResult.artifact_key == key)
                | (S3UploadResult.response.is_(None)),
            )
            .first()
        ):
            raise StorageOwnershipError("Completion fences part mutation")
        entry = _create(claim, key, args)
        if _part(db, claim, key, args) is not None:
            raise StorageOwnershipError("Part capability cannot be replayed")
        if (
            db.query(S3UploadPart)
            .filter_by(publication_id=claim.id, acknowledgment=None)
            .first()
        ):
            raise StorageOwnershipError("Part attempt effect-held")
        prior = (
            db.query(S3UploadPart)
            .filter_by(publication_id=claim.id, artifact_key=key)
            .order_by(S3UploadPart.number.desc())
            .first()
        )
        unit = part_size(artifact, request["plan"].get("transfer_profile"))
        if (
            args["number"] != (prior.number + 1 if prior else 1)
            or args["bytes"] > unit
            or prior
            and (prior.acknowledgment is None or prior.byte_count != unit)
            # Every earlier part is immutable and full-sized by induction:
            # only the last part may be smaller, and then admission stops.
            or (args["number"] - 1) * unit + args["bytes"] > artifact["ciphertext_max"]
        ):
            raise StorageOwnershipError("Part sequence unavailable")
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        intent = deepcopy(entry["intent"])
        intent.update(
            operation="provider_part",
            nonce=str(uuid.uuid4()),
            created_at=now,
            expires_at=now + 60,
            credential_kind=identity.credential_kind,
            credential_id=identity.credential_id,
            number=args["number"],
            bytes=args["bytes"],
            sha256=args["sha256"],
            upload_id=args["upload_id"],
            create_response_sha256=_digest(db, entry["response"]),
        )
        row = S3UploadPart(
            org_id=identity.org_id,
            publication_id=claim.id,
            artifact_key=key,
            number=args["number"],
            byte_count=args["bytes"],
            sha256=args["sha256"],
            intent=intent,
        )
        db.add(row)
        db.flush()
        db.refresh(row)
        marker = row.intent_xid
        db.commit()
        return deepcopy(intent), marker, request


def _boundary(
    factory, identity, backup_id, binding, key, args, intent, marker, *, result=None
):
    with TenantContext(identity.org_id), factory() as db:
        claim, request, _, _ = _admit(db, identity, backup_id, binding, key)
        window = require_evidence(
            db, request, "part_sign", signing_window=result is None
        )
        _create(claim, key, args)
        row = _part(db, claim, key, args)
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        if (
            row is None
            or row.intent != intent
            or row.intent_xid != marker
            or intent["credential_kind"] != identity.credential_kind
            or intent["credential_id"] != identity.credential_id
            or row.acknowledgment is not None
            or row.signing_result != result
            or result is None
            and now >= intent["expires_at"]
            or result is not None
            and now >= result["expires_at"]
        ):
            raise StorageOwnershipError("Part continuation unavailable")
        db.commit()
        return request, window


def _sign(factory, identity, request, key, args, window):
    # PostgreSQL read_configuration uses short separate connections and returns
    # detached rows before get_secret decrypts or authority signs. This Session
    # supplies only the engine; actual crypto call-site PG probes cover that
    # property, not merely the fresh-session check below.
    ref = request["plan"]["capability_evidence"]
    if (
        type(window) is not SigningWindow
        or window.evidence_id != ref["id"]
        or window.evidence_sha256 != ref["sha256"]
    ):
        raise StorageOwnershipError("Part signing evidence differs")
    with TenantContext(identity.org_id), factory() as db:
        if db.in_transaction():
            raise StorageOwnershipError("Fresh part configuration required")
        return authority(
            db,
            request,
            key,
            "PUT",
            {"uploadId": args["upload_id"], "partNumber": str(args["number"])},
            {
                "content-length": str(args["bytes"]),
                "x-amz-content-sha256": args["sha256"],
                "x-amz-checksum-sha256": base64.b64encode(
                    bytes.fromhex(args["sha256"])
                ).decode(),
            },
            signing_window=window,
            callback_identity=identity,
            operation="part_sign",
        )


def sign_callback_part(factory, identity, backup_id, binding, artifact_key, args):
    args = _request(args)
    intent, marker, request = _first(
        factory, identity, backup_id, binding, artifact_key, args
    )
    current, window = _boundary(
        factory, identity, backup_id, binding, artifact_key, args, intent, marker
    )
    if current != request:
        raise StorageOwnershipError("Part plan changed")
    try:
        signed = _sign(factory, identity, request, artifact_key, args, window)
    except Exception:
        raise StorageOwnershipError("Part signing unavailable") from None
    result = dict(
        schema=1,
        sha256=hashlib.sha256(
            json.dumps(
                signed, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest(),
        expires_at=signed["expires_at"],
    )
    with TenantContext(identity.org_id), factory() as db:
        # Persist-only after credential revocation; no new IO or disclosure.
        claim, current, _, _ = _custody_authority(
            db, identity, backup_id, binding, artifact_key
        )
        row = _part(db, claim, artifact_key, args)
        if (
            current != request
            or row is None
            or row.intent != intent
            or row.intent_xid != marker
            or row.signing_result is not None
            or row.acknowledgment is not None
        ):
            raise StorageOwnershipError("Part signing custody conflict")
        row.signing_result = result
        db.commit()
    _boundary(
        factory,
        identity,
        backup_id,
        binding,
        artifact_key,
        args,
        intent,
        marker,
        result=result,
    )
    # Charge the final DB commit/return delay too, even if local wall time moves.
    window.interval()
    if int(time.time()) >= signed["expires_at"]:
        raise StorageOwnershipError("Part signature expired")
    return dict(schema=1, authority=signed)


def acknowledge_callback_part(
    factory, identity, backup_id, binding, artifact_key, args
):
    args = _request(args, ack=True)
    for attach in (True, False):
        with TenantContext(identity.org_id), factory() as db:
            claim, _, _, _ = _admit(db, identity, backup_id, binding, artifact_key)
            _create(claim, artifact_key, args)
            row = _part(db, claim, artifact_key, args)
            if row is None or row.signing_result is None:
                raise StorageOwnershipError("Part signing custody required")
            if row.acknowledgment is not None:
                if row.acknowledgment["etag"] != args["etag"]:
                    raise StorageOwnershipError("Part acknowledgment conflict")
            elif attach:
                row.acknowledgment = dict(
                    schema=1,
                    etag=args["etag"],
                    credential_kind=identity.credential_kind,
                    credential_id=identity.credential_id,
                )
            else:
                raise StorageOwnershipError("Part acknowledgment unavailable")
            db.commit()
    return dict(schema=1, acknowledged=True)
