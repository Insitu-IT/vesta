"""Unmounted one-send Complete/HEAD, with separately committed result custody."""

import base64
from copy import deepcopy
import hashlib
import re
import time
import uuid
from xml.etree import ElementTree

from sqlalchemy import text
from core.storage_capability_evidence import require_evidence

from core.callback_intents import _digest
from core.callback_provider_create import _admit, _custody_authority
from core.s3_ownership import StorageOwnershipError
from core.storage_composite import verify_sha256_composite
from core.storage_control import authority, metadata
from core.storage_signing import control_call, xml_fields
from core.tenant_context import TenantContext
from models import S3UploadPart, S3UploadResult


def _row(db, claim, key, operation):
    return (
        db.query(S3UploadResult)
        .filter_by(publication_id=claim.id, artifact_key=key, operation=operation)
        .one_or_none()
    )


def _parts(db, claim, key):
    rows = (
        db.query(S3UploadPart)
        .filter_by(publication_id=claim.id, artifact_key=key)
        .order_by(S3UploadPart.number)
        .limit(10001)
        .all()
    )
    if not rows or len(rows) > 10000 or any(r.acknowledgment is None for r in rows):
        raise StorageOwnershipError("Committed part acknowledgments required")
    return [
        dict(
            number=r.number,
            bytes=r.byte_count,
            sha256=r.sha256,
            etag=r.acknowledgment["etag"],
        )
        for r in rows
    ]


def _saved(row):
    return dict(
        id=row.id,
        intent=deepcopy(row.intent),
        intent_xid=row.intent_xid,
        response=deepcopy(row.response),
        response_xid=row.response_xid,
    )


def _first(factory, identity, backup_id, binding, key, operation):
    if operation not in ("complete", "head"):
        raise StorageOwnershipError("Unknown result operation")
    with TenantContext(identity.org_id), factory() as db:
        claim, request, artifact, _ = _admit(db, identity, backup_id, binding, key)
        row = _row(db, claim, key, operation)
        if row:
            if "capability_evidence" in request["plan"]:
                require_evidence(db, request, operation)
            saved = _saved(row)
            db.commit()
            return False, saved, request, artifact, None, None
        require_evidence(db, request, operation)
        entry = (claim.provider_create or {}).get(key)
        if (
            not entry
            or entry["response"] is None
            or any(item["response"] is None for item in claim.provider_create.values())
            or db.query(S3UploadPart)
            .filter_by(publication_id=claim.id, acknowledgment=None)
            .first()
        ):
            raise StorageOwnershipError("Provider predecessor unresolved")
        if (
            db.query(S3UploadResult)
            .filter_by(publication_id=claim.id, response=None)
            .first()
        ):
            raise StorageOwnershipError("Provider result attempt effect-held")
        parts = _parts(db, claim, key)
        total = sum(part["bytes"] for part in parts)
        if not artifact["ciphertext_min"] <= total <= artifact["ciphertext_max"]:
            raise StorageOwnershipError("Completed size outside committed plan")
        completed = _row(db, claim, key, "complete")
        completion = deepcopy(completed.response) if completed else None
        if operation == "head" and completion is None:
            raise StorageOwnershipError("Committed completion required")
        raw = b"".join(bytes.fromhex(part["sha256"]) for part in parts)
        composite = (
            base64.b64encode(hashlib.sha256(raw).digest()).decode()
            + "-"
            + str(len(parts))
        )
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        intent = deepcopy(entry["intent"])
        intent.update(
            operation="provider_" + operation,
            nonce=str(uuid.uuid4()),
            created_at=now,
            expires_at=now + 60,
            credential_kind=identity.credential_kind,
            credential_id=identity.credential_id,
            upload_id=entry["response"]["upload_id"],
            create_response_sha256=_digest(db, entry["response"]),
            parts_sha256=_digest(db, parts),
            part_count=len(parts),
            total_bytes=total,
            composite_sha256=composite,
            completion_sha256=_digest(db, completion) if completion else None,
        )
        row = S3UploadResult(
            org_id=identity.org_id,
            publication_id=claim.id,
            artifact_key=key,
            operation=operation,
            intent=intent,
        )
        db.add(row)
        db.flush()
        db.refresh(row)
        saved = _saved(row)
        db.commit()
        return True, saved, request, artifact, parts, completion


def _boundary(factory, identity, backup_id, binding, key, operation, saved, request):
    with TenantContext(identity.org_id), factory() as db:
        claim, current, _, _ = _admit(db, identity, backup_id, binding, key)
        require_evidence(db, current, operation)
        row = _row(db, claim, key, operation)
        now = db.scalar(
            text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        )
        if (
            row is None
            or _saved(row) != saved
            or current != request
            or now >= saved["intent"]["expires_at"]
            or saved["intent"]["credential_kind"] != identity.credential_kind
            or saved["intent"]["credential_id"] != identity.credential_id
        ):
            raise StorageOwnershipError("Provider result continuation unavailable")
        db.commit()


def _sign(factory, identity, request, key, operation, intent, parts, completion):
    if operation == "complete":
        root = ElementTree.Element("CompleteMultipartUpload")
        for part in parts:
            node = ElementTree.SubElement(root, "Part")
            for field, value in (
                ("PartNumber", part["number"]),
                ("ETag", part["etag"]),
                (
                    "ChecksumSHA256",
                    base64.b64encode(bytes.fromhex(part["sha256"])).decode(),
                ),
            ):
                ElementTree.SubElement(node, field).text = str(value)
        body = ElementTree.tostring(root, encoding="utf-8")
        headers = {
            "content-type": "application/xml",
            "content-length": str(len(body)),
            "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
            "if-none-match": "*",
        }
        method, query = "POST", {"uploadId": intent["upload_id"]}
    else:
        body = b""
        headers = {"if-match": completion["etag"], "x-amz-checksum-mode": "ENABLED"}
        method = "HEAD"
        query = (
            {}
            if completion["version_id"] is None
            else {"versionId": completion["version_id"]}
        )
    with TenantContext(identity.org_id), factory() as db:
        if db.in_transaction():
            raise StorageOwnershipError("Fresh provider configuration required")
        signed = authority(
            db,
            request,
            key,
            method,
            query,
            headers,
            callback_identity=identity,
            operation=operation,
        )
        if db.in_transaction():
            raise StorageOwnershipError("Provider configuration transaction remains")
    return signed, body


def _identifier(value):
    if value is not None and (
        type(value) is not str
        or not 1 <= len(value.encode()) <= 1024
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise StorageOwnershipError("Provider result identifier invalid")
    return value


def _response(request, artifact, operation, intent, parts, completion, headers, data):
    if type(data) is not bytes or len(data) > 1024 * 1024:
        raise StorageOwnershipError("Provider result body invalid")
    profile = request["plan"]["capability_profile"]
    if profile not in {
        "checksum-enforced/1",
        "consumer-verified/1",
        "db-rooted-consumer-verified/1",
    }:
        raise StorageOwnershipError("Provider result profile unavailable")
    result = dict(
        schema=2,
        profile=profile,
        assurance=(
            "completion_observed"
            if operation == "complete"
            else "identity_metadata_only"
        ),
        scrub_required=True,
        kind=operation,
        bucket=request["plan"]["target"]["bucket"],
        key=artifact["key"],
        version_id=_identifier(headers.get("x-amz-version-id")),
        request_id=_identifier(headers.get("x-amz-request-id")),
        host_id=_identifier(headers.get("x-amz-id-2")),
        body_sha256=hashlib.sha256(data).hexdigest(),
        bytes=None,
        metadata=None,
    )
    if operation == "complete":
        fields = xml_fields(data, "CompleteMultipartUploadResult")
        if (
            fields.get("Bucket") != result["bucket"]
            or fields.get("Key") != result["key"]
        ):
            raise StorageOwnershipError("Provider completion owner differs")
        result["etag"] = fields.get("ETag")
        checksum, kind = fields.get("ChecksumSHA256"), fields.get("ChecksumType")
    else:
        if data:
            raise StorageOwnershipError("HEAD unexpectedly returned body")
        result["etag"] = headers.get("etag")
        if not re.fullmatch(r"0|[1-9][0-9]{0,18}", headers.get("content-length", "")):
            raise StorageOwnershipError("HEAD size invalid")
        result["bytes"] = int(headers["content-length"])
        result["metadata"] = {
            k[11:]: v for k, v in headers.items() if k.startswith("x-amz-meta-")
        }
        if (
            result["bytes"] != intent["total_bytes"]
            or result["metadata"] != metadata(request, artifact)
            or result["etag"] != completion["etag"]
            or result["version_id"] != completion["version_id"]
        ):
            raise StorageOwnershipError("HEAD identity differs from completion")
        checksum, kind = headers.get("x-amz-checksum-sha256"), headers.get(
            "x-amz-checksum-type"
        )
    if type(result["etag"]) is not str or not re.fullmatch(
        r'"[^"\x00-\x1f\x7f]{1,1022}"', result["etag"]
    ):
        raise StorageOwnershipError("Provider result ETag invalid")
    absent = checksum is None and kind is None
    if absent and (operation == "complete" or profile != "checksum-enforced/1"):
        result.update(checksum_algorithm=None, checksum_type=None, checksum_value=None)
    else:
        evidence = verify_sha256_composite([p["sha256"] for p in parts], checksum, kind)
        result.update(
            checksum_algorithm=evidence["algorithm"],
            checksum_type=evidence["type"],
            checksum_value=evidence["value"],
        )
    result["checksum_comparison"] = "absent" if absent else "composite_match"
    result["assurance_reason"] = (
        "object_verification_pending"
        if operation == "complete"
        else (
            "checksum_absent"
            if absent
            else (
                "composite_not_full_object_sha256"
                if profile == "checksum-enforced/1"
                else "provider_checksum_enforcement_unproven"
            )
        )
    )
    return result


def resolve_callback_result(
    factory, identity, backup_id, binding, artifact_key, operation
):
    """One acknowledged creator may send; persisted intents cannot recreate it."""
    args = (factory, identity, backup_id, binding, artifact_key, operation)
    created, saved, request, artifact, parts, completion = _first(*args)
    if not created:
        if saved["response"] is None:
            raise StorageOwnershipError("Provider result outcome unresolved")
        return saved["response"]
    _boundary(*args, saved, request)
    signed, body = _sign(
        factory,
        identity,
        request,
        artifact_key,
        operation,
        saved["intent"],
        parts,
        completion,
    )
    _boundary(*args, saved, request)
    if int(time.time()) >= signed["expires_at"]:
        raise StorageOwnershipError("Provider result signature expired")
    try:
        headers, data = control_call(signed, body)
        response = _response(
            request,
            artifact,
            operation,
            saved["intent"],
            parts,
            completion,
            headers,
            data,
        )
    except Exception:
        raise StorageOwnershipError("Provider result outcome unresolved") from None
    with TenantContext(identity.org_id), factory() as db:
        claim, current, _, _ = _custody_authority(
            db, identity, backup_id, binding, artifact_key
        )
        row = _row(db, claim, artifact_key, operation)
        if row is None or _saved(row) != saved or current != request:
            raise StorageOwnershipError("Provider result custody conflict")
        row.response = response
        db.commit()
    _, stored, _, _, _, _ = _first(*args)
    return stored["response"]
