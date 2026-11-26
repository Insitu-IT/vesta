"""Unmounted observation-only ListParts. No acknowledgment or recovery mutation.

Temporary lifetime quotas are not a supported mounted recovery lifecycle.
"""

from copy import deepcopy
import hashlib
import json
import logging
import re
import time
import uuid

from sqlalchemy import text
from core.storage_capability_evidence import require_evidence
from core.callback_intents import _digest
from core.callback_provider_create import _admit, _custody_authority
from core.callback_provider_result import _identifier
from core.installation_config import read_configuration
from core.s3_ownership import StorageOwnershipError
from core.storage_control import authority
from core.storage_listparts import parse_page, classify
from core.storage_signing import observation_call, xml_fields
from core.tenant_context import TenantContext
from models import (
    SettingV3,
    S3PartObservationScan as Scan,
    S3PartObservationPage as Page,
    S3UploadPart,
)

log = logging.getLogger(__name__)
PART_SET = """SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object(
 'id',id,'number',number,'bytes',byte_count,'sha256',sha256,'intent_xid',intent_xid,
 'signing_result',signing_result,'signing_xid',signing_xid,
 'acknowledgment',acknowledgment,'acknowledgment_xid',acknowledgment_xid)
 ORDER BY number),'[]'::jsonb)::text,'UTF8')),'hex')
 FROM public.s3_upload_parts WHERE publication_id=:publication AND artifact_key=:key"""


def _profile(db, request):
    rows = read_configuration(db, SettingV3, "storage.s3.listparts_profile")
    row = rows[0] if len(rows) == 1 else None
    try:
        value = json.loads(row.value) if row else None
    except (ValueError, TypeError):
        value = None
    if (
        type(value) is not dict
        or value
        != dict(
            schema=1,
            profile="listparts-sha256-composite/1",
            target_sha256=_digest(db, request["plan"]["target"]),
            evidence_sha256=value.get("evidence_sha256"),
            limits=value.get("limits"),
        )
        or type(value.get("schema")) is not int
        or type(value.get("evidence_sha256")) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", value["evidence_sha256"])
    ):
        raise StorageOwnershipError("Verified ListParts profile required")
    limits = value.get("limits")
    maxima = dict(
        attempt_scans=4,
        tenant_scans=64,
        attempt_bytes=1073741824,
        tenant_bytes=4294967296,
    )
    if (
        type(limits) is not dict
        or set(limits) != set(maxima)
        or any(
            type(limits[k]) is not int
            or not (8421376 if k.endswith("bytes") else 1) <= limits[k] <= bound
            for k, bound in maxima.items()
        )
    ):
        raise StorageOwnershipError("Invalid ListParts limits")
    return _digest(db, value)


def _intent(db, identity, claim, request, key, operation):
    entry = (claim.provider_create or {}).get(key)
    if not entry or entry["response"] is None:
        raise StorageOwnershipError("Committed exact upload required")
    now = db.scalar(text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint"))
    value = deepcopy(entry["intent"])
    value.update(
        operation=operation,
        nonce=str(uuid.uuid4()),
        created_at=now,
        expires_at=now + 60,
        credential_kind=identity.credential_kind,
        credential_id=identity.credential_id,
        upload_id=entry["response"]["upload_id"],
        create_response_sha256=_digest(db, entry["response"]),
        parts_sha256=db.scalar(text(PART_SET), dict(publication=claim.id, key=key)),
        profile_sha256=_profile(db, request),
    )
    return value


def start_scan(factory, identity, backup_id, binding, key):
    """Explicit new generation only; no implicit restart or lifetime recycling."""
    try:
        with TenantContext(identity.org_id), factory() as db:
            claim, request, _, _ = _admit(db, identity, backup_id, binding, key)
            require_evidence(db, request, "list_parts")
            row = Scan(
                org_id=identity.org_id,
                publication_id=claim.id,
                artifact_key=key,
                intent=_intent(
                    db, identity, claim, request, key, "provider_listparts_scan"
                ),
            )
            db.add(row)
            db.flush()
            scan_id = row.id
            db.commit()
            return scan_id
    except Exception:
        # No provider material or exception text. SQL also emits attribution for
        # quota refusals. This is an operational log, not a committed audit row.
        log.info(
            "listparts_scan_refused org=%s backup=%s agent=%s",
            identity.org_id,
            backup_id,
            identity.agent_id,
        )
        raise


def _saved(row):
    return dict(
        id=row.id,
        intent=deepcopy(row.intent),
        intent_xid=row.intent_xid,
        observation=deepcopy(row.observation),
        observation_xid=row.observation_xid,
    )


def _scan(db, claim, key, scan_id):
    row = (
        db.query(Scan)
        .filter_by(id=scan_id, publication_id=claim.id, artifact_key=key)
        .one_or_none()
    )
    if row is None:
        raise StorageOwnershipError("Observation scan unavailable")
    return row


def _first(factory, identity, backup_id, binding, key, scan_id, number):
    if type(number) is not int or not 1 <= number <= 10001:
        raise StorageOwnershipError("Observation page number invalid")
    with TenantContext(identity.org_id), factory() as db:
        claim, request, _, _ = _admit(db, identity, backup_id, binding, key)
        scan = _scan(db, claim, key, scan_id)
        row = db.query(Page).filter_by(scan_id=scan.id, number=number).one_or_none()
        if row:
            if "capability_evidence" in request["plan"]:
                require_evidence(db, request, "list_parts")
            saved = _saved(row)
            db.commit()
            return False, saved, request
        require_evidence(db, request, "list_parts")
        prior = (
            db.query(Page).filter_by(scan_id=scan.id, number=number - 1).one_or_none()
        )
        marker = 0
        if number > 1:
            if (
                not prior
                or not prior.observation
                or prior.observation["outcome"] != "page"
                or not prior.observation["truncated"]
                or prior.observation["conflict"]
                or prior.observation["comparison_stale"]
            ):
                raise StorageOwnershipError(
                    "Committed observation predecessor required"
                )
            marker = prior.observation["next_marker"]
        value = _intent(db, identity, claim, request, key, "provider_listparts_page")
        value.update(
            scan_id=scan.id,
            number=number,
            marker=marker,
            previous_sha256=_digest(db, prior.observation) if prior else None,
        )
        if any(
            value[field] != scan.intent[field]
            for field in ("parts_sha256", "profile_sha256")
        ):
            raise StorageOwnershipError("Observation scan binding changed")
        row = Page(
            org_id=identity.org_id,
            publication_id=claim.id,
            artifact_key=key,
            scan_id=scan.id,
            number=number,
            marker=marker,
            intent=value,
            retained_bytes=8388608,
        )
        db.add(row)
        db.flush()
        db.refresh(row)
        saved = _saved(row)
        db.commit()
        return True, saved, request


def _boundary(factory, identity, backup_id, binding, key, saved, request):
    with TenantContext(identity.org_id), factory() as db:
        claim, current, _, _ = _admit(db, identity, backup_id, binding, key)
        require_evidence(db, current, "list_parts")
        row = (
            db.query(Page)
            .filter_by(id=saved["id"], publication_id=claim.id, artifact_key=key)
            .one_or_none()
        )
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
            or db.scalar(text(PART_SET), dict(publication=claim.id, key=key))
            != saved["intent"]["parts_sha256"]
            or _profile(db, request) != saved["intent"]["profile_sha256"]
        ):
            raise StorageOwnershipError("Observation continuation unavailable")
        db.commit()


def _sign(factory, identity, request, key, saved):
    with TenantContext(identity.org_id), factory() as db:
        if db.in_transaction():
            raise StorageOwnershipError("Fresh observation configuration required")
        signed = authority(
            db,
            request,
            key,
            "GET",
            {
                "uploadId": saved["intent"]["upload_id"],
                "part-number-marker": str(saved["intent"]["marker"]),
                "max-parts": "1000",
            },
            {},
            callback_identity=identity,
            operation="list_parts",
        )
        if db.in_transaction():
            raise StorageOwnershipError("Observation configuration transaction remains")
    return signed


def _response(request, key, saved, status, headers, data):
    value = dict(
        schema=1,
        outcome="page",
        status=status,
        code=None,
        bucket=request["plan"]["target"]["bucket"],
        key=key,
        upload_id=saved["intent"]["upload_id"],
        marker=saved["intent"]["marker"],
        truncated=False,
        next_marker=None,
        parts=[],
        conflict=False,
        request_id=_identifier(headers.get("x-amz-request-id")),
        host_id=_identifier(headers.get("x-amz-id-2")),
        body_sha256=hashlib.sha256(data).hexdigest(),
        comparison_stale=False,
        observed_at=int(time.time()),
        checksum_algorithm="SHA256" if status == 200 else None,
        checksum_type="COMPOSITE" if status == 200 else None,
    )
    if status == 200:
        value.update(
            parse_page(data, value["bucket"], key, value["upload_id"], value["marker"])
        )
    elif type(status) is int and 400 <= status <= 599:
        code = xml_fields(data, "Error").get("Code")
        if type(code) is not str or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9]{0,127}", code
        ):
            raise StorageOwnershipError("Invalid ListParts refusal evidence")
        value.update(
            code=code,
            outcome=(
                "no_such_upload"
                if status == 404 and code == "NoSuchUpload"
                else "provider_refusal"
            ),
        )
    else:
        raise StorageOwnershipError("Invalid ListParts response status")
    return value


def observe_page(factory, identity, backup_id, binding, key, scan_id, number):
    """Exactly one page creator sends. An unresolved page is never reconstructed."""
    created, saved, request = _first(
        factory, identity, backup_id, binding, key, scan_id, number
    )
    if not created:
        if saved["observation"] is None:
            raise StorageOwnershipError("Observation page unresolved; no replay")
        return saved["observation"]
    _boundary(factory, identity, backup_id, binding, key, saved, request)
    signed = _sign(factory, identity, request, key, saved)
    _boundary(factory, identity, backup_id, binding, key, saved, request)
    status, headers, data = observation_call(signed)
    value = _response(request, key, saved, status, headers, data)
    with TenantContext(identity.org_id), factory() as db:
        claim, current, _, _ = _custody_authority(db, identity, backup_id, binding, key)
        row = (
            db.query(Page)
            .filter_by(id=saved["id"], publication_id=claim.id, artifact_key=key)
            .one_or_none()
        )
        if row is None or _saved(row) != saved or current != request:
            raise StorageOwnershipError("Observation result custody changed")
        numbers = [p["number"] for p in value["parts"]]
        local = (
            db.query(S3UploadPart)
            .filter(
                S3UploadPart.publication_id == claim.id,
                S3UploadPart.artifact_key == key,
                S3UploadPart.number.in_(numbers),
            )
            .all()
            if numbers
            else []
        )
        value["comparison_stale"] = (
            db.scalar(text(PART_SET), dict(publication=claim.id, key=key))
            != saved["intent"]["parts_sha256"]
        )
        value["parts"] = classify(
            value["parts"],
            {
                p.number: dict(
                    bytes=p.byte_count,
                    sha256=p.sha256,
                    acknowledgment=deepcopy(p.acknowledgment),
                )
                for p in local
            },
        )
        if value["comparison_stale"]:
            value["parts"] = [
                dict(p, classification="unclassified") for p in value["parts"]
            ]
        value["conflict"] = any(
            p["classification"] == "conflict" for p in value["parts"]
        )
        row.observation = value
        db.flush()
        db.commit()
    # Fresh authority for disclosure; no additional provider call on readback.
    return _first(factory, identity, backup_id, binding, key, scan_id, number)[1][
        "observation"
    ]


def inspect_scan(factory, identity, backup_id, binding, key, scan_id):
    """Bounded current comparison; historical page readback remains separate."""
    with TenantContext(identity.org_id), factory() as db:
        claim, _, _, _ = _admit(db, identity, backup_id, binding, key)
        scan = _scan(db, claim, key, scan_id)
        if (
            db.scalar(text(PART_SET), dict(publication=claim.id, key=key))
            != scan.intent["parts_sha256"]
        ):
            raise StorageOwnershipError("Observation comparison stale")
        last = (
            db.query(Page)
            .filter_by(scan_id=scan.id)
            .order_by(Page.number.desc())
            .first()
        )
        missing = list(
            db.scalars(
                text("""SELECT p.number FROM s3_upload_parts p
            WHERE p.publication_id=:publication AND p.artifact_key=:key AND NOT EXISTS(
              SELECT 1 FROM s3_part_observation_pages pages,
              LATERAL jsonb_array_elements(pages.observation->'parts') item
              WHERE pages.scan_id=:scan AND (item->>'number')::integer=p.number)
            ORDER BY p.number LIMIT 10000"""),
                dict(publication=claim.id, key=key, scan=scan.id),
            )
        )
        counts = dict(
            db.execute(
                text("""SELECT item->>'classification',count(*)
            FROM s3_part_observation_pages pages,
            LATERAL jsonb_array_elements(pages.observation->'parts') item
            WHERE pages.scan_id=:scan GROUP BY item->>'classification'"""),
                dict(scan=scan.id),
            ).all()
        )
        result = dict(
            scan_id=scan.id,
            pagination_complete=bool(
                last
                and last.observation
                and last.observation["outcome"] == "page"
                and not last.observation["truncated"]
            ),
            known_unobserved_numbers=missing,
            tuple_counts=counts,
            recovery_authorized=False,
        )
        db.commit()
        return result
