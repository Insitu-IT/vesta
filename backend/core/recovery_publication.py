"""Bounded retries and backfill for signed offsite VM recovery records."""

from bisect import bisect_right
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import re
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import func, or_, select, text

from core.installation_config import RECOVERY_PUBLICATION_CURSOR
from core.legacy_recovery import legacy_s3_unverified
from core.recovery_evidence import accepted_evidence
from core.recovery_signing import (
    RecoveryUnavailable,
    installation_id,
    signing_key,
    sign_point,
    _verified_point_shape,
    _public_identity,
    verify_point_envelope,
)
from core.singleton import lock_key
from core.storage_publication import _verify_object
from core.storage_transaction import _recorded_target_client
from core.tenant_context import PlatformContext, TenantContext
from core.tenant_work import organization_work_ids
from models import (
    Backup,
    RecoveryPublication,
    S3Publication,
    SettingV3,
    StorageLineageGeneration,
)

logger = logging.getLogger(__name__)
BATCH_LIMIT = 4
MAX_ORGS_PER_TICK = 32
CLAIM_LEASE = timedelta(minutes=5)
MAX_RETRY_DELAY = timedelta(hours=6)


def _retry_delay(attempt_count):
    return min(CLAIM_LEASE * (2 ** min(attempt_count - 1, 7)), MAX_RETRY_DELAY)


def _claim_next(factory, org_id, prefer_recent):
    now = datetime.now(timezone.utc)
    if prefer_recent:
        # Always give an unseen completion a slot before overdue retries.
        order = (
            RecoveryPublication.generation_id.is_not(None),
            RecoveryPublication.next_attempt_at,
            Backup.completed_at.desc(),
            Backup.id,
        )
    else:
        # Age due work independently so older backfill can make progress.
        order = (
            func.coalesce(RecoveryPublication.next_attempt_at, Backup.completed_at),
            Backup.id,
        )
    with factory() as db:
        candidate = db.execute(
            select(StorageLineageGeneration.id, Backup.id)
            .join(Backup, Backup.id == StorageLineageGeneration.backup_id)
            .outerjoin(
                RecoveryPublication,
                RecoveryPublication.generation_id == StorageLineageGeneration.id,
            )
            .where(
                StorageLineageGeneration.org_id == org_id,
                StorageLineageGeneration.state == "accepted",
                Backup.org_id == org_id,
                Backup.status == "completed",
                Backup.unverified_legacy_s3.is_(False),
                RecoveryPublication.published_at.is_(None),
                or_(
                    RecoveryPublication.next_attempt_at.is_(None),
                    RecoveryPublication.next_attempt_at <= now,
                ),
            )
            .order_by(*order)
            .limit(1)
        ).first()
        if candidate is None:
            return None
        generation_id, backup_id = candidate
        if db.get_bind().dialect.name == "postgresql" and not db.scalar(
            text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": lock_key("publish-recovery:" + generation_id)},
        ):
            return None
        row = db.get(
            RecoveryPublication,
            generation_id,
            populate_existing=True,
            with_for_update=True,
        )
        if row is None:
            row = RecoveryPublication(
                generation_id=generation_id,
                backup_id=backup_id,
                org_id=org_id,
                object_key=f"vesta-recovery/v1/{installation_id(db)}/{org_id}/{backup_id}.json",
                created_at=now,
                attempt_count=0,
            )
            db.add(row)
        else:
            due = row.next_attempt_at
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
            if row.published_at is not None or due > now:
                return None
        token = str(uuid4())
        row.claim_token = token
        row.attempt_count = min(row.attempt_count + 1, 2**31 - 1)
        row.next_attempt_at = now + _retry_delay(row.attempt_count)
        db.commit()
        return generation_id, backup_id, token


def _owned_row(db, org_id, generation_id, token):
    row = (
        db.query(RecoveryPublication)
        .filter_by(
            generation_id=generation_id,
            org_id=org_id,
            claim_token=token,
            published_at=None,
        )
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if row is None:
        raise RecoveryUnavailable("Recovery publication claim changed")
    return row


def _scope_client(client, location, record_key):
    endpoint = location["endpoint"]
    bucket = location["bucket"]
    if client.meta.endpoint_url != endpoint or client.meta.region_name != (
        location["region"] or "us-east-1"
    ):
        raise RecoveryUnavailable(
            "Recovery storage configuration differs from the accepted target"
        )

    paths = {f"/{bucket}/{location['key']}", f"/{bucket}/{record_key}"}

    def verify_request(request, **_kwargs):
        parsed = urlsplit(request.url)
        if (
            request.method not in {"GET", "PUT"}
            or parsed.scheme != "https"
            or "https://" + parsed.netloc != endpoint
            or parsed.path not in paths
        ):
            raise RecoveryUnavailable(
                "S3 request differs from approved recovery storage"
            )

    client.meta.events.register("before-send.s3", verify_request)


def _read_envelope(client, bucket, key, expected, written=None):
    args = dict(Bucket=bucket, Key=key)
    if written is not None:
        if written.get("ETag"):
            args["IfMatch"] = written["ETag"]
        if written.get("VersionId") is not None:
            args["VersionId"] = written["VersionId"]
    response = client.get_object(**args)
    body = response["Body"]
    observed = bytearray()
    try:
        while len(observed) <= len(expected):
            piece = body.read(len(expected) + 1 - len(observed))
            if not piece:
                break
            observed.extend(piece)
    finally:
        body.close()
    version, etag = response.get("VersionId"), response.get("ETag")
    if (
        observed != expected
        or response.get("ContentLength") != len(expected)
        or not isinstance(etag, str)
        or not re.fullmatch(r'"[^"\r\n]{1,1022}"', etag)
        or (
            version is not None
            and (not isinstance(version, str) or not 0 < len(version) <= 1024)
        )
        or (written and written.get("ETag") and written["ETag"] != etag)
        or (
            written
            and written.get("VersionId") is not None
            and written["VersionId"] != version
        )
    ):
        raise RecoveryUnavailable(
            "Existing recovery record differs from its registered envelope"
        )
    return {
        "version_id": version,
        "etag": etag,
        "bytes": len(expected),
        "sha256": hashlib.sha256(expected).hexdigest(),
    }


def _publish_envelope(client, bucket, key, expected):
    # A least-privilege writer may receive 403 for a missing key when
    # bucket listing is disallowed. The conditional write requires no
    # discovery rights and still cannot replace an existing object.
    try:
        written = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=expected,
            ContentType="application/json",
            IfNoneMatch="*",
        )
    except Exception:
        # A lost reply or conditional conflict may reconcile exact committed
        # bytes. There is never an overwrite, replacement key, or delete.
        return _read_envelope(client, bucket, key, expected)
    return _read_envelope(client, bucket, key, expected, written)


def publish_one(factory, org_id, *, prefer_recent=True):
    claim = _claim_next(factory, org_id, prefer_recent)
    if claim is None:
        return False
    generation_id, backup_id, token = claim
    client = None
    try:
        with factory() as db:
            evidence = accepted_evidence(db, org_id, backup_id)
            if evidence.point["generation_id"] != generation_id:
                raise RecoveryUnavailable("Original recovery generation changed")
            _verified_point_shape(evidence.point, evidence.point)
            row = _owned_row(db, org_id, generation_id, token)
            key = row.object_key
            retained = row.envelope
            db.rollback()
            # The immutable intent survives process loss before or after S3 IO.
            signing = signing_key(factory)
            if retained is None:
                envelope = sign_point(evidence.point, signing)
            else:
                # A renamed libvirt VM does not change accepted bytes or
                # replace the display label already registered in a record.
                envelope = retained.encode("ascii")
                key_id, public_key = _public_identity(signing)
                prior = verify_point_envelope(
                    envelope,
                    {**evidence.point, "key_id": key_id, "public_key": public_key},
                )
                if prior != {**evidence.point, "name": prior["name"]}:
                    raise RecoveryUnavailable("Registered recovery envelope changed")
            row = _owned_row(db, org_id, generation_id, token)
            row.envelope = envelope.decode("ascii")
            db.commit()
            location = evidence.point["generation"]
            publication = db.get(S3Publication, generation_id)
            client = _recorded_target_client(db, publication, path_style=True)
            _scope_client(client, location, key)
            db.rollback()
            _verify_object(
                client, evidence.publication_snapshot, evidence.stored_identity
            )
            with factory() as refresh:
                fresh = accepted_evidence(refresh, org_id, backup_id)
                if (
                    replace(
                        fresh, point={**fresh.point, "name": evidence.point["name"]}
                    )
                    != evidence
                ):
                    raise RecoveryUnavailable("Accepted recovery evidence changed")
                _owned_row(refresh, org_id, generation_id, token)
            receipt = _publish_envelope(client, location["bucket"], key, envelope)
            row = _owned_row(db, org_id, generation_id, token)
            row.published_at = datetime.now(timezone.utc)
            row.publication_receipt = receipt
            db.commit()
    except Exception:
        # The claim's next-attempt deadline is durable even if the process
        # dies; never publish an alternate identity on retry or reveal S3 data.
        try:
            with factory.begin() as db:
                row = _owned_row(db, org_id, generation_id, token)
                row.last_failure_at = datetime.now(timezone.utc)
                row.next_attempt_at = row.last_failure_at + _retry_delay(
                    row.attempt_count
                )
        except Exception:
            logger.warning("Recovery publication retry metadata unavailable")
        logger.warning("Signed recovery publication retained for retry")
    finally:
        if client is not None:
            client.close()
    return True


def _reserve_org_visit(factory, organizations):
    # Persist each visit before storage I/O. Restarts cannot drive the
    # scheduler back to the same initial tenants on every pass.
    with PlatformContext(), factory.begin() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": lock_key(RECOVERY_PUBLICATION_CURSOR)},
            )
        cursor = db.get(SettingV3, RECOVERY_PUBLICATION_CURSOR, with_for_update=True)
        if cursor is None:
            cursor = SettingV3(
                key=RECOVERY_PUBLICATION_CURSOR,
                value_type="string",
                source="installation",
            )
            db.add(cursor)
        cursor.value = organizations[
            bisect_right(organizations, cursor.value or "") % len(organizations)
        ]
        return cursor.value


def run_recovery_publication(factory):
    organizations = sorted(organization_work_ids(factory))
    if not organizations:
        return
    try:
        signing_key(factory)
    except Exception:
        logger.warning("Installation recovery signing custody unavailable")
        return
    attempted = 0
    visited = set()
    for _ in range(min(len(organizations), MAX_ORGS_PER_TICK)):
        org_id = _reserve_org_visit(factory, organizations)
        if org_id in visited:
            break
        visited.add(org_id)
        visits = BATCH_LIMIT if len(organizations) == 1 else 2
        with TenantContext(org_id):
            for visit in range(min(visits, BATCH_LIMIT - attempted)):
                try:
                    if not publish_one(factory, org_id, prefer_recent=visit % 2 == 0):
                        break
                    attempted += 1
                except Exception:
                    logger.warning("Recovery publication discovery deferred")
                    break
        if attempted >= BATCH_LIMIT:
            break


def publication_status(db, backup):
    if backup.status not in (
        "completed",
        "deleting",
        "deleted",
    ) or legacy_s3_unverified(backup):
        return None
    result = db.execute(
        select(StorageLineageGeneration.id, RecoveryPublication)
        .outerjoin(
            RecoveryPublication,
            RecoveryPublication.generation_id == StorageLineageGeneration.id,
        )
        .where(
            StorageLineageGeneration.org_id == backup.org_id,
            StorageLineageGeneration.backup_id == backup.id,
            StorageLineageGeneration.state == "accepted",
        )
    ).one_or_none()
    if result is None:
        return None
    _, publication = result
    attempts = publication.attempt_count if publication is not None else 0
    retry_at = None
    if backup.status != "completed":
        state = "unavailable"
    elif publication is not None and publication.published_at is not None:
        state = "ready"
    elif publication is not None and (
        publication.last_failure_at is not None or attempts > 1
    ):
        state, retry_at = "retrying", publication.next_attempt_at
    else:
        state = "pending"
    return {"state": state, "attempts": attempts, "next_attempt_at": retry_at}
