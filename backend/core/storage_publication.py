"""Publish immutable generations after accepted KubeVirt/native checkpoint evidence.

The DB-rooted profile has no mutable S3 pointer. A committed per-backup
reservation is the outbox: its exact bytes/key survive retries, and only the
final database transaction makes those bytes visible to ordinary consumers.
"""

from copy import deepcopy
import hashlib
import re
import uuid

from sqlalchemy import text

from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical, decode
from models import Backup, S3Publication, StorageConfigurationClock, StorageLineageHead

PROFILE = "db-rooted-consumer-verified/1"
MAX_MANIFEST = 16 * 1024 * 1024
MAX_MEMBERS = 256


def _refuse(message="Generation publication unavailable; retain reservation"):
    raise StorageOwnershipError(message)


def _member(claim, request, backup=None):
    native = request["plan"]["provider"] == "libvirt"
    entry = dict(
        request=deepcopy(request),
        receipt=deepcopy(claim.prepared_receipt["receipt"]),
        receipt_sha256=claim.prepared_receipt["receipt_sha256"],
        acceptance=deepcopy(claim.prepared_receipt["response"]),
        wrapped_attempt_key=deepcopy(claim.wrapped_attempt_key),
        checkpoint=None if native else deepcopy(claim.finalize_intent["binding"]),
        checkpoint_proof=None if native else deepcopy(claim.checkpoint_proof),
    )
    if native:
        entry["native_result"] = deepcopy(backup.native_inventory["push_result"])
    return entry


def _manifest(plan):
    try:
        body = plan["manifest_canonical"].encode("utf-8")
        value = decode(body)
        if (
            plan["schema"] != 4
            or not 0 < len(body) <= MAX_MANIFEST
            or canonical(value) != body
            or hashlib.sha256(body).hexdigest() != plan["manifest_sha256"]
            or value["generation_id"] != plan["generation_id"]
            or value["predecessor_id"] != plan["predecessor_id"]
            or not 0 < len(value["members"]) <= MAX_MEMBERS
        ):
            _refuse()
        return value, body
    except (KeyError, TypeError, ValueError, AttributeError):
        _refuse()


def _prepare(db, backup_id, agent_id, credential):
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .one_or_none()
    )
    native = bool(
        claim
        and (claim.expected_plan or {})
        .get("transaction", {})
        .get("plan", {})
        .get("provider")
        == "libvirt"
    )
    if native:
        from core import native_publication as publication_profile
    else:
        from core import storage_finalize as publication_profile

    payload, request, _ = publication_profile.admit(db, backup_id, agent_id, credential)
    if (
        request["plan"]["capability_profile"] != PROFILE
        or "capability_evidence" in request["plan"]
        or (not native and payload.checkpoint_proof is None)
    ):
        _refuse("Publication requires the supported DB-rooted checkpointed transaction")
    backup = db.get(Backup, backup_id)
    head = db.get(StorageLineageHead, backup.vm_id, populate_existing=True)
    previous = head.generation_id if head else None
    publication = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, org_id=backup.org_id, kind="chain_manifest")
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if publication is not None:
        manifest, _ = _manifest(publication.expected_plan)
        if (
            publication.state != "reserved"
            or manifest["predecessor_id"] != previous
            or manifest["members"][-1] != _member(payload, request, backup)
        ):
            _refuse("Generation predecessor or accepted member changed")
        return publication, payload
    clock = db.get(StorageConfigurationClock, 1)
    if clock is None or not clock.installation_id:
        _refuse("Installation identity is unavailable")
    parent = request["plan"]["parent"]
    root = parent["root_backup_id"] if parent else backup.id
    members = []
    if parent:
        if (
            head is None
            or head.state != "current"
            or previous != parent["generation_id"]
        ):
            _refuse("Incremental generation is no longer current")
        parent_publication = db.get(S3Publication, previous, populate_existing=True)
        if parent_publication is None or parent_publication.state != "published":
            _refuse("Accepted parent generation object is unavailable")
        ancestor, _ = _manifest(parent_publication.expected_plan)
        if (
            ancestor["root_backup_id"] != root
            or ancestor["installation_id"] != clock.installation_id
        ):
            _refuse()
        members = deepcopy(ancestor["members"])
    members.append(_member(payload, request, backup))
    if len(members) > MAX_MEMBERS:
        _refuse("Chain limit reached; create a fresh full backup")
    generation_id = str(uuid.uuid4())
    manifest = dict(
        protocol="vnbui-storage-generation/1",
        installation_id=clock.installation_id,
        org_id=backup.org_id,
        generation_id=generation_id,
        predecessor_id=previous,
        root_backup_id=root,
        backup_id=backup.id,
        source=deepcopy(request["plan"]["source"]),
        target=deepcopy(request["plan"]["target"]),
        members=members,
    )
    body = canonical(manifest)
    if len(body) > MAX_MANIFEST:
        _refuse("Generation manifest exceeds 16 MiB; create a fresh full backup")
    # Reuse the immutable ownership namespace, with a unique object per
    # generation. No stable chain.json is written or replaced in this profile.
    org = hashlib.sha256(backup.org_id.encode()).hexdigest()
    owner = hashlib.sha256(root.encode()).hexdigest()
    publication = S3Publication(
        id=generation_id,
        org_id=backup.org_id,
        backup_id=backup.id,
        kind="chain_manifest",
        endpoint=payload.endpoint,
        bucket=payload.bucket,
        object_key=f"vnbui-owned/v1/{org}/{owner}/generations/{generation_id}.json",
        expected_plan=dict(
            schema=4,
            generation_id=generation_id,
            predecessor_id=previous,
            manifest_canonical=body.decode("utf-8"),
            manifest_sha256=hashlib.sha256(body).hexdigest(),
        ),
        state="reserved",
    )
    db.add(publication)
    db.flush()
    return publication, payload


def _metadata(snapshot):
    return {
        "vnbui-kind": "generation",
        "vnbui-org-id": snapshot["org_id"],
        "vnbui-backup-id": snapshot["backup_id"],
        "vnbui-reservation-id": snapshot["id"],
        "vnbui-manifest-sha256": snapshot["plan"]["manifest_sha256"],
    }


def _missing(error):
    response = getattr(error, "response", {})
    return response.get("Error", {}).get("Code") in {"NoSuchKey", "NotFound", "404"}


def _verify_object(client, snapshot, identity=None):
    _, expected = _manifest(snapshot["plan"])
    args = dict(Bucket=snapshot["bucket"], Key=snapshot["key"])
    if identity:
        if identity.get("ETag"):
            args["IfMatch"] = identity["ETag"]
        if identity.get("VersionId") is not None:
            args["VersionId"] = identity["VersionId"]
    response = client.get_object(**args)
    stream = response["Body"]
    try:
        # Read through EOF, including SDK streams that return short reads.
        pieces, size = [], 0
        while True:
            piece = stream.read(min(1024 * 1024, len(expected) + 1 - size))
            if not piece:
                break
            pieces.append(piece)
            size += len(piece)
            if size > len(expected):
                _refuse("Generation object differs from committed bytes")
        observed = b"".join(pieces)
    finally:
        stream.close()
    etag, version = response.get("ETag"), response.get("VersionId")
    if (
        observed != expected
        or response.get("ContentLength") != len(expected)
        or response.get("Metadata") != _metadata(snapshot)
        or not isinstance(etag, str)
        or re.fullmatch(r'"[^"\r\n]{1,1022}"', etag) is None
        or (
            version is not None
            and (not isinstance(version, str) or not version or len(version) > 1024)
        )
        or (identity and identity.get("ETag") and identity["ETag"] != etag)
        or (
            identity
            and identity.get("VersionId") is not None
            and identity["VersionId"] != version
        )
    ):
        _refuse("Generation object differs from committed identity")
    return dict(
        schema=1,
        generation_id=snapshot["id"],
        endpoint=snapshot["endpoint"],
        bucket=snapshot["bucket"],
        key=snapshot["key"],
        version_id=version,
        etag=etag,
        bytes=len(expected),
        sha256=snapshot["plan"]["manifest_sha256"],
        assurance="consumer_sha256_verified",
    )


def _publish_object(client, snapshot):
    """Reconcile an exact reserved key before retrying its conditional create."""
    if client.meta.endpoint_url != snapshot["endpoint"]:
        _refuse("Generation storage target changed")
    try:
        return _verify_object(client, snapshot)
    except Exception as error:
        if not _missing(error):
            raise
    _, body = _manifest(snapshot["plan"])
    try:
        identity = client.put_object(
            Bucket=snapshot["bucket"],
            Key=snapshot["key"],
            Body=body,
            ContentType="application/json",
            Metadata=_metadata(snapshot),
            IfNoneMatch="*",
        )
    except Exception:
        # A lost response or conditional collision can only resolve to these
        # exact bytes. No replacement, new key, or guessed publication occurs.
        return _verify_object(client, snapshot)
    return _verify_object(client, snapshot, identity)


def completed_publication(db, backup_id, agent_id, credential, proof=None):
    """Authenticated retry after the ordinary dispatch admission has closed."""
    from core.storage_attempt_key import _credential

    backup = db.get(Backup, backup_id, populate_existing=True)
    if backup is None or backup.status != "completed":
        return None
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .one_or_none()
    )
    manifest = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="chain_manifest")
        .one_or_none()
    )
    if (
        claim is None
        or manifest is None
        or claim.state != "published"
        or manifest.state != "published"
        or claim.expected_plan.get("schema") != 3
        or claim.expected_plan["transaction"]["agent_id"] != agent_id
        or (proof is not None and claim.checkpoint_proof != proof)
    ):
        _refuse()
    _credential(db, agent_id, credential)
    from models import StorageLineageGeneration

    generation = db.get(StorageLineageGeneration, manifest.id)
    if (
        generation is None
        or generation.backup_id != backup_id
        or generation.state != "accepted"
    ):
        _refuse()
    result = dict(
        intent_id=(
            claim.id
            if claim.expected_plan["transaction"]["plan"]["provider"] == "libvirt"
            else claim.finalize_intent["intent_id"]
        ),
        status="completed",
        completed=True,
        generation_id=manifest.id,
    )
    db.commit()
    return result


def publish_checkpointed_backup(db, backup_id, agent_id, credential, *, client=None):
    """Checkpoint callback continuation; every IO and commit is replayable."""
    owned = None
    try:
        prior = completed_publication(db, backup_id, agent_id, credential)
        if prior is not None:
            return prior
        publication, _ = _prepare(db, backup_id, agent_id, credential)
        snapshot = dict(
            id=publication.id,
            org_id=publication.org_id,
            backup_id=backup_id,
            endpoint=publication.endpoint,
            bucket=publication.bucket,
            key=publication.object_key,
            plan=deepcopy(publication.expected_plan),
            receipt=deepcopy(publication.prepared_receipt),
        )
        db.commit()  # immutable generation/outbox intent precedes provider IO
        if snapshot["receipt"] is None:
            # Resolve current credentials only for the frozen literal target.
            if client is None:
                from core.storage_transaction import _recorded_target_client

                owned = _recorded_target_client(
                    db, db.get(S3Publication, snapshot["id"])
                )
                client = owned
            db.rollback()  # no transaction spans the provider request
            observed = _publish_object(client, snapshot)
            receipt_bytes = canonical(observed)
            receipt = dict(
                receipt=observed,
                receipt_canonical=receipt_bytes.decode("utf-8"),
                receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
            )
            publication, _ = _prepare(db, backup_id, agent_id, credential)
            if publication.id != snapshot["id"]:
                _refuse()
            if (
                publication.prepared_receipt is not None
                and publication.prepared_receipt != receipt
            ):
                _refuse("Conflicting generation object receipt")
            publication.prepared_receipt = deepcopy(receipt)
            db.commit()  # existing ownership trigger requires a prior receipt
        if db.get_bind().dialect.name != "postgresql":
            _refuse("Generation completion requires PostgreSQL atomic publication")
        _prepare(db, backup_id, agent_id, credential)
        result = db.execute(
            text(
                "SELECT public.vnbui_publish_storage_generation(:generation,:agent,:kind,:credential)"
            ),
            dict(
                generation=snapshot["id"],
                agent=agent_id,
                kind=credential[0],
                credential=credential[1],
            ),
        ).scalar_one()
        db.commit()
        return result
    except StorageOwnershipError:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        _refuse()
    finally:
        if owned is not None:
            owned.close()
