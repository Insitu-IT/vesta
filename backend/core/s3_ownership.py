"""Write-ahead S3 ownership reservations, independent of mutable VM names.

Reservations must be committed before any storage request. This module does not
infer ownership of existing objects or perform storage operations. Publication
and compensation callers must use the recorded endpoint, bucket and exact key.
"""

import hashlib
from urllib.parse import urlsplit

from models import Backup, S3Publication


class StorageOwnershipError(RuntimeError):
    """No durable authority exists for the requested storage operation."""


def storage_identity(config):
    """Compare a target without persisting credentials or an implicit endpoint."""
    if not config or not config.get("endpoint") or not config.get("bucket"):
        raise StorageOwnershipError("Explicit S3 endpoint and bucket are required")
    endpoint = str(config["endpoint"]).rstrip("/")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise StorageOwnershipError("S3 endpoint must be an explicit HTTP(S) origin")
    # URL-form is mandatory here: a bare host has no durable TLS identity.
    # Do not collapse DNS aliases or guess that two endpoints share storage.
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        host += f":{port}"
    bucket = str(config["bucket"])
    if not bucket or any(c in bucket for c in "/\\\x00"):
        raise StorageOwnershipError("Invalid S3 bucket")
    return f"{parsed.scheme}://{host}", bucket


def _backup(db, backup_id):
    backup = (
        db.query(Backup).filter(Backup.id == backup_id).with_for_update().one_or_none()
    )
    if backup is None or not backup.org_id:
        raise StorageOwnershipError("Backup owner is not visible in this organization")
    return backup


def owned_chain_target(db, parent):
    """Return the single published target, or None for an unusable lineage.

    Historical chains remain readable. A missing claim does not become ownership
    by observing an S3 path, and a partial/compensating publication is not a seed.
    """
    root = db.query(Backup).filter(Backup.id == parent.chain_id).one_or_none()
    if (
        root is None
        or root.org_id != parent.org_id
        or root.vm_id != parent.vm_id
        or root.chain_id != root.id
        or root.status != "completed"
    ):
        return None
    members = (
        db.query(Backup)
        .filter(Backup.chain_id == root.id, Backup.status == "completed")
        .all()
    )
    required = {(member.id, "payload") for member in members}
    required.add((root.id, "chain_manifest"))
    claims = (
        db.query(S3Publication)
        .filter(S3Publication.backup_id.in_([m.id for m in members]))
        .all()
    )
    published = {
        (claim.backup_id, claim.kind)
        for claim in claims
        if claim.org_id == parent.org_id and claim.state == "published"
    }
    if not required <= published or (parent.id, "payload") not in published:
        return None
    targets = {
        (claim.endpoint, claim.bucket)
        for claim in claims
        if (claim.backup_id, claim.kind) in required
    }
    # A multi-target chain needs its own credentials and restore contract. Until
    # one exists, even fully attributed split claims require a new full seed.
    if len(targets) != 1:
        return None
    return targets.pop()


def require_publication(db, backup_id, kind, config):
    """A missing row is a refusal, never permission to reconstruct a key."""
    backup = _backup(db, backup_id)
    publication = (
        db.query(S3Publication)
        .filter(S3Publication.backup_id == backup.id, S3Publication.kind == kind)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if publication is None or publication.org_id != backup.org_id:
        raise StorageOwnershipError("No durable S3 publication ownership; retain data")
    if (publication.endpoint, publication.bucket) != storage_identity(config):
        raise StorageOwnershipError(
            "Configured storage differs from the recorded publication target"
        )
    if publication.state == "deleted":
        raise StorageOwnershipError(
            "Publication is already reclaimed and cannot be reused"
        )
    return publication


def reserve_publication(db, backup_id, kind, config, *, reservation_id=None):
    """Reserve a new object's immutable address, serialized on its backup row.

    Only new publication may call this. Cleanup/discovery must call require, not
    reserve. The caller commits this reservation before publishing any bytes.
    A retry keeps the original prefix even when settings or the VM name changed.
    """
    if kind not in {"payload", "chain_manifest"}:
        raise StorageOwnershipError("Unknown publication kind")
    backup = _backup(db, backup_id)
    if kind == "payload" and backup.parent_backup_id:
        parent = _backup(db, backup.parent_backup_id)
        if (
            backup.org_id != parent.org_id
            or backup.vm_id != parent.vm_id
            or backup.chain_id != parent.chain_id
            or owned_chain_target(db, parent) != storage_identity(config)
        ):
            raise StorageOwnershipError(
                "Unowned, incomplete or changed-target chain requires a fresh full backup"
            )
    if kind == "chain_manifest" and backup.chain_id != backup.id:
        raise StorageOwnershipError("Only the persisted chain root owns its manifest")
    if kind == "chain_manifest":
        payload = require_publication(db, backup.id, "payload", config)
        if payload.state == "cleanup_required":
            raise StorageOwnershipError("Root payload compensation must finish first")
    existing = (
        db.query(S3Publication)
        .filter(S3Publication.backup_id == backup.id, S3Publication.kind == kind)
        .one_or_none()
    )
    if existing is not None:
        publication = require_publication(db, backup_id, kind, config)
        if reservation_id is not None and publication.id != reservation_id:
            raise StorageOwnershipError("Reservation differs from committed attempt")
        if publication.state == "cleanup_required":
            raise StorageOwnershipError(
                "Publication compensation must finish before reuse"
            )
        return publication
    if kind == "payload" and (
        backup.status not in {"pending", "running", "uploading"}
        or (backup.storage_path or "").startswith("s3://")
    ):
        raise StorageOwnershipError(
            "Existing payloads require explicit attribution; no automatic adoption"
        )
    endpoint, bucket = storage_identity(config)
    # Hash persisted identifiers, never a display name or request-supplied path.
    # Different artifact kinds are disjoint; a payload listing cannot encompass
    # its manifest, another backup, or another organization's objects.
    org = hashlib.sha256(backup.org_id.encode()).hexdigest()
    owner = hashlib.sha256(backup.id.encode()).hexdigest()
    suffix = "payload/" if kind == "payload" else "chain.json"
    publication = S3Publication(
        **({"id": reservation_id} if reservation_id is not None else {}),
        org_id=backup.org_id,
        backup_id=backup.id,
        kind=kind,
        endpoint=endpoint,
        bucket=bucket,
        object_key=f"vnbui-owned/v1/{org}/{owner}/{suffix}",
        state="reserved",
    )
    db.add(publication)
    db.flush()
    return publication


def commit_artifact_plan(db, backup_id, kind, config, artifacts):
    """Commit reservation and immutable plan before returning upload authority.

    This is an explicit transaction boundary. The caller must finish source
    selection before calling; no agent or storage writes belong before it.
    Existing receipts, listings and legacy paths cannot supply this plan.
    """
    from core.storage_plan import build_plan

    publication = reserve_publication(db, backup_id, kind, config)
    plan = build_plan(publication, artifacts)
    if publication.expected_plan is not None and publication.expected_plan != plan:
        raise StorageOwnershipError(
            "Recorded artifact plan differs; retain original reservation"
        )
    if publication.state != "reserved":
        raise StorageOwnershipError(
            "Only a reserved publication accepts an upload plan"
        )
    publication.expected_plan = plan
    db.commit()
    return publication
