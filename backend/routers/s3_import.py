"""
S3 backup discovery and import for greenfield DR.

Discovers chain manifests in S3 and imports backup records into the database,
enabling restore from a fresh install with only S3 access.
"""

import logging
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user, check_role, log_activity
from models import Backup, VM, Agent, EncryptionKey

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/s3", tags=["s3-import"])


# --- Request/Response models ---


class ChainConflict(BaseModel):
    backup_id: str
    reason: str
    existing_chain_id: Optional[str] = None
    manifest_chain_id: Optional[str] = None


class ChainInfo(BaseModel):
    chain_id: str
    vm_name: str
    backup_count: int
    imported_count: int
    total_size_bytes: int
    oldest_backup: Optional[str] = None
    newest_backup: Optional[str] = None
    encrypted: bool
    kek_available: bool
    kek_ids: list
    status: str  # available, imported, partial, conflict, kek_missing
    conflicts: list


class DiscoverResponse(BaseModel):
    chains: list
    s3_endpoint: Optional[str] = None
    s3_bucket: Optional[str] = None


class ImportRequest(BaseModel):
    chain_id: str


class ImportResponse(BaseModel):
    imported_count: int
    skipped_count: int
    vm_name: str
    vm_id: str
    vm_created: bool
    status: str


# --- Helpers ---


def _get_s3_client_and_config(db: Session):
    """Get S3 client and config, or raise 404."""
    from core.settings_service import SettingsService
    import boto3

    svc = SettingsService(db)
    s3_config = svc.get_s3_config()
    if not s3_config:
        raise HTTPException(status_code=404, detail="S3 storage not configured")

    s3 = boto3.client(
        "s3",
        endpoint_url=s3_config.get("endpoint") or None,
        aws_access_key_id=s3_config.get("access_key"),
        aws_secret_access_key=s3_config.get("secret_key"),
        region_name=s3_config.get("region", "us-east-1"),
    )
    return s3, s3_config


def _download_manifests(s3, bucket: str, prefix: str) -> list:
    """Download and parse all chain manifests from S3."""
    manifest_prefix = f"{prefix}/manifests/"
    manifests = []

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=manifest_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            # Key format: prefix/manifests/vm_name/chain_id.json
            rel = key[len(manifest_prefix) :]
            parts = rel.split("/")
            if len(parts) != 2 or not parts[1].endswith(".json"):
                continue

            try:
                resp = s3.get_object(Bucket=bucket, Key=key)
                manifest = json.loads(resp["Body"].read().decode("utf-8"))
                manifests.append(manifest)
            except Exception as e:
                logger.warning(f"Failed to parse manifest {key}: {e}")

    return manifests


def _same_manifest_vm(vm, manifest):
    identity = manifest.get("vm_identity")
    if isinstance(identity, dict) and identity.get("vm_uid"):
        if (vm.vm_metadata or {}).get("imported_from_s3"):
            return (vm.vm_metadata or {}).get("source_identity") == identity
        return all(
            getattr(vm, field) == identity.get(field)
            for field in ("agent_id", "provider", "namespace", "vm_uid")
        )
    # Legacy manifests cannot establish identity. Existing backup IDs can make
    # an import idempotent, but their VM owner must never be changed by name.
    return vm.name == manifest.get("vm_name")


def _classify_chain(manifest: dict, db: Session) -> dict:
    """Classify a chain manifest against existing DB state."""
    chain_id = manifest.get("chain_id", "")
    vm_name = manifest.get("vm_name", "")
    backups = manifest.get("backups", [])
    backup_ids = [b["backup_id"] for b in backups]

    # Check which backup IDs already exist
    existing = (
        db.query(Backup).filter(Backup.id.in_(backup_ids)).all() if backup_ids else []
    )
    existing_map = {b.id: b for b in existing}

    imported_count = 0
    conflicts = []

    for entry in backups:
        bid = entry["backup_id"]
        if bid in existing_map:
            eb = existing_map[bid]
            # Check for hard conflicts
            if eb.chain_id and eb.chain_id != chain_id:
                conflicts.append(
                    {
                        "backup_id": bid,
                        "reason": "exists_different_chain",
                        "existing_chain_id": eb.chain_id,
                        "manifest_chain_id": chain_id,
                    }
                )
            elif eb.vm and not _same_manifest_vm(eb.vm, manifest):
                conflicts.append(
                    {
                        "backup_id": bid,
                        "reason": "exists_different_vm",
                        "existing_chain_id": eb.chain_id,
                        "manifest_chain_id": chain_id,
                    }
                )
            else:
                imported_count += 1

    # Check encryption KEKs
    kek_ids = list(
        set(b.get("encryption_key_id") for b in backups if b.get("encryption_key_id"))
    )
    encrypted = len(kek_ids) > 0
    kek_available = True
    if kek_ids:
        existing_keks = (
            db.query(EncryptionKey.id).filter(EncryptionKey.id.in_(kek_ids)).all()
        )
        existing_kek_ids = {k.id for k in existing_keks}
        kek_available = all(kid in existing_kek_ids for kid in kek_ids)

    # Determine status
    if conflicts:
        status = "conflict"
    elif encrypted and not kek_available:
        status = "kek_missing"
    elif imported_count == len(backups):
        status = "imported"
    elif imported_count > 0:
        status = "partial"
    else:
        status = "available"

    # Compute size and date range
    total_size = sum(b.get("size_bytes", 0) or 0 for b in backups)
    dates = [b.get("created_at") for b in backups if b.get("created_at")]
    oldest = min(dates) if dates else None
    newest = max(dates) if dates else None

    return {
        "chain_id": chain_id,
        "vm_name": vm_name,
        "backup_count": len(backups),
        "imported_count": imported_count,
        "total_size_bytes": total_size,
        "oldest_backup": oldest,
        "newest_backup": newest,
        "encrypted": encrypted,
        "kek_available": kek_available,
        "kek_ids": kek_ids,
        "status": status,
        "conflicts": conflicts,
    }


def _get_or_create_sentinel_agent(db: Session) -> Agent:
    """Get or create the __s3_import__ sentinel agent."""
    agent = db.query(Agent).filter(Agent.hostname == "__s3_import__").first()
    if not agent:
        agent = Agent(
            hostname="__s3_import__",
            display_name="S3 Import (placeholder)",
            status="offline",
        )
        db.add(agent)
        db.flush()
    return agent


def _find_or_create_vm(
    db: Session, vm_name: str, chain_id: str, identity=None
) -> tuple:
    """Reuse only an exact source identity; unidentified chains stay historical."""
    if (
        isinstance(identity, dict)
        and all(identity.get(key) for key in ("agent_id", "provider", "vm_uid"))
        and isinstance(identity.get("namespace"), str)
    ):
        vm = (
            db.query(VM)
            .filter(
                VM.agent_id == identity["agent_id"],
                VM.provider == identity["provider"],
                VM.namespace == identity["namespace"],
                VM.vm_uid == identity["vm_uid"],
            )
            .one_or_none()
        )
        if vm:
            return vm, False
    agent = _get_or_create_sentinel_agent(db)
    for vm in db.query(VM).filter(VM.agent_id == agent.id).all():
        if (vm.vm_metadata or {}).get("import_chain_id") == chain_id:
            return vm, False
    vm = VM(
        name=vm_name,
        agent_id=agent.id,
        state="unknown",
        inventory_present=False,
        vm_metadata={
            "imported_from_s3": True,
            "placeholder": True,
            "import_chain_id": chain_id,
            "source_identity": identity,
        },
    )
    db.add(vm)
    db.flush()
    return vm, True


# --- Endpoints ---


@router.get("/discover")
async def discover_chains(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Discover chain manifests in S3 and report import status."""
    check_role(current_user, ["admin"])

    s3, s3_config = _get_s3_client_and_config(db)
    bucket = s3_config["bucket"]
    prefix = s3_config.get("prefix", "backups").strip("/")

    manifests = _download_manifests(s3, bucket, prefix)
    chains = [_classify_chain(m, db) for m in manifests]

    return {
        "chains": chains,
        "s3_endpoint": s3_config.get("endpoint"),
        "s3_bucket": bucket,
    }


@router.post("/import")
async def import_chain(
    req: ImportRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Import a backup chain from S3 manifests. Idempotent — skips existing records."""
    check_role(current_user, ["admin"])

    s3, s3_config = _get_s3_client_and_config(db)
    bucket = s3_config["bucket"]
    prefix = s3_config.get("prefix", "backups").strip("/")

    # Find and download the manifest for this chain_id
    manifest = None
    manifest_prefix = f"{prefix}/manifests/"
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=manifest_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            rel = key[len(manifest_prefix) :]
            parts = rel.split("/")
            if len(parts) != 2 or not parts[1].endswith(".json"):
                continue
            if parts[1][:-5] == req.chain_id:
                resp = s3.get_object(Bucket=bucket, Key=key)
                manifest = json.loads(resp["Body"].read().decode("utf-8"))
                break
        if manifest:
            break

    if not manifest:
        raise HTTPException(
            status_code=404, detail=f"Manifest not found for chain {req.chain_id}"
        )

    chain_id = manifest["chain_id"]
    vm_name = manifest["vm_name"]
    backups_list = sorted(
        manifest.get("backups", []), key=lambda b: b.get("chain_position", 0)
    )

    # Validate KEKs
    kek_ids = list(
        set(
            b.get("encryption_key_id")
            for b in backups_list
            if b.get("encryption_key_id")
        )
    )
    if kek_ids:
        existing_keks = (
            db.query(EncryptionKey.id).filter(EncryptionKey.id.in_(kek_ids)).all()
        )
        existing_kek_ids = {k.id for k in existing_keks}
        missing = [kid for kid in kek_ids if kid not in existing_kek_ids]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing encryption keys: {', '.join(missing)}. Import keys first via Settings → Encryption.",
            )

    # Check for hard conflicts
    backup_ids = [b["backup_id"] for b in backups_list]
    existing = (
        db.query(Backup).filter(Backup.id.in_(backup_ids)).all() if backup_ids else []
    )
    existing_map = {b.id: b for b in existing}

    conflicts = []
    for entry in backups_list:
        bid = entry["backup_id"]
        if bid in existing_map:
            eb = existing_map[bid]
            if eb.chain_id and eb.chain_id != chain_id:
                conflicts.append(
                    {
                        "backup_id": bid,
                        "reason": "exists_different_chain",
                        "existing_chain_id": eb.chain_id,
                    }
                )
            elif eb.vm and not _same_manifest_vm(eb.vm, manifest):
                conflicts.append(
                    {
                        "backup_id": bid,
                        "reason": "exists_different_vm",
                        "existing_chain_id": eb.chain_id,
                    }
                )

    if conflicts:
        raise HTTPException(
            status_code=409,
            detail="Chain has conflicting backup records",
            headers={"X-Conflicts": json.dumps(conflicts)},
        )

    # Find or create VM
    # A partial import must retain its existing chain's VM, never attach its tail
    # to a same-named replacement discovered since the first import.
    existing_vm_ids = {b.vm_id for b in existing}
    if len(existing_vm_ids) > 1:
        raise HTTPException(409, "Existing chain spans multiple VM identities")
    if existing_vm_ids:
        vm = db.query(VM).filter(VM.id == next(iter(existing_vm_ids))).one()
        vm_created = False
    else:
        vm, vm_created = _find_or_create_vm(
            db, vm_name, chain_id, manifest.get("vm_identity")
        )

    # Import backups (idempotent)
    imported_count = 0
    skipped_count = 0
    prev_backup_id = None

    for entry in backups_list:
        bid = entry["backup_id"]
        position = entry.get("chain_position", 0)

        if bid in existing_map:
            skipped_count += 1
            prev_backup_id = bid
            continue

        # Build storage path
        s3_prefix = entry.get("s3_prefix", "")
        storage_path = f"s3://{bucket}/{s3_prefix}" if s3_prefix else None

        # Parse created_at
        created_at = None
        if entry.get("created_at"):
            try:
                created_at = datetime.fromisoformat(
                    entry["created_at"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                created_at = datetime.utcnow()

        completed_at = None
        if entry.get("completed_at"):
            try:
                completed_at = datetime.fromisoformat(
                    entry["completed_at"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                completed_at = created_at

        backup = Backup(
            authority_kind="human",
            initiating_user_id=str(current_user.id),
            id=bid,
            vm_id=vm.id,
            status="completed",
            progress=100,
            size_bytes=entry.get("size_bytes"),
            retention_days=entry.get("retention_days", 30),
            backup_type=entry.get("backup_type", "full"),
            storage_path=storage_path,
            tags={"imported_from_s3": True},
            created_at=created_at or datetime.utcnow(),
            completed_at=completed_at or created_at or datetime.utcnow(),
            encryption_key_id=entry.get("encryption_key_id"),
            wrapped_dek=entry.get("wrapped_dek"),
            chain_position=position,
        )

        # Chain linkage: full backup (position 0) is its own chain root
        if position == 0:
            backup.chain_id = None
            backup.parent_backup_id = None
            db.add(backup)
            db.flush()
            backup.chain_id = backup.id
        else:
            backup.chain_id = chain_id
            backup.parent_backup_id = prev_backup_id
            db.add(backup)

        imported_count += 1
        prev_backup_id = bid

    db.commit()

    log_activity(
        db,
        current_user,
        "s3_chain_imported",
        "backup_chain",
        chain_id,
        {
            "vm_name": vm_name,
            "imported_count": imported_count,
            "skipped_count": skipped_count,
            "vm_created": vm_created,
        },
    )

    return {
        "imported_count": imported_count,
        "skipped_count": skipped_count,
        "vm_name": vm_name,
        "vm_id": vm.id,
        "vm_created": vm_created,
        "status": "ok",
    }
