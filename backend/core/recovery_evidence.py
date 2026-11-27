"""Read positive, DB-rooted VM custody for offsite recovery publication."""

from dataclasses import dataclass
from datetime import timezone
import hashlib
import re

from core.legacy_recovery import legacy_s3_unverified
from core.recovery_signing import (
    POINT_FORMAT,
    RecoveryUnavailable,
    canonical_id,
    installation_id,
)
from core.s3_ownership import StorageOwnershipError
from core.storage_publication import _manifest
from core.storage_receipt_v2 import canonical
from core.storage_restore import BUNDLE_SCHEMA, build_restore_bundle
from models import Backup, S3Publication, StorageLineageGeneration, VM


@dataclass(frozen=True)
class RecoveryEvidence:
    point: dict
    publication_snapshot: dict
    stored_identity: dict


def accepted_evidence(db, org_id, backup_id):
    """Revalidate complete DB ancestry; callers must also verify the S3 bytes."""
    if not canonical_id(org_id) or not canonical_id(backup_id):
        raise RecoveryUnavailable("Recovery point identity unavailable")
    backup = (
        db.query(Backup)
        .filter_by(org_id=org_id, id=backup_id, status="completed")
        .one_or_none()
    )
    generation = (
        db.query(StorageLineageGeneration)
        .filter_by(org_id=org_id, backup_id=backup_id, state="accepted")
        .one_or_none()
    )
    if backup is None or legacy_s3_unverified(backup) or generation is None:
        raise RecoveryUnavailable("An accepted recovery generation is required")
    publication = (
        db.query(S3Publication)
        .filter_by(
            org_id=org_id,
            backup_id=backup_id,
            id=generation.id,
            state="published",
            kind="chain_manifest",
        )
        .one_or_none()
    )
    if publication is None or backup.completed_at is None:
        raise RecoveryUnavailable("Published generation history unavailable")
    try:
        manifest, raw = _manifest(publication.expected_plan)
        identifier = installation_id(db)
        if (
            manifest["protocol"] != "vnbui-storage-generation/1"
            or manifest["installation_id"] != identifier
            or manifest["org_id"] != org_id
            or manifest["backup_id"] != backup_id
            or manifest["generation_id"] != generation.id
            or not canonical_id(generation.id)
            or manifest["root_backup_id"] != generation.root_backup_id
            or not canonical_id(generation.root_backup_id)
            or manifest["target"]["endpoint"] != publication.endpoint
            or manifest["target"]["bucket"] != publication.bucket
        ):
            raise RecoveryUnavailable("Generation scope differs from accepted catalog")
        expected_key = (
            f"vnbui-owned/v1/{hashlib.sha256(org_id.encode()).hexdigest()}/"
            f"{hashlib.sha256(generation.root_backup_id.encode()).hexdigest()}/"
            f"generations/{generation.id}.json"
        )
        if publication.object_key != expected_key:
            raise RecoveryUnavailable(
                "Published generation key differs from accepted custody"
            )
        prepared = publication.prepared_receipt
        receipt = prepared["receipt"]
        receipt_bytes = canonical(receipt)
        digest = hashlib.sha256(raw).hexdigest()
        if (
            receipt
            != {
                "schema": 1,
                "generation_id": generation.id,
                "endpoint": publication.endpoint,
                "bucket": publication.bucket,
                "key": expected_key,
                "version_id": receipt["version_id"],
                "etag": receipt["etag"],
                "bytes": len(raw),
                "sha256": digest,
                "assurance": "consumer_sha256_verified",
            }
            or not re.fullmatch(r'"[^"\r\n]{1,1022}"', receipt["etag"])
            or (
                receipt["version_id"] is not None
                and (
                    not isinstance(receipt["version_id"], str)
                    or not 0 < len(receipt["version_id"]) <= 1024
                )
            )
            or prepared["receipt_canonical"].encode() != receipt_bytes
            or prepared["receipt_sha256"] != hashlib.sha256(receipt_bytes).hexdigest()
            or prepared["receipt_sha256"] != generation.manifest_receipt_sha256
        ):
            raise RecoveryUnavailable(
                "Stored generation receipt differs from accepted catalog"
            )

        bundle = build_restore_bundle(db, backup_id, org_id)
        provider = {
            BUNDLE_SCHEMA: "kubevirt",
            "vnbui-native-restore/1": "libvirt",
        }[bundle["schema"]]
        projected = []
        for entry in manifest["members"]:
            member = {"request": entry["request"], "receipt": entry["receipt"]}
            if provider == "libvirt":
                member["push_result"] = entry["native_result"]
            projected.append(member)
            request = member["request"]
            payload = (
                db.query(S3Publication)
                .filter_by(
                    org_id=org_id,
                    id=request["reservation_id"],
                    backup_id=request["backup_id"],
                    state="published",
                    kind="payload",
                )
                .one_or_none()
            )
            if (
                payload is None
                or entry["wrapped_attempt_key"] != payload.wrapped_attempt_key
                or entry["receipt_sha256"] != payload.prepared_receipt["receipt_sha256"]
                or entry["acceptance"] != payload.prepared_receipt["response"]
                or (
                    provider == "kubevirt"
                    and (
                        entry["checkpoint"] != payload.finalize_intent["binding"]
                        or entry["checkpoint_proof"] != payload.checkpoint_proof
                    )
                )
            ):
                raise RecoveryUnavailable(
                    "Generation member custody differs from accepted catalog"
                )
        if projected != bundle["members"]:
            raise RecoveryUnavailable("Generation body differs from accepted ancestry")
        if provider == "libvirt":
            native_vm = (
                db.query(VM).filter_by(id=generation.vm_id, org_id=org_id).one_or_none()
            )
            if native_vm is None:
                raise RecoveryUnavailable(
                    "Native recovery source attribution unavailable"
                )
            name = native_vm.name
        else:
            name = generation.accepted_request["plan"]["vm_name"]
        completed = backup.completed_at
        completed = (
            completed.replace(tzinfo=timezone.utc)
            if completed.tzinfo is None
            else completed.astimezone(timezone.utc)
        )
        return RecoveryEvidence(
            point={
                "format": POINT_FORMAT,
                "installation_id": identifier,
                "org_id": org_id,
                "backup_id": backup_id,
                "generation_id": generation.id,
                "root_backup_id": generation.root_backup_id,
                "provider": provider,
                "name": name,
                "completed_at": completed.isoformat().replace("+00:00", "Z"),
                "generation": {
                    "endpoint": publication.endpoint,
                    "bucket": publication.bucket,
                    "region": manifest["target"]["region"],
                    "key": expected_key,
                    "version_id": receipt["version_id"],
                    "etag": receipt["etag"],
                    "bytes": len(raw),
                    "sha256": digest,
                },
            },
            publication_snapshot={
                "id": publication.id,
                "org_id": org_id,
                "backup_id": backup_id,
                "endpoint": publication.endpoint,
                "bucket": publication.bucket,
                "key": expected_key,
                "plan": publication.expected_plan.copy(),
            },
            stored_identity={
                "ETag": receipt["etag"],
                "VersionId": receipt["version_id"],
            },
        )
    except (KeyError, TypeError, ValueError, AttributeError, StorageOwnershipError):
        raise RecoveryUnavailable("Published generation custody unavailable") from None
