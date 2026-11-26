"""Accepted native catalog ancestry, explicit receipts and push manifests."""

from copy import deepcopy
from types import SimpleNamespace

from core.native_manifest import validate_receipt_binding
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import validate
from core.storage_publication import _manifest
from models import Backup, S3Publication, StorageLineageGeneration

SCHEMA = "vnbui-native-restore/1"


def _refuse():
    raise StorageOwnershipError("An intact accepted native push chain is required")


def build_native_bundle(db, backup_id, org_id):
    if not org_id:
        _refuse()
    selected = (
        db.query(StorageLineageGeneration)
        .filter_by(backup_id=backup_id, org_id=org_id, state="accepted")
        .one_or_none()
    )
    if selected is None:
        _refuse()
    generation, members, seen = selected, [], set()
    stable = None
    while generation is not None:
        if generation.id in seen or len(members) >= 256:
            _refuse()
        seen.add(generation.id)
        backup = (
            db.query(Backup)
            .filter_by(
                id=generation.backup_id,
                org_id=org_id,
                vm_id=selected.vm_id,
                status="completed",
            )
            .one_or_none()
        )
        claim = (
            db.query(S3Publication)
            .filter_by(
                backup_id=generation.backup_id,
                org_id=org_id,
                kind="payload",
                state="published",
            )
            .one_or_none()
        )
        publication = (
            db.query(S3Publication)
            .filter_by(
                id=generation.id,
                backup_id=generation.backup_id,
                org_id=org_id,
                kind="chain_manifest",
                state="published",
            )
            .one_or_none()
        )
        if (
            backup is None
            or claim is None
            or publication is None
            or not backup.native_inventory
        ):
            _refuse()
        saved = claim.prepared_receipt
        response = saved.get("response") if isinstance(saved, dict) else None
        if not isinstance(response, dict) or response.get("accepted") is not True:
            _refuse()
        view = SimpleNamespace(
            **{
                key: getattr(claim, key)
                for key in (
                    "id",
                    "backup_id",
                    "org_id",
                    "endpoint",
                    "bucket",
                    "dispatch_token",
                    "expected_plan",
                )
            },
            state="reserved",
        )
        request, receipt, receipt_hash = validate(view, saved.get("receipt"))
        if request["plan"]["provider"] != "libvirt":
            _refuse()
        push = validate_receipt_binding(request, receipt, backup.native_inventory)
        manifest, _ = _manifest(publication.expected_plan)
        accepted = manifest["members"][-1]
        if (
            request != generation.accepted_request
            or request["backup_id"] != backup.id
            or request["org_id"] != org_id
            or request["plan"]["source"]["vm_id"] != selected.vm_id
            or generation.vm_id != selected.vm_id
            or generation.state != "accepted"
            or generation.root_backup_id != selected.root_backup_id
            or generation.root_receipt_sha256 != selected.root_receipt_sha256
            or generation.tracker_uid != selected.tracker_uid
            or generation.tracker_uid != push["manifest"]["domain_uuid"]
            or generation.checkpoint != push["manifest"]["checkpoint"]
            or receipt_hash != generation.receipt_sha256
            or receipt_hash != saved.get("receipt_sha256")
            or receipt_hash != response.get("receipt_sha256")
            or accepted.get("request") != request
            or accepted.get("receipt") != receipt
            or accepted.get("native_result") != push
            or not publication.prepared_receipt
            or publication.prepared_receipt.get("receipt_sha256")
            != generation.manifest_receipt_sha256
        ):
            _refuse()
        identity = (
            request["agent_id"],
            request["plan"]["target"],
            push["manifest"]["source"],
            push["manifest"]["exclusions"],
        )
        if stable is None:
            stable = identity
        elif identity != stable:
            _refuse()
        members.append(
            dict(request=deepcopy(request), receipt=receipt, push_result=deepcopy(push))
        )
        parent = request["plan"]["parent"]
        if parent is None:
            if (
                request["plan"]["backup_type"] != "full"
                or generation.backup_id != selected.root_backup_id
                or receipt_hash != selected.root_receipt_sha256
                or push["manifest"]["parent_backup_id"] is not None
            ):
                _refuse()
            break
        ancestor = (
            db.query(StorageLineageGeneration)
            .filter_by(id=parent["generation_id"], org_id=org_id)
            .one_or_none()
        )
        if (
            ancestor is None
            or any(
                getattr(ancestor, key) != parent[key]
                for key in (
                    "backup_id",
                    "root_backup_id",
                    "receipt_sha256",
                    "tracker_uid",
                    "checkpoint",
                )
            )
            or push["manifest"]["parent_backup_id"] != ancestor.backup_id
        ):
            _refuse()
        generation = ancestor
    members.reverse()
    for previous, member in zip(members, members[1:]):
        if (
            member["push_result"]["manifest"]["parent_manifest_sha256"]
            != previous["push_result"]["manifest_sha256"]
        ):
            _refuse()
    return dict(schema=SCHEMA, members=members)
