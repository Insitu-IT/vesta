"""Export an accepted KubeVirt chain for the streaming restore worker.

The bundle contains immutable requests and receipts, never credentials or DEKs.
Object retrieval and byte verification belong to the consumer; listing a bucket
or sorting backup timestamps cannot establish this chain.
"""

from copy import deepcopy
from types import SimpleNamespace

from core.legacy_recovery import legacy_s3_unverified
from core.s3_ownership import StorageOwnershipError
from core.storage_lineage import stable_source
from core.storage_receipt_v2 import validate
from models import Backup, S3Publication, StorageLineageGeneration

BUNDLE_SCHEMA = "vnbui-kubevirt-restore/1"
MAX_CHAIN_MEMBERS = 256


def _refuse():
    raise StorageOwnershipError("An intact accepted KubeVirt chain is required")


def build_restore_bundle(db, backup_id, org_id):
    """Read one tenant's selected historical generation and all its ancestors.

    A newer current head does not invalidate a retained historical restore point.
    Every member must still be accepted, completed and published. Explicit org
    predicates supplement the normal ORM/RLS tenant boundary.
    """
    if not org_id:
        _refuse()
    generation = (
        db.query(StorageLineageGeneration)
        .filter_by(backup_id=backup_id, org_id=org_id, state="accepted")
        .one_or_none()
    )
    if generation is None:
        _refuse()
    if (generation.accepted_request or {}).get("plan", {}).get("provider") == "libvirt":
        from core.native_restore_bundle import build_native_bundle

        return build_native_bundle(db, backup_id, org_id)
    selected = generation
    seen = set()
    members = []
    source = None
    target = None
    while generation is not None:
        if generation.id in seen or len(members) >= MAX_CHAIN_MEMBERS:
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
        if backup is None or claim is None or legacy_s3_unverified(backup):
            _refuse()
        saved = claim.prepared_receipt
        response = saved.get("response") if isinstance(saved, dict) else None
        if not isinstance(response, dict) or response.get("accepted") is not True:
            _refuse()
        # The shared wire validator checks a pre-publication claim. Supply only
        # an in-memory view of that phase; never change persisted custody.
        view = SimpleNamespace(
            id=claim.id,
            backup_id=claim.backup_id,
            org_id=claim.org_id,
            endpoint=claim.endpoint,
            bucket=claim.bucket,
            state="reserved",
            dispatch_token=claim.dispatch_token,
            expected_plan=claim.expected_plan,
        )
        request, receipt, receipt_hash = validate(view, saved.get("receipt"))
        plan = request["plan"]
        if (
            plan["provider"] != "kubevirt"
            or request != generation.accepted_request
            or request["backup_id"] != generation.backup_id
            or request["org_id"] != org_id
            or plan["source"]["vm_id"] != selected.vm_id
            or generation.vm_id != selected.vm_id
            or generation.state != "accepted"
            or generation.root_backup_id != selected.root_backup_id
            or generation.root_receipt_sha256 != selected.root_receipt_sha256
            or generation.tracker_uid != selected.tracker_uid
            or receipt_hash != generation.receipt_sha256
            or receipt_hash != saved.get("receipt_sha256")
            or receipt_hash != response.get("receipt_sha256")
        ):
            _refuse()
        member_source = stable_source(plan["source"])
        if source is None:
            source, target = member_source, plan["target"]
        elif source != member_source or target != plan["target"]:
            _refuse()
        members.append(dict(request=deepcopy(request), receipt=receipt))
        parent = plan["parent"]
        if parent is None:
            if (
                plan["backup_type"] != "full"
                or generation.backup_id != selected.root_backup_id
                or receipt_hash != selected.root_receipt_sha256
            ):
                _refuse()
            break
        if plan["backup_type"] != "incremental":
            _refuse()
        ancestor = (
            db.query(StorageLineageGeneration)
            .filter_by(id=parent["generation_id"], org_id=org_id)
            .one_or_none()
        )
        if ancestor is None or any(
            getattr(ancestor, field) != parent[field]
            for field in (
                "backup_id",
                "root_backup_id",
                "receipt_sha256",
                "tracker_uid",
                "checkpoint",
            )
        ):
            _refuse()
        generation = ancestor
    members.reverse()
    return dict(schema=BUNDLE_SCHEMA, members=members)
