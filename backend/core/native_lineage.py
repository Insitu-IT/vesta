"""Select a current accepted native push parent; no filename/status inference."""

from copy import deepcopy

from sqlalchemy import func

from core.native_inventory import digest, refuse
from core.native_manifest import validate_result
from models import Backup, S3Publication, StorageLineageGeneration, StorageLineageHead


def require_parent_after_fence(member, fenced_xid):
    """A post-fence accepted full must reset the chain before incremental reuse."""
    if fenced_xid is None:
        return
    execution = member.native_execution
    if (
        type(fenced_xid) is not int
        or fenced_xid <= 0
        or type(execution) is not dict
        or execution.get("state") != "bound"
        or type(execution.get("bound_xid")) is not int
        or execution["bound_xid"] <= fenced_xid
    ):
        refuse()


def select_parent(db, backup, source):
    from core.native_storage_wire import NativeTransactionRequest

    head = db.get(StorageLineageHead, backup.vm_id, populate_existing=True)
    if head is None or head.org_id != backup.org_id or head.state != "current":
        refuse()
    generation = db.get(
        StorageLineageGeneration, head.generation_id, populate_existing=True
    )
    if (
        generation is None
        or generation.org_id != backup.org_id
        or generation.vm_id != backup.vm_id
        or generation.state != "accepted"
        or generation.backup_id == backup.id
        or backup.parent_backup_id not in {None, generation.backup_id}
        or any(
            getattr(head, key) != getattr(generation, key)
            for key in (
                "root_backup_id",
                "tracker_uid",
                "checkpoint",
                "manifest_receipt_sha256",
            )
        )
        or generation.tracker_uid != source["domain_uuid"]
    ):
        refuse()
    first = generation
    seen = set()
    result = None
    for _ in range(256):
        if generation.id in seen:
            refuse()
        seen.add(generation.id)
        try:
            request = NativeTransactionRequest.model_validate(
                generation.accepted_request
            ).model_dump()
        except (ValueError, TypeError):
            refuse()
        member = db.get(Backup, generation.backup_id, populate_existing=True)
        publication = db.get(S3Publication, generation.id, populate_existing=True)
        payload = db.get(
            S3Publication, request["reservation_id"], populate_existing=True
        )
        if (
            member is None
            or member.org_id != backup.org_id
            or member.vm_id != backup.vm_id
            or member.status != "completed"
            or not member.native_inventory
            or request["org_id"] != backup.org_id
            or request["backup_id"] != member.id
            or request["agent_id"] != source["agent_id"]
            or publication is None
            or publication.kind != "chain_manifest"
            or publication.state != "published"
            or publication.backup_id != member.id
            or publication.org_id != backup.org_id
            or not publication.prepared_receipt
            or publication.prepared_receipt["receipt_sha256"]
            != generation.manifest_receipt_sha256
            or payload is None
            or payload.state != "published"
            or payload.backup_id != member.id
            or payload.expected_plan != dict(schema=3, transaction=request)
            or not payload.prepared_receipt
            or payload.prepared_receipt["receipt_sha256"] != generation.receipt_sha256
        ):
            refuse()
        push = validate_result(member.native_inventory["push_result"])
        if result is None:
            fenced_xid = (
                db.query(func.max(Backup.native_fenced_failure_xid))
                .filter_by(org_id=backup.org_id, vm_id=backup.vm_id)
                .scalar()
            )
            require_parent_after_fence(member, fenced_xid)
        manifest = push["manifest"]
        if (
            manifest["source"] != source["disks"]
            or manifest["exclusions"] != source["exclusions"]
            or manifest["domain_uuid"] != source["domain_uuid"]
            or manifest["checkpoint"] != generation.checkpoint
            or generation.root_backup_id != first.root_backup_id
            or generation.root_receipt_sha256 != first.root_receipt_sha256
            or generation.tracker_uid != first.tracker_uid
            or digest(member.native_inventory["inventory"])
            != request["plan"]["source"]["inventory_sha256"]
        ):
            refuse()
        if result is None:
            result = deepcopy(push)
        parent = request["plan"]["parent"]
        if parent is None:
            if (
                generation.backup_id != first.root_backup_id
                or generation.receipt_sha256 != first.root_receipt_sha256
            ):
                refuse()
            break
        ancestor = db.get(
            StorageLineageGeneration, parent["generation_id"], populate_existing=True
        )
        if (
            ancestor is None
            or ancestor.org_id != backup.org_id
            or ancestor.vm_id != backup.vm_id
            or ancestor.state != "accepted"
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
        ):
            refuse()
        generation = ancestor
    else:
        refuse()
    binding = dict(
        backup_id=first.backup_id,
        root_backup_id=first.root_backup_id,
        receipt_sha256=first.receipt_sha256,
        generation_id=first.id,
        tracker_uid=first.tracker_uid,
        checkpoint=first.checkpoint,
    )
    return binding, result
