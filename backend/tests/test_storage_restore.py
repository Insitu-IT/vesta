"""Restore bundle uses retained accepted ancestry, not bucket/prefix inference."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import uuid

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical
from core.storage_restore import BUNDLE_SCHEMA, build_restore_bundle
from core.storage_wire import plan_digest
from models import Backup, S3Publication, StorageLineageGeneration


def member(db, parent=None, *, versioned=False):
    request = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "agent/contracts/storage_semantic_valid.json"
        ).read_text()
    )
    request["backup_id"] = str(uuid.uuid4())
    request["reservation_id"] = str(uuid.uuid4())
    plan = request["plan"]
    plan["attempt_id"] = request["reservation_id"]
    if parent:
        plan["backup_type"] = "incremental"
        plan["parent"] = {
            name: getattr(parent, name)
            for name in (
                "backup_id",
                "root_backup_id",
                "receipt_sha256",
                "tracker_uid",
                "checkpoint",
            )
        }
        plan["parent"]["generation_id"] = parent.id
        plan["source"]["volumes"][0]["pvc_resource_version"] = "2"

    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    root = (
        f'vnbui-owned/v1/{digest(request["org_id"])}/{digest(request["backup_id"])}/'
        f'payload/{request["reservation_id"]}/'
    )
    for artifact in plan["artifacts"]:
        artifact["key"] = root + digest(artifact["volume_id"]) + "/" + artifact["role"]
    request["plan_sha256"] = plan_digest(plan)
    receipt = dict(
        protocol=request["protocol"],
        schema=2,
        reservation_id=request["reservation_id"],
        backup_id=request["backup_id"],
        endpoint=plan["target"]["endpoint"],
        bucket=plan["target"]["bucket"],
        objects=[
            dict(
                key=a["key"],
                volume_id=a["volume_id"],
                role=a["role"],
                version_id="payload-version" if versioned else None,
                etag='"exact-object"',
                plaintext_bytes=1,
                ciphertext_bytes=1,
                plaintext_sha256=digest("x"),
                ciphertext_sha256=digest("x"),
            )
            for a in plan["artifacts"]
        ],
    )
    receipt_hash = hashlib.sha256(canonical(receipt)).hexdigest()
    backup = Backup(
        id=request["backup_id"],
        org_id=request["org_id"],
        vm_id=plan["source"]["vm_id"],
        status="completed",
        backup_type=plan["backup_type"],
    )
    claim = S3Publication(
        id=request["reservation_id"],
        org_id=backup.org_id,
        backup_id=backup.id,
        kind="payload",
        state="published",
        endpoint=receipt["endpoint"],
        bucket=receipt["bucket"],
        object_key=root,
        dispatch_token="committed-dispatch",
        expected_plan=dict(schema=3, transaction=request),
        prepared_receipt=dict(
            receipt=receipt,
            receipt_sha256=receipt_hash,
            response=dict(accepted=True, receipt_sha256=receipt_hash),
        ),
    )
    generation = StorageLineageGeneration(
        id=str(uuid.uuid4()),
        org_id=backup.org_id,
        vm_id=backup.vm_id,
        backup_id=backup.id,
        root_backup_id=parent.root_backup_id if parent else backup.id,
        state="accepted",
        receipt_sha256=receipt_hash,
        root_receipt_sha256=parent.root_receipt_sha256 if parent else receipt_hash,
        manifest_receipt_sha256="a" * 64,
        tracker_uid="tracker-uid",
        checkpoint=str(uuid.uuid4()),
        accepted_request=deepcopy(request),
    )
    db.add_all([backup, claim, generation])
    db.commit()
    return generation, claim, backup


def test_full_incremental_bundle_stops_at_selected_restore_point(db_session):
    first, _, _ = member(db_session)
    second, _, _ = member(db_session, first)
    member(db_session, second)
    bundle = build_restore_bundle(db_session, second.backup_id, second.org_id)
    assert bundle["schema"] == BUNDLE_SCHEMA
    assert [m["request"]["backup_id"] for m in bundle["members"]] == [
        first.backup_id,
        second.backup_id,
    ]
    assert set(bundle["members"][0]) == {"request", "receipt"}
    assert not db_session.dirty


def test_bundle_returns_detached_metadata_without_key_material(db_session):
    generation, claim, _ = member(db_session)
    claim.wrapped_attempt_key = {"private": "not-for-bundle"}
    db_session.commit()
    bundle = build_restore_bundle(db_session, generation.backup_id, generation.org_id)
    assert "not-for-bundle" not in json.dumps(bundle)
    bundle["members"][0]["request"]["plan"]["vm_name"] = "changed"
    assert generation.accepted_request["plan"]["vm_name"] == "vm"


def test_other_organization_cannot_export_bundle(db_session):
    generation, _, _ = member(db_session)
    with pytest.raises(StorageOwnershipError):
        build_restore_bundle(db_session, generation.backup_id, str(uuid.uuid4()))


def test_bundle_endpoint_uses_operator_auth_and_disables_caching(db_session):
    from types import SimpleNamespace
    from fastapi import Response
    from routers import backups as backup_routes

    generation, _, _ = member(db_session)
    route = next(
        r for r in backup_routes.router.routes if r.path.endswith("/restore-bundle")
    )
    assert backup_routes.get_operator_or_admin in {
        d.call for d in route.dependant.dependencies
    }
    response = Response()
    bundle = backup_routes.get_restore_bundle(
        generation.backup_id,
        response,
        db_session,
        SimpleNamespace(org_id=generation.org_id),
    )
    assert bundle["schema"] == BUNDLE_SCHEMA
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    "problem",
    [
        "missing-parent",
        "deleted-payload",
        "incomplete-backup",
        "unaccepted-parent",
        "receipt-changed",
        "wrong-root",
        "wrong-checkpoint",
    ],
)
def test_incomplete_or_changed_ancestry_refuses(db_session, problem):
    first, claim, backup = member(db_session)
    second, _, _ = member(db_session, first)
    if problem == "missing-parent":
        db_session.delete(first)
    elif problem == "deleted-payload":
        claim.state = "deleted"
    elif problem == "incomplete-backup":
        backup.status = "failed"
    elif problem == "unaccepted-parent":
        first.state = "held"
    elif problem == "receipt-changed":
        saved = deepcopy(claim.prepared_receipt)
        saved["receipt"]["objects"][0]["etag"] = '"replacement"'
        claim.prepared_receipt = saved
    elif problem == "wrong-root":
        first.root_backup_id = str(uuid.uuid4())
    else:
        first.checkpoint = "replacement-checkpoint"
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        build_restore_bundle(db_session, second.backup_id, second.org_id)
