"""Transaction retention deletes literal accepted versions and retains custody."""

from datetime import datetime, timedelta
from copy import deepcopy
import hashlib
import uuid

from botocore.exceptions import ClientError
import pytest

from backend.tests.test_storage_restore import member
from core.storage_deletion import delete_transaction_payload, _delete_object
from core.storage_receipt_v2 import canonical
from core.storage_restore import build_restore_bundle
from core.backup_deletion import BackupDependencyError
from core.s3_ownership import StorageOwnershipError
from models import Agent, Backup, Organization, Restore, S3Publication, VM


class Store:
    def __init__(self):
        self.deleted = []
        self.fail_at = None

    def delete_object(self, **args):
        if len(self.deleted) == self.fail_at:
            raise OSError("disconnected")
        self.deleted.append(args)

    def head_object(self, **args):
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "HeadObject")


def ready(db, parent=None):
    generation, claim, backup = member(db, parent, versioned=True)
    request = generation.accepted_request
    if db.get(Organization, backup.org_id) is None:
        db.add(Organization(id=backup.org_id, name="storage-retention"))
        db.add(
            Agent(
                id=request["agent_id"],
                org_id=backup.org_id,
                hostname="retention",
                status="online",
            )
        )
        db.add(
            VM(
                id=backup.vm_id,
                org_id=backup.org_id,
                agent_id=request["agent_id"],
                name="source",
                uuid=str(uuid.uuid4()),
                provider="kubevirt",
                namespace="fixture",
                vm_uid=request["plan"]["source"]["vm_uid"],
            )
        )
    backup.capacity_state = "released"
    backup.capacity_id = str(uuid.uuid4())
    backup.capacity_reserved_at = datetime.utcnow()
    backup.capacity_policy_revision = 1
    backup.capacity_release = {"schema": 1, "reason": "generation_committed"}
    backup.chain_id = generation.root_backup_id
    backup.chain_position = 1 if parent else 0
    backup.size_bytes = 123
    manifest_receipt = dict(
        key=f"vnbui-owned/generations/{generation.id}.json",
        bucket=claim.bucket,
        endpoint=claim.endpoint,
        generation_id=generation.id,
        etag='"generation-etag"',
        version_id="version-1",
    )
    generation.manifest_receipt_sha256 = hashlib.sha256(
        canonical(manifest_receipt)
    ).hexdigest()
    db.add(
        S3Publication(
            id=generation.id,
            org_id=backup.org_id,
            backup_id=backup.id,
            kind="chain_manifest",
            endpoint=claim.endpoint,
            bucket=claim.bucket,
            object_key=manifest_receipt["key"],
            state="published",
            expected_plan={"schema": 4},
            prepared_receipt={
                "receipt": manifest_receipt,
                "receipt_sha256": generation.manifest_receipt_sha256,
            },
        )
    )
    db.commit()
    return generation, claim, backup


def test_exact_keys_and_versions_deleted_catalog_retained(db_session):
    generation, claim, backup = ready(db_session)
    store = Store()
    assert delete_transaction_payload(db_session, backup.id, client=store) == 123
    assert backup.status == "deleted" and db_session.get(Backup, backup.id) is not None
    expected = {o["key"] for o in claim.prepared_receipt["receipt"]["objects"]}
    expected.add(f"vnbui-owned/generations/{generation.id}.json")
    assert {o["Key"] for o in store.deleted} == expected
    assert all("IfMatch" in o and "Prefix" not in o for o in store.deleted)
    assert store.deleted[-1]["VersionId"] == "version-1"
    assert delete_transaction_payload(db_session, backup.id, client=store) == 0


def test_interrupted_delete_retries_same_receipts(db_session):
    _, _, backup = ready(db_session)
    store = Store()
    store.fail_at = 1
    with pytest.raises(OSError):
        delete_transaction_payload(db_session, backup.id, client=store)
    assert db_session.get(Backup, backup.id).status == "deleting"
    first = store.deleted[0]
    store.fail_at = None
    delete_transaction_payload(db_session, backup.id, client=store)
    assert store.deleted[1] == first and backup.status == "deleted"


@pytest.mark.parametrize(
    "failure_stage", ["before_any", "after_one", "at_manifest", "head_after_delete"]
)
def test_permission_denied_retains_custody_and_retries_exact_receipts(
    db_session, failure_stage
):
    generation, claim, backup = ready(db_session)
    claims = db_session.query(S3Publication).filter_by(backup_id=backup.id).all()
    before = {p.id: deepcopy(p.prepared_receipt) for p in claims}
    accepted_request = deepcopy(generation.accepted_request)
    objects = claim.prepared_receipt["receipt"]["objects"]
    manifest = next(p for p in claims if p.kind == "chain_manifest")
    expected = [
        dict(
            Bucket=claim.bucket,
            Key=o["key"],
            IfMatch=o["etag"],
            **({"VersionId": o["version_id"]} if o["version_id"] is not None else {}),
        )
        for o in [*objects, manifest.prepared_receipt["receipt"]]
    ]
    denied_index = {
        "before_any": 0,
        "after_one": 1,
        "at_manifest": len(expected) - 1,
        "head_after_delete": 0,
    }[failure_stage]

    class PermissionStore(Store):
        denied = True

        def __init__(self):
            super().__init__()
            self.calls = []

        def delete_object(self, **args):
            self.calls.append(args)
            if (
                self.denied
                and failure_stage != "head_after_delete"
                and args["Key"] == expected[denied_index]["Key"]
            ):
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "DeleteObject")
            return super().delete_object(**args)

        def head_object(self, **args):
            if self.denied and failure_stage == "head_after_delete":
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")
            return super().head_object(**args)

    store = PermissionStore()
    with pytest.raises(ClientError) as refused:
        delete_transaction_payload(db_session, backup.id, client=store)
    assert refused.value.response["Error"]["Code"] == "AccessDenied"
    assert backup.status == "deleting"
    assert backup.tags["storage_deletion"]["state"] == "deleting"
    assert (
        generation.state == "accepted"
        and generation.accepted_request == accepted_request
    )
    assert all(
        p.state == "published" and p.prepared_receipt == before[p.id] for p in claims
    )
    assert store.calls == expected[: denied_index + 1]
    with pytest.raises(StorageOwnershipError):
        build_restore_bundle(db_session, backup.id, backup.org_id)
    previous_calls = len(store.calls)
    store.denied = False
    assert delete_transaction_payload(db_session, backup.id, client=store) == 123
    assert store.calls[previous_calls:] == expected
    assert backup.status == "deleted"
    assert all(p.prepared_receipt == before[p.id] for p in claims)


@pytest.mark.parametrize(
    "status,capacity_state",
    [
        ("cleanup_required", "reserved"),
        ("failed", "reserved"),
        ("failed", "legacy_held"),
        ("cleanup_required", "unreserved"),
    ],
)
def test_unsettled_backup_without_chain_metadata_protects_parent(
    db_session, status, capacity_state
):
    _, _, parent = ready(db_session)
    child = Backup(
        org_id=parent.org_id,
        vm_id=parent.vm_id,
        status=status,
        capacity_state=capacity_state,
    )
    if capacity_state != "unreserved":
        child.capacity_id = str(uuid.uuid4())
        child.capacity_reserved_at = datetime.utcnow()
        child.capacity_policy_revision = 1 if capacity_state == "reserved" else None
    db_session.add(child)
    db_session.commit()
    assert child.chain_id is None and child.chain_position is None
    store = Store()
    with pytest.raises(BackupDependencyError, match="chain"):
        delete_transaction_payload(db_session, parent.id, client=store)
    assert not store.deleted and parent.status == "completed"


@pytest.mark.parametrize("has_chain_metadata", [False, True])
def test_settled_failed_backup_without_chain_metadata_does_not_hold_parent(
    db_session, has_chain_metadata
):
    _, _, parent = ready(db_session)
    db_session.add(
        Backup(
            org_id=parent.org_id,
            vm_id=parent.vm_id,
            status="failed",
            capacity_state="released",
            capacity_id=str(uuid.uuid4()),
            capacity_reserved_at=datetime.utcnow(),
            capacity_policy_revision=1,
            capacity_release={"schema": 1, "reason": "pre_effect_failure"},
            chain_id=parent.chain_id if has_chain_metadata else None,
            chain_position=1 if has_chain_metadata else None,
            native_no_effect=(
                {"verified": "by database guard"} if has_chain_metadata else None
            ),
        )
    )
    db_session.commit()
    store = Store()
    assert delete_transaction_payload(db_session, parent.id, client=store) == 123
    assert parent.status == "deleted" and store.deleted


@pytest.mark.asyncio
@pytest.mark.parametrize("by_vm", [False, True])
async def test_retention_resumes_interrupted_delete_even_without_retention_days(
    db_session, monkeypatch, by_vm
):
    from unittest.mock import AsyncMock
    from core.retention import RetentionPolicyEnforcer

    _, _, backup = ready(db_session)
    backup.status = "deleting"
    backup.retention_days = 0
    db_session.commit()
    monkeypatch.setattr("core.retention.SessionLocal", lambda: db_session)
    monkeypatch.setattr("core.retention.get_setting", lambda *args: True)
    enforcer = RetentionPolicyEnforcer()
    enforcer._cleanup_orphaned_manifests = AsyncMock()
    enforcer._delete_backup = AsyncMock(return_value=123)
    result = (
        await enforcer.enforce_for_vm(backup.vm_id)
        if by_vm
        else await enforcer.enforce_all()
    )
    assert result["deleted_count"] == 1 and result["deleted_bytes"] == 123
    enforcer._delete_backup.assert_awaited_once()
    assert enforcer._delete_backup.call_args.args[:2] == (db_session, backup)


def test_retained_descendant_protects_parent(db_session):
    generation, _, root = ready(db_session)
    _, _, child = ready(db_session, generation)
    store = Store()
    with pytest.raises(BackupDependencyError):
        delete_transaction_payload(db_session, root.id, client=store)
    assert not store.deleted
    db_session.rollback()
    delete_transaction_payload(db_session, child.id, client=store)
    delete_transaction_payload(db_session, root.id, client=store)
    assert child.status == root.status == "deleted"


@pytest.mark.asyncio
async def test_retention_expires_at_elapsed_day_and_preserves_live_descendant(
    db_session, monkeypatch
):
    from unittest.mock import AsyncMock
    from core.retention import RetentionPolicyEnforcer

    generation, _, root = ready(db_session)
    _, _, child = ready(db_session, generation)
    now = datetime.utcnow()
    root.retention_days = child.retention_days = 1
    root.completed_at = now - timedelta(hours=25)
    child.completed_at = now - timedelta(hours=23)
    db_session.commit()
    monkeypatch.setattr("core.retention.SessionLocal", lambda: db_session)
    monkeypatch.setattr("core.retention.get_setting", lambda *args: True)
    enforcer = RetentionPolicyEnforcer()
    enforcer._cleanup_orphaned_manifests = AsyncMock()
    enforcer._delete_backup = AsyncMock(return_value=123)

    assert enforcer._is_expired(root)
    assert not enforcer._is_expired(child)
    first = await enforcer.enforce_all()
    assert not first.get("skipped"), first
    assert first["deleted_count"] == 0
    enforcer._delete_backup.assert_not_awaited()

    child.completed_at = now - timedelta(hours=25)
    db_session.add(child)
    db_session.commit()
    assert enforcer._is_expired(child)
    assert db_session.query(Backup).filter(Backup.status == "completed").count() == 2
    second = await enforcer.enforce_all()
    assert second["deleted_count"] == 2
    assert [call.args[1].id for call in enforcer._delete_backup.await_args_list] == [
        child.id,
        root.id,
    ]


@pytest.mark.parametrize(
    "state", ["pending", "dispatching", "running", "cleanup_required"]
)
def test_restore_custody_protects_source_chain(db_session, state):
    _, _, backup = ready(db_session)
    db_session.add(
        Restore(
            org_id=backup.org_id,
            backup_id=backup.id,
            created_by=str(uuid.uuid4()),
            status=state,
        )
    )
    db_session.commit()
    store = Store()
    with pytest.raises(BackupDependencyError, match="restore"):
        delete_transaction_payload(db_session, backup.id, client=store)
    assert not store.deleted


def test_changed_object_is_not_deleted():
    store = Store()

    def changed(**args):
        raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "DeleteObject")

    store.delete_object = changed
    with pytest.raises(ClientError):
        _delete_object(
            store,
            "backup",
            dict(
                key="owned/object", etag='"original"', version_id="immutable-original"
            ),
        )


def test_delete_ack_without_absence_is_not_success():
    store = Store()
    store.head_object = lambda **args: {"ETag": '"still-present"'}
    with pytest.raises(StorageOwnershipError, match="still exists"):
        _delete_object(
            store,
            "backup",
            dict(
                key="owned/object", etag='"original"', version_id="immutable-original"
            ),
        )


@pytest.mark.parametrize("version", [None, "", "null"])
def test_unversioned_delete_refuses_before_provider_io(version):
    class IgnoresIfMatch(Store):
        def delete_object(self, **args):
            pytest.fail("Unqualified conditional delete reached the provider")

        def head_object(self, **args):
            pytest.fail("HEAD must not be used as a TOCTOU deletion fallback")

    with pytest.raises(StorageOwnershipError, match="Immutable S3 version IDs"):
        _delete_object(
            IgnoresIfMatch(),
            "backup",
            dict(key="owned/object", etag='"original"', version_id=version),
        )
