"""Connected native catalog/admission/progress without live provider mutation."""

from copy import deepcopy
import json
from types import SimpleNamespace
import uuid

from fastapi import BackgroundTasks, HTTPException
import pytest

from backend.tests.test_native_push import specimen
from core.native_inventory import digest
from core.native_restore import apply_progress, build_plan, hydrate_request
from core.native_restore_bundle import build_native_bundle
from core.native_storage import build_artifacts
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical
from core.storage_restore import build_restore_bundle
from core.storage_wire import plan_digest
from models import (
    Agent,
    Backup,
    Organization,
    OperatorDispatch,
    Restore,
    S3Publication,
    StorageLineageGeneration,
    User,
    VM,
)


def member(db, previous=None):
    request, _, saved, _ = specimen()
    request["backup_id"], request["reservation_id"] = str(uuid.uuid4()), str(
        uuid.uuid4()
    )
    plan, push = request["plan"], saved["push_result"]
    inventory, manifest = plan["source"]["inventory"], push["manifest"]
    plan["attempt_id"] = request["reservation_id"]
    for value in (inventory, manifest):
        value["backup_id"], value["attempt_id"] = (
            request["backup_id"],
            request["reservation_id"],
        )
        value["checkpoint"] = "vnbui-" + request["reservation_id"]
    inventory["job_id"] = "vnbui-native-" + request["reservation_id"]
    if previous:
        generation, _, previous_backup = previous
        plan["backup_type"] = "incremental"
        plan["parent"] = {
            key: getattr(generation, key)
            for key in (
                "backup_id",
                "root_backup_id",
                "receipt_sha256",
                "tracker_uid",
                "checkpoint",
            )
        }
        plan["parent"]["generation_id"] = generation.id
        manifest["parent_backup_id"] = generation.backup_id
        manifest["parent_manifest_sha256"] = previous_backup.native_inventory[
            "push_result"
        ]["manifest_sha256"]
    push["manifest_sha256"] = digest(manifest)
    for file in inventory["files"]:
        file["member_backup_id"], file["member_checkpoint"] = (
            inventory["backup_id"],
            inventory["checkpoint"],
        )
        if file["role"] == "backup_metadata":
            file["size"] = len(canonical(manifest))
        file["artifact_id"] = digest(
            [
                inventory[key]
                for key in (
                    "format",
                    "domain_uuid",
                    "backup_id",
                    "attempt_id",
                    "job_id",
                    "checkpoint",
                )
            ]
            + [
                file[key]
                for key in (
                    "member_backup_id",
                    "member_checkpoint",
                    "path",
                    "role",
                    "disk_id",
                )
            ]
        )
    saved.update(
        inventory=inventory,
        inventory_sha256=digest(inventory),
        push_manifest_canonical=canonical(manifest).decode(),
    )
    plan["source"]["inventory_sha256"] = digest(inventory)
    plan["artifacts"] = build_artifacts(
        plan["source"],
        request["org_id"],
        request["backup_id"],
        request["reservation_id"],
        plan["encryption"],
    )
    request["plan_sha256"] = plan_digest(plan)
    hashes = {
        "domain_config": manifest["domain_xml_sha256"],
        "checkpoint": manifest["checkpoint_sha256"],
        "backup_metadata": push["manifest_sha256"],
        "disk_payload": "a" * 64,
    }
    receipt = dict(
        protocol=request["protocol"],
        schema=2,
        representation="libvirt-native-fileset/1",
        reservation_id=request["reservation_id"],
        backup_id=request["backup_id"],
        endpoint=plan["target"]["endpoint"],
        bucket=plan["target"]["bucket"],
        objects=[
            dict(
                **{
                    key: artifact[key]
                    for key in ("key", "role", "artifact_id", "disk_id")
                },
                version_id="immutable-version",
                etag='"immutable"',
                plaintext_bytes=artifact["plaintext_max"],
                ciphertext_bytes=artifact["plaintext_max"],
                plaintext_sha256=hashes[artifact["role"]],
                ciphertext_sha256=hashes[artifact["role"]],
            )
            for artifact in plan["artifacts"]
        ],
    )
    receipt_hash = digest(receipt)
    backup = Backup(
        id=request["backup_id"],
        org_id=request["org_id"],
        vm_id=plan["source"]["vm_id"],
        status="completed",
        backup_type=plan["backup_type"],
        native_inventory=deepcopy(saved),
    )
    claim = S3Publication(
        id=request["reservation_id"],
        org_id=backup.org_id,
        backup_id=backup.id,
        kind="payload",
        state="published",
        endpoint=receipt["endpoint"],
        bucket=receipt["bucket"],
        object_key="payload/" + request["reservation_id"],
        dispatch_token="committed",
        expected_plan=dict(schema=3, transaction=request),
        prepared_receipt=dict(
            receipt=receipt,
            receipt_sha256=receipt_hash,
            response=dict(accepted=True, receipt_sha256=receipt_hash),
        ),
    )
    identity = str(uuid.uuid4())
    generation = StorageLineageGeneration(
        id=identity,
        org_id=backup.org_id,
        vm_id=backup.vm_id,
        backup_id=backup.id,
        root_backup_id=previous[0].root_backup_id if previous else backup.id,
        state="accepted",
        receipt_sha256=receipt_hash,
        root_receipt_sha256=(
            previous[0].root_receipt_sha256 if previous else receipt_hash
        ),
        manifest_receipt_sha256="b" * 64,
        tracker_uid=manifest["domain_uuid"],
        checkpoint=manifest["checkpoint"],
        accepted_request=deepcopy(request),
    )
    publication_manifest = dict(
        generation_id=identity,
        predecessor_id=previous[0].id if previous else None,
        members=[dict(request=request, receipt=receipt, native_result=push)],
    )
    publication = S3Publication(
        id=identity,
        org_id=backup.org_id,
        backup_id=backup.id,
        kind="chain_manifest",
        state="published",
        endpoint=receipt["endpoint"],
        bucket=receipt["bucket"],
        object_key="manifest/" + identity,
        expected_plan=dict(
            schema=4,
            generation_id=identity,
            predecessor_id=publication_manifest["predecessor_id"],
            manifest_canonical=canonical(publication_manifest).decode(),
            manifest_sha256=digest(publication_manifest),
        ),
        prepared_receipt=dict(receipt_sha256="b" * 64),
    )
    db.add_all([backup, claim, generation, publication])
    db.commit()
    return generation, claim, backup


def fixture(db):
    generation, claim, backup = member(db)
    request = claim.expected_plan["transaction"]
    org = Organization(id=backup.org_id, name="Native restore org", enabled=True)
    user = User(
        id=str(uuid.uuid4()),
        org_id=org.id,
        username="restore-native",
        email="native@example.invalid",
        password_hash="unused",
        role="operator",
        is_active=True,
    )
    agent = Agent(
        id=request["agent_id"], org_id=org.id, hostname="native-agent", status="online"
    )
    vm = VM(
        id=backup.vm_id,
        org_id=org.id,
        name="source-vm",
        uuid=generation.tracker_uid,
        vm_uid=generation.tracker_uid,
        agent_id=agent.id,
        provider="libvirt",
        inventory_present=True,
    )
    db.add_all([org, user, agent, vm])
    db.commit()
    return (
        backup,
        user,
        dict(
            vm_name="new-native-vm",
            disks=["vda", "vdb"],
            drop_excluded_disks=[],
            networks=[],
        ),
    )


def test_native_full_incremental_bundle_is_accepted_and_nonsecret(db_session):
    first = member(db_session)
    second = member(db_session, first)
    bundle = build_restore_bundle(db_session, second[2].id, second[2].org_id)
    assert bundle["schema"] == "vnbui-native-restore/1"
    assert [m["request"]["backup_id"] for m in bundle["members"]] == [
        first[2].id,
        second[2].id,
    ]
    assert set(bundle["members"][0]) == {"request", "receipt", "push_result"}
    assert not db_session.dirty
    with pytest.raises(StorageOwnershipError):
        build_native_bundle(db_session, second[2].id, str(uuid.uuid4()))


@pytest.mark.parametrize(
    "fault", ["receipt", "manifest", "ancestor", "publication", "role"]
)
def test_native_chain_corruption_or_missing_publication_refuses(db_session, fault):
    first = member(db_session)
    second = member(db_session, first)
    generation, claim, backup = first
    if fault == "receipt":
        saved = deepcopy(claim.prepared_receipt)
        saved["receipt"]["objects"][0]["etag"] = '"other"'
        claim.prepared_receipt = saved
    elif fault == "manifest":
        saved = deepcopy(backup.native_inventory)
        saved["push_result"]["manifest"]["domain_xml_sha256"] = "0" * 64
        backup.native_inventory = saved
    elif fault == "ancestor":
        backup.status = "deleted"
    elif fault == "publication":
        db_session.get(S3Publication, generation.id).state = "deleted"
    else:
        saved = deepcopy(backup.native_inventory)
        saved["inventory"]["files"][0]["role"] = "autostart"
        backup.native_inventory = saved
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        build_native_bundle(db_session, second[2].id, second[2].org_id)


@pytest.mark.parametrize(
    "fault",
    [None, "tenant", "viewer", "source", "disks", "drop", "network", "uuid", "path"],
)
def test_native_plan_requires_new_identity_and_explicit_complete_target(
    db_session, fault
):
    backup, user, target = fixture(db_session)
    if fault == "tenant":
        user.org_id = str(uuid.uuid4())
    elif fault == "viewer":
        user.role = "viewer"
    elif fault == "source":
        target["vm_name"] = backup.vm.name
    elif fault == "disks":
        target["disks"] = ["vda"]
    elif fault == "drop":
        target["drop_excluded_disks"] = ["vdb"]
    elif fault == "network":
        target["networks"] = [dict(source_mac="not-mac", network="default")]
    elif fault == "uuid":
        target["vm_uuid"] = backup.vm.uuid
    elif fault == "path":
        target["output_path"] = "/existing"
    db_session.commit()
    args = dict(
        backup_id=backup.id,
        org_id=user.org_id,
        actor_id=user.id,
        restore_id=str(uuid.uuid4()),
        target=target,
    )
    if fault:
        with pytest.raises(StorageOwnershipError):
            build_plan(db_session, **args)
    else:
        plan = build_plan(db_session, **args)
        assert plan["target"]["vm_uuid"] != backup.vm.uuid
        assert not set(plan).intersection({"keys", "s3"})


def test_native_create_resume_cancel_and_progress_contract(db_session):
    from routers.restores import create_restore, resume_kubevirt_restore, cancel_restore

    backup, user, target = fixture(db_session)
    tasks = BackgroundTasks()
    result = create_restore(
        dict(backup_id=backup.id, restore_to_original=False, native_target=target),
        tasks,
        user,
        db_session,
        request_id=str(uuid.uuid4()),
    )
    assert result.status_code == 201
    result = json.loads(result.body)
    restore = db_session.get(Restore, result["id"])
    assert restore.native_plan and not restore.kubevirt_plan and tasks.tasks == []
    work = db_session.query(OperatorDispatch).one()
    assert (
        work.resource_id == restore.id
        and work.kind == "restore"
        and work.state == "pending"
    )
    resume_kubevirt_restore(restore.id, tasks, user, db_session)
    with pytest.raises(HTTPException):
        cancel_restore(restore.id, user, db_session)
    manifest = restore.native_plan["bundle"]["members"][-1]["push_result"]["manifest"]
    response = dict(
        restore_id=restore.id,
        status="completed",
        progress_percent=100,
        result=dict(
            vm_name=target["vm_name"],
            vm_uuid=restore.native_plan["target"]["vm_uuid"],
            state="shutoff",
            plan_sha256="a" * 64,
            disks=[
                dict(
                    target=d["target"],
                    path="/images/" + restore.id + "/disks/" + d["target"] + ".raw",
                    size_bytes=d["virtual_size"],
                    sha256="b" * 64,
                )
                for d in manifest["disks"]
            ],
        ),
    )
    wrong = deepcopy(response)
    wrong["result"]["vm_uuid"] = backup.vm.uuid
    with pytest.raises(StorageOwnershipError):
        apply_progress(restore, wrong)
    apply_progress(restore, response)
    assert restore.status == "completed" and restore.native_result["state"] == "shutoff"


def test_native_hydration_rechecks_catalog_before_key_delivery(db_session, monkeypatch):
    backup, user, target = fixture(db_session)
    plan = build_plan(
        db_session,
        backup_id=backup.id,
        org_id=user.org_id,
        actor_id=user.id,
        restore_id=str(uuid.uuid4()),
        target=target,
    )
    restore = SimpleNamespace(
        id=plan["restore_id"], org_id=user.org_id, backup_id=backup.id, native_plan=plan
    )
    target = plan["bundle"]["members"][0]["request"]["plan"]["target"]
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config",
        lambda self: dict(target, access_key="read", secret_key="private"),
    )
    calls = []
    monkeypatch.setattr(
        "core.storage_attempt_key.unwrap_retained_attempt_key",
        lambda *args: calls.append(args[2]["backup_id"]) or b"x" * 32,
    )
    delivered = hydrate_request(db_session, restore)
    assert delivered["native"]["keys"][backup.id] and calls == [backup.id]
    assert "private" not in json.dumps(plan) and "keys" not in plan
    backup.status = "deleted"
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        hydrate_request(db_session, restore)
    assert calls == [backup.id]
