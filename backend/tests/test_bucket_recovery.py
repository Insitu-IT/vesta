"""Fresh-console recovery selects immutable bucket evidence and local destinations."""

import base64
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
from secrets import token_bytes
from uuid import uuid4

from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from fastapi import HTTPException
import pytest

from backend.tests.test_native_restore import member as native_member
from backend.tests.test_storage_restore import member as kubevirt_member
from core import bucket_recovery as recovery
from core import settings_service
from core.recovery_signing import _public_identity, sign_point
from core.storage_publication import _member
from core.storage_receipt_v2 import canonical
from core.storage_wire import plan_digest
from models import (
    Agent,
    Backup,
    EncryptionKey,
    OperatorRequest,
    Organization,
    OrganizationDefault,
    Restore,
    S3Publication,
    StorageConfigurationClock,
    StorageLineageGeneration,
    User,
)
from routers.s3_import import PointRequest, RestoreRequest, preview_point, restore_point


def uid():
    return str(uuid4())


class ReadOnlyBucket:
    def __init__(self):
        self.objects = {}
        self.reads = []

    def close(self):
        pass

    def get_object(self, **args):
        self.reads.append(args)
        item = self.head_object(**args)
        return {**item, "Body": BytesIO(self.objects[args["Key"]][0])}

    def head_object(self, **args):
        if args["Key"] not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        data, etag, version = self.objects[args["Key"]]
        if args.get("IfMatch", etag) != etag or args.get(
            "VersionId", version or "null"
        ) != (version or "null"):
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "GetObject")
        return {"ContentLength": len(data), "ETag": etag, "VersionId": version}

    def list_object_versions(self, **args):
        keys = [
            key
            for key in sorted(self.objects)
            if key.startswith(args["Prefix"]) and key > args.get("KeyMarker", "")
        ]
        versions = [
            {
                "Key": key,
                "VersionId": self.objects[key][2] or "null",
                "IsLatest": True,
                "LastModified": datetime.now(timezone.utc),
            }
            for key in keys[: args["MaxKeys"]]
        ]
        truncated = len(keys) > args["MaxKeys"]
        response = {"Versions": versions, "IsTruncated": truncated}
        if truncated:
            response.update(
                NextKeyMarker=versions[-1]["Key"],
                NextVersionIdMarker=versions[-1]["VersionId"],
            )
        return response


def capture_fixture(member, native, key_id, kek, dek):
    from core.native_storage import build_artifacts

    request = member["request"]
    plan = request["plan"]
    receipt = member["receipt"]
    source = plan["source"]
    plan["encryption"] = {
        "format": "vnbu1-aes256gcm-chunk5242880",
        "key_ref": f"kek:{key_id}:{sha256(kek).hexdigest()[:16]}",
    }

    def envelope(body):
        nonce = token_bytes(12)
        frame = nonce + AESGCM(dek).encrypt(nonce, body, None)
        return b"VNBU\x01" + len(frame).to_bytes(4, "big") + frame

    def update_object(obj, body, storage):
        obj.update(
            plaintext_bytes=len(body),
            ciphertext_bytes=len(storage),
            plaintext_sha256=sha256(body).hexdigest(),
            ciphertext_sha256=sha256(storage).hexdigest(),
        )
        return obj["key"], (storage, obj["etag"], obj["version_id"])

    blobs = {}
    if native:
        domain = member["native_result"]["manifest"]
        raw = (
            f'<domain type="kvm"><name>source-vm</name><uuid>{domain["domain_uuid"]}</uuid>'
            "<metadata><private>synthetic-private-bootstrap</private></metadata>"
            '<devices><interface type="network"><mac address="52:54:00:00:00:0a"/>'
            '<source network="source-network"/></interface></devices></domain>'
        ).encode()
        domain["domain_xml_sha256"] = sha256(raw).hexdigest()
        manifest = canonical(domain)
        member["native_result"]["manifest_sha256"] = sha256(manifest).hexdigest()
        inventory = source["inventory"]
        for item in inventory["files"]:
            if item["role"] == "domain_config":
                item["size"] = len(raw)
            if item["role"] == "backup_metadata":
                item["size"] = len(manifest)
        source["inventory_sha256"] = sha256(canonical(inventory)).hexdigest()
        plan["artifacts"] = build_artifacts(
            source,
            request["org_id"],
            request["backup_id"],
            request["reservation_id"],
            plan["encryption"],
        )
        bounds = {entry["key"]: entry for entry in plan["artifacts"]}
        for obj in receipt["objects"]:
            obj["ciphertext_bytes"] = bounds[obj["key"]]["ciphertext_max"]
            if obj["role"] == "domain_config":
                key, value = update_object(obj, raw, envelope(raw))
                blobs[key] = value
            elif obj["role"] == "backup_metadata":
                update_object(obj, manifest, envelope(manifest))
    else:
        definition = {
            "apiVersion": "kubevirt.io/v1",
            "kind": "VirtualMachine",
            "metadata": {
                "namespace": source["namespace"],
                "uid": source["vm_uid"],
                "name": plan["vm_name"],
                "resourceVersion": "7",
            },
            "spec": {
                "template": {
                    "spec": {
                        "networks": [{"name": "frontend", "pod": {}}],
                        "domain": {
                            "devices": {
                                "interfaces": [
                                    {
                                        "name": "frontend",
                                        "macAddress": "52:54:00:00:00:0a",
                                    }
                                ]
                            }
                        },
                        "volumes": [
                            *[
                                {
                                    "name": v["name"],
                                    "persistentVolumeClaim": {
                                        "claimName": v["pvc_name"]
                                    },
                                }
                                for v in source["volumes"]
                            ],
                            {
                                "name": "bootstrap",
                                "cloudInitNoCloud": {
                                    "secretRef": {"name": "bootstrap-data"},
                                    "userData": "synthetic-private-bootstrap",
                                },
                            },
                            {"name": "config", "configMap": {"name": "app-config"}},
                        ],
                    }
                }
            },
        }
        archive = base64.b64encode(envelope(canonical(definition))).decode()
        for artifact in plan["artifacts"]:
            if artifact["role"] == "volume_payload":
                artifact["ciphertext_min"] = 5
                maximum = artifact["plaintext_max"]
                artifact["ciphertext_max"] = (
                    5 + maximum + 32 * ((maximum + 5242879) // 5242880)
                )
        payloads = {
            obj["volume_id"]: obj
            for obj in receipt["objects"]
            if obj["role"] == "volume_payload"
        }
        for payload in payloads.values():
            payload["ciphertext_bytes"] = 5 + payload["plaintext_bytes"] + 32
        volumes = {volume["pvc_uid"]: volume for volume in source["volumes"]}
        for obj in receipt["objects"]:
            if obj["role"] == "volume_manifest":
                raw = canonical(
                    {
                        "format": "vnbui-kubevirt-cbt-v1",
                        "vm_namespace": source["namespace"],
                        "vm_uid": source["vm_uid"],
                        "volume": volumes[obj["volume_id"]]["name"],
                        "backup_type": plan["backup_type"],
                        "encrypted": True,
                        "payload_key": payloads[obj["volume_id"]]["key"],
                        "vm_definition": archive,
                    }
                )
                key, value = update_object(obj, raw, raw)
                blobs[key] = value
    request["plan_sha256"] = plan_digest(plan)
    member["receipt_sha256"] = sha256(canonical(receipt)).hexdigest()
    member["acceptance"]["receipt_sha256"] = member["receipt_sha256"]
    member["wrapped_attempt_key"] = {
        "schema": 1,
        "org_id": request["org_id"],
        "backup_id": request["backup_id"],
        "reservation_id": request["reservation_id"],
        "attempt_id": plan["attempt_id"],
        "plan_sha256": request["plan_sha256"],
        "key_ref": plan["encryption"]["key_ref"],
        "format": plan["encryption"]["format"],
        "wrapping": "aes256-keywrap/1",
        "ciphertext": base64.b64encode(aes_key_wrap(kek, dek)).decode(),
    }
    return blobs


@pytest.fixture(
    params=[
        (provider, region)
        for provider in ("libvirt", "kubevirt")
        for region in ("us-east-1", "")
    ],
    ids=["native-region", "native-default", "kubevirt-region", "kubevirt-default"],
)
def recovery_site(request, db_session, monkeypatch):
    provider, region = request.param
    native = provider == "libvirt"
    make = native_member if native else kubevirt_member
    root = make(db_session)
    tip = make(db_session, root if native else root[0])
    generation, _, _ = tip
    installation = uid()
    members = []
    for item, claim, backup in (root, tip):
        claim.finalize_intent = {
            "binding": {
                "tracker_uid": item.tracker_uid,
                "checkpoint": item.checkpoint,
            }
        }
        accepted = claim.expected_plan["transaction"]
        accepted["plan"]["target"]["region"] = region
        accepted["plan_sha256"] = plan_digest(accepted["plan"])
        value = _member(claim, accepted, backup)
        members.append(value)
    key_id, kek, dek = uid(), b"k" * 32, b"d" * 32
    captures = capture_fixture(members[-1], native, key_id, kek, dek)
    selected = members[-1]["request"]["plan"]["source"]
    target = members[-1]["request"]["plan"]["target"]
    point = dict(
        format="vesta-recovery-point/1",
        installation_id=installation,
        org_id=generation.org_id,
        generation_id=generation.id,
        backup_id=generation.backup_id,
        root_backup_id=generation.root_backup_id,
        provider=provider,
        name=generation.accepted_request["plan"].get("vm_name", "historical-native-vm"),
        completed_at="2026-11-27T10:00:00Z",
    )
    manifest = {
        **{
            key: point[key]
            for key in (
                "installation_id",
                "org_id",
                "generation_id",
                "backup_id",
                "root_backup_id",
            )
        },
        "protocol": "vnbui-storage-generation/1",
        "predecessor_id": root[0].id,
        "source": selected,
        "target": target,
        "members": members,
    }
    body = canonical(manifest)
    point["generation"] = {
        **{field: target[field] for field in ("endpoint", "bucket", "region")},
        "key": recovery._generation_key(point),
        "version_id": "exact-version",
        "etag": '"receipt-etag"',
        "bytes": len(body),
        "sha256": sha256(body).hexdigest(),
    }
    key = Ed25519PrivateKey.generate()
    _, public = _public_identity(key)
    trust = recovery.TrustAnchor(
        installation_id=installation, org_id=generation.org_id, public_key=public
    )
    envelope_key = recovery._point_key(trust.model_dump(), point["backup_id"])
    bucket = ReadOnlyBucket()
    bucket.objects.update(captures)
    bucket.objects.update(
        {
            point["generation"]["key"]: (body, '"receipt-etag"', "exact-version"),
            envelope_key: (sign_point(point, key), '"signature"', "signature-version"),
        }
    )
    db_session.query(StorageLineageGeneration).delete()
    db_session.query(S3Publication).delete()
    db_session.query(Backup).delete()
    org = Organization(id=uid(), name="new installation", enabled=True)
    admin = User(
        id=uid(),
        org_id=org.id,
        username="new-admin",
        password_hash="unused",
        role="admin",
        is_active=True,
    )
    agent = Agent(
        id=uid(),
        org_id=org.id,
        hostname="local-agent",
        status="online",
        capabilities={"provider": provider, "s3_recovery_restore": True},
        metrics={"scope": {"restore_namespaces": ["recovery"]}},
    )
    from core.kms.local import _get_fernet

    imported_key = EncryptionKey(
        id=key_id,
        org_id=org.id,
        name="Imported recovery fixture",
        key_hash=sha256(kek).hexdigest()[:16],
        algorithm="aes-256-gcm",
        encrypted_material=_get_fernet().encrypt(kek).decode(),
        status="rotated",
        provider="local",
    )
    db_session.add_all(
        [
            org,
            admin,
            agent,
            imported_key,
            StorageConfigurationClock(slot=1, installation_id=uid(), revision=1),
        ]
    )
    db_session.get(OrganizationDefault, "oss").org_id = org.id
    db_session.commit()
    monkeypatch.setattr(recovery, "vm_agent_peer", lambda *_: "pinned-local-peer")
    monkeypatch.setattr(settings_service, "_fernet", Fernet(Fernet.generate_key()))
    settings = settings_service.SettingsService(db_session)
    for field in ("endpoint", "bucket", "region"):
        settings.set(f"storage.s3.{field}", target[field])
    settings.set_secret("storage.s3.access_key", "test-write")
    settings.set_secret("storage.s3.secret_key", "private-write")
    settings.set_secret("storage.s3.recovery_access_key", "test-read")
    settings.set_secret("storage.s3.recovery_secret_key", "private-read")

    def scoped_client(config):
        assert config["access_key"] == "test-read"
        assert config["secret_key"] == "private-read"
        return bucket

    monkeypatch.setattr(recovery, "_client", scoped_client)
    if native:
        push = members[-1]["native_result"]["manifest"]
        mapping = {
            "native_target": {
                "vm_name": "recovered-vm",
                "disks": [disk["target"] for disk in push["disks"]],
                "drop_excluded_disks": push["exclusions"],
                "networks": [
                    {
                        "source_mac": "52:54:00:00:00:0a",
                        "network": "destination-network",
                    }
                ],
            }
        }
    else:
        mapping = {
            "kubevirt_target": {
                "vm_name": "recovered-vm",
                "namespace": "recovery",
                "disks": [
                    {
                        "pvc_name": "recovered-data",
                        "storage_class": "recovery-block",
                        "volume_name": selected["volumes"][0]["name"],
                        "capacity_bytes": selected["volumes"][0]["capacity_bytes"],
                        "access_mode": "ReadWriteOnce",
                        "volume_mode": "Filesystem",
                    }
                ],
                "networks": [{"name": "frontend", "type": "pod", "network_name": ""}],
                "dependencies": {
                    "secret/bootstrap-data": "fresh-bootstrap",
                    "configMap/app-config": "fresh-config",
                },
            }
        }
    return bucket, point, trust, admin, agent, mapping, envelope_key


@pytest.mark.parametrize(
    "recover_access,recover_secret",
    [
        (None, None),
        ("writer-access", "reader-secret"),
        ("reader-access", "writer-secret"),
        ("reader-access", None),
    ],
)
def test_recovery_requires_a_separate_reader_even_with_working_writer(
    db_session, monkeypatch, recover_access, recover_secret
):
    svc = settings_service.SettingsService(db_session)
    svc.set("storage.type", "s3")
    svc.set("storage.s3.endpoint", "https://repository.example")
    svc.set("storage.s3.bucket", "backups")
    monkeypatch.setenv("S3_ACCESS_KEY", "writer-access")
    monkeypatch.setenv("S3_SECRET_KEY", "writer-secret")
    monkeypatch.delenv("S3_RECOVERY_ACCESS_KEY", raising=False)
    monkeypatch.delenv("S3_RECOVERY_SECRET_KEY", raising=False)
    if recover_access is not None:
        monkeypatch.setenv("S3_RECOVERY_ACCESS_KEY", recover_access)
    if recover_secret is not None:
        monkeypatch.setenv("S3_RECOVERY_SECRET_KEY", recover_secret)
    assert svc.get_s3_config()["access_key"] == "writer-access"
    with pytest.raises(recovery.BucketRecoveryError, match="dedicated read-only"):
        recovery.configured_repository(db_session)


@pytest.mark.asyncio
async def test_settings_saves_recovery_only_reader_as_redacted_encrypted_pair(
    db_session, monkeypatch, recovery_site
):
    from models import SecretV3
    from routers import config

    _, _, _, admin, _, _, _ = recovery_site
    svc = settings_service.SettingsService(db_session)
    for key in ("S3_ACCESS_KEY", "S3_SECRET_KEY"):
        monkeypatch.delenv(key, raising=False)
    for field in ("access_key", "secret_key"):
        svc.delete_secret(f"storage.s3.{field}")
    result = await config.update_settings_v3(
        {
            "storage.s3.recovery_access_key": "new-reader-access",
            "storage.s3.recovery_secret_key": "new-reader-secret",
        },
        admin,
        db_session,
    )
    visible = await config.get_settings_v3(admin, db_session)
    assert "new-reader" not in str(result) + str(visible)
    for name in ("access_key", "secret_key"):
        key = f"storage.s3.recovery_{name}"
        assert visible["secrets"][key] == {"configured": True, "source": "ui"}
        assert "new-reader" not in db_session.get(SecretV3, key).encrypted_value
    assert svc.get_s3_config() is None
    assert (
        recovery.configured_repository(db_session)["secret_key"] == "new-reader-secret"
    )


def test_discovery_marks_a_withdrawn_signed_generation_unavailable(
    db_session, recovery_site
):
    bucket, point, trust, _, _, _, envelope = recovery_site
    key = point["generation"]["key"]
    anchor = trust.model_dump(exclude_none=True)
    assert recovery.discover(db_session, anchor)["points"][0]["status"] == "verified"
    del bucket.objects[key]
    response = recovery.discover(db_session, anchor)
    assert response["points"][0]["status"] == "unavailable"
    assert response["points"][0]["backup_id"] == point["backup_id"]
    assert envelope in bucket.objects


def test_discover_requires_independent_trust_and_does_not_fallback(
    db_session, recovery_site
):
    bucket, point, trust, _, _, _, envelope_key = recovery_site
    assert recovery.discover(db_session)["points"][0]["status"] == "trust_required"
    assert (
        recovery.discover(db_session, trust.model_dump(exclude_none=True))["points"][0][
            "status"
        ]
        == "verified"
    )
    assert recovery.discover(db_session, legacy=True)["points"] == []
    body, _, _ = bucket.objects[envelope_key]
    bucket.objects[envelope_key] = (
        body.replace(b"EdDSA", b"tampered")[:-1] + b"?",
        '"changed"',
        None,
    )
    assert recovery.discover(db_session)["points"][0]["status"] == "invalid"
    assert recovery.discover(db_session, legacy=True)["points"] == []
    del bucket.objects[envelope_key]
    legacy = recovery.discover(db_session, legacy=True)["points"][0]
    assert legacy["status"] == "unsigned"
    assert legacy["generation_key"] == point["generation"]["key"]
    assert legacy["version_id"] == point["generation"]["version_id"]


def test_discovery_retains_valid_points_across_mixed_version_pages(
    db_session, recovery_site, monkeypatch
):
    bucket, point, trust, _, _, _, _ = recovery_site
    authority = trust.model_dump(exclude_none=True)
    other = "ffffffff-ffff-4fff-bfff-ffffffffffff"
    assert point["backup_id"] < other
    next_key = recovery._point_key(authority, other)
    bucket.objects[next_key] = (b"unverifiable envelope", '"bad"', "exact-bad-version")
    mixed = recovery.discover(db_session, authority)
    assert {item["status"] for item in mixed["points"]} == {"verified", "invalid"}
    monkeypatch.setattr(recovery, "DISCOVERY_LIMIT", 1)
    first = recovery.discover(db_session, authority)
    second = recovery.discover(db_session, authority, first["next_cursor"])
    assert first["points"][0]["status"] == "verified"
    assert second["points"][0]["status"] == "invalid"
    assert second["next_cursor"] is None
    assert all(read.get("VersionId") for read in bucket.reads)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper_after_approval", [False, True])
async def test_fresh_database_queues_and_executes_existing_worker(
    db_session, recovery_site, monkeypatch, tamper_after_approval
):
    import asyncio
    from types import SimpleNamespace

    import httpx
    from sqlalchemy.orm import sessionmaker
    from core import restore_executor as worker

    bucket, point, trust, admin, agent, mapping, _ = recovery_site
    preview = preview_point(
        point["backup_id"], PointRequest(trust=trust), admin, db_session
    )
    assert preview["destination_agents"][0]["id"] == agent.id
    assert preview["requires_kek"] is True
    assert "synthetic-private-bootstrap" not in str(preview)
    if "native_target" in mapping:
        assert preview["source"]["interfaces"] == [
            {"source_mac": "52:54:00:00:00:0a", "source_network": "source-network"}
        ]
    else:
        assert preview["source"]["networks"] == [
            {"name": "frontend", "type": "pod", "source_mac": "52:54:00:00:00:0a"}
        ]
        assert preview["source"]["dependencies"] == [
            {"kind": "configMap", "name": "app-config"},
            {"kind": "secret", "name": "bootstrap-data"},
        ]
    request = RestoreRequest(trust=trust, agent_id=agent.id, **mapping)
    request_id = uid()
    reply = restore_point(point["backup_id"], request, admin, db_session, request_id)
    assert reply.status_code == 201
    assert reply.headers["Cache-Control"] == "no-store"
    receipt = json.loads(reply.body)
    assert receipt["recovery_source"]["backup_id"] == point["backup_id"]
    assert receipt["recovery_source"]["status"] == "verified"
    target_key = "native_target" if "native_target" in mapping else "kubevirt_target"
    other_key = "kubevirt_target" if target_key == "native_target" else "native_target"
    assert receipt[target_key]["vm_name"] == "recovered-vm"
    assert other_key not in receipt
    for value in (
        b"private-read",
        b"test-read",
        b'"access_key"',
        b'"secret_key"',
        b'"bundle"',
        b'"generation"',
    ):
        assert value not in reply.body
    replay = restore_point(point["backup_id"], request, admin, db_session, request_id)
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.body == reply.body
    restore = db_session.query(Restore).one()
    assert restore.backup_id is None and db_session.query(Backup).count() == 0
    assert "private-read" not in str(restore.s3_recovery)
    calls = []

    peer = SimpleNamespace(agent_id=agent.id)
    native = "native_target" in mapping

    class AgentTransport:
        async def post(self, target_peer, path, *, json, headers, recheck):
            await recheck()
            assert target_peer == peer
            assert path == "/api/restores" and headers["X-Vesta-Agent-ID"] == agent.id
            plan = json["native" if native else "kubevirt"]
            assert plan["agent_id"] == agent.id and plan["org_id"] == admin.org_id
            assert plan["recovery_origin"]["org_id"] == point["org_id"]
            assert plan["s3"]["secret_key"] == "private-read"
            assert plan["s3"]["region"] == "us-east-1"
            assert all(
                member["request"]["plan"]["target"]["region"]
                == point["generation"]["region"]
                for member in plan["bundle"]["members"]
            )
            calls.append(json)
            target = plan["target"]
            result = {"vm_name": target["vm_name"], "plan_sha256": "a" * 64}
            if native:
                manifest = plan["bundle"]["members"][-1]["push_result"]["manifest"]
                result.update(
                    vm_uuid=target["vm_uuid"],
                    state="shutoff",
                    disks=[
                        {
                            "target": disk["target"],
                            "path": f"/images/{restore.id}/disks/{disk['target']}.raw",
                            "size_bytes": disk["virtual_size"],
                            "sha256": "b" * 64,
                        }
                        for disk in manifest["disks"]
                    ],
                )
            else:
                result.update(
                    namespace=target["namespace"],
                    run_strategy="Halted",
                    vm_uid="fresh-vm",
                    job_uid="fresh-job",
                    job_name="restore-job",
                    pvc_uids={disk["pvc_name"]: uid() for disk in target["disks"]},
                )
            return httpx.Response(
                202,
                request=httpx.Request("POST", "https://synthetic.invalid/api/restores"),
                json={
                    "restore_id": restore.id,
                    "status": "completed",
                    "progress_percent": 100,
                    "result": result,
                },
            )

    if tamper_after_approval:
        key = point["generation"]["key"]
        body, etag, version = bucket.objects[key]
        bucket.objects[key] = (body[::-1], etag, version)

    monkeypatch.setattr(
        worker, "SessionLocal", sessionmaker(bind=db_session.get_bind())
    )
    process = worker.RestoreExecutor()
    monkeypatch.setattr(process, "_transport", AgentTransport)
    monkeypatch.setattr(process, "_agent_peer", lambda *_: peer)
    outcome = await asyncio.wait_for(
        process.execute_restore(restore.id, admin.org_id, admin.id), timeout=10
    )
    db_session.refresh(restore)
    if tamper_after_approval:
        assert outcome == {"status": "held"}
        assert calls == [] and restore.status == "dispatching"
    else:
        assert outcome is None
        assert len(calls) == 1 and restore.status == "completed"
        assert restore.native_result if native else restore.kubevirt_result
    assert any(
        read.get("IfMatch") == '"receipt-etag"'
        and read.get("VersionId") == "exact-version"
        for read in bucket.reads
    )


def test_preview_mapping_cannot_be_omitted_from_launch(db_session, recovery_site):
    _, point, trust, admin, agent, mapping, _ = recovery_site
    plan = next(iter(mapping.values()))
    plan["networks"] = []
    command = RestoreRequest(trust=trust, agent_id=agent.id, **mapping)
    with pytest.raises(
        HTTPException, match="map every captured source|Map every captured source"
    ):
        restore_point(point["backup_id"], command, admin, db_session, uid())
    assert db_session.query(Restore).count() == 0


def test_wrong_scope_unsigned_or_invalid_destination_refused(db_session, recovery_site):
    bucket, point, trust, admin, agent, mapping, envelope_key = recovery_site
    request = RestoreRequest(trust=trust, agent_id=uid(), **mapping)
    with pytest.raises(HTTPException, match="Destination agent is unavailable"):
        restore_point(point["backup_id"], request, admin, db_session, uid())
    db_session.rollback()
    foreign = trust.model_copy(update={"org_id": uid()})
    foreign_key = recovery._point_key(foreign.model_dump(), point["backup_id"])
    bucket.objects[foreign_key] = bucket.objects[envelope_key]
    with pytest.raises(HTTPException, match="signature or source scope"):
        preview_point(
            point["backup_id"], PointRequest(trust=foreign), admin, db_session
        )
    del bucket.objects[envelope_key]
    with pytest.raises(HTTPException, match="unavailable"):
        preview_point(point["backup_id"], PointRequest(trust=trust), admin, db_session)
    assert db_session.query(Restore).count() == 0


def test_local_cross_org_recovery_stops_before_read_or_queue(
    db_session, recovery_site, monkeypatch
):
    _, point, trust, admin, agent, mapping, _ = recovery_site
    local = db_session.get(StorageConfigurationClock, 1).installation_id
    anchor = trust.model_copy(update={"installation_id": local})

    def unexpected_storage(*args, **kwargs):
        pytest.fail("foreign local organization consulted the recovery bucket")

    monkeypatch.setattr(recovery, "load_point", unexpected_storage)
    with pytest.raises(HTTPException, match="Use the original organization"):
        preview_point(point["backup_id"], PointRequest(trust=anchor), admin, db_session)
    with pytest.raises(HTTPException, match="Use the original organization"):
        restore_point(
            point["backup_id"],
            RestoreRequest(trust=anchor, agent_id=agent.id, **mapping),
            admin,
            db_session,
            uid(),
        )
    assert (
        db_session.query(OperatorRequest).count()
        == db_session.query(Restore).count()
        == 0
    )
