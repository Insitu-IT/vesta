"""Real accepted metadata, signed compact bytes and conditional offsite custody."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from types import SimpleNamespace
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

from core.recovery_evidence import accepted_evidence
from core import recovery_publication
from core.recovery_publication import publication_status, publish_one
from core.recovery_signing import (
    RecoveryUnavailable,
    recovery_trust,
    sign_point,
    signing_key,
    verify_point_envelope,
)
from core.storage_publication import _member, _metadata
from core.storage_receipt_v2 import canonical
from models import (
    Backup,
    Organization,
    RecoveryPublication,
    S3Publication,
    StorageConfigurationClock,
    VM,
)
from .test_storage_restore import member
from .test_native_restore import member as native_member


def seed_accepted_source(db_session, monkeypatch, *, native=False, completed_at=None):
    from core import settings_service

    db = db_session
    clock = db.get(StorageConfigurationClock, 1)
    if clock is None:
        monkeypatch.setattr(settings_service, "_fernet", Fernet(Fernet.generate_key()))
        clock = StorageConfigurationClock(
            slot=1, installation_id=str(uuid4()), revision=1
        )
        db.add(clock)
    generation, claim, backup = (native_member if native else member)(db)
    if db.get(Organization, generation.org_id) is None:
        db.add(Organization(id=generation.org_id, name="Accepted recovery fixture"))
    if native:
        db.add(
            VM(
                id=backup.vm_id,
                org_id=backup.org_id,
                agent_id=generation.accepted_request["agent_id"],
                name="enrolled-native-vm",
            )
        )
    backup.completed_at = completed_at or datetime(2026, 11, 20, 12)
    claim.finalize_intent = {"binding": {"checkpoint": "synthetic-checkpoint"}}
    claim.checkpoint_proof = {"schema": 1}
    nested = _member(claim, generation.accepted_request, backup)
    target = generation.accepted_request["plan"]["target"]
    manifest = dict(
        protocol="vnbui-storage-generation/1",
        installation_id=clock.installation_id,
        org_id=generation.org_id,
        generation_id=generation.id,
        predecessor_id=None,
        root_backup_id=generation.root_backup_id,
        backup_id=generation.backup_id,
        source=generation.accepted_request["plan"]["source"],
        target=target,
        members=[nested],
    )
    raw = canonical(manifest)
    key = (
        f"vnbui-owned/v1/{sha256(generation.org_id.encode()).hexdigest()}/"
        f"{sha256(generation.root_backup_id.encode()).hexdigest()}/generations/{generation.id}.json"
    )
    receipt = dict(
        schema=1,
        generation_id=generation.id,
        endpoint=target["endpoint"],
        bucket=target["bucket"],
        key=key,
        version_id="original-version",
        etag='"original"',
        bytes=len(raw),
        sha256=sha256(raw).hexdigest(),
        assurance="consumer_sha256_verified",
    )
    receipt_bytes = canonical(receipt)
    generation.manifest_receipt_sha256 = sha256(receipt_bytes).hexdigest()
    publication = db.get(S3Publication, generation.id)
    if publication is None:
        publication = S3Publication(
            id=generation.id,
            org_id=generation.org_id,
            backup_id=generation.backup_id,
            kind="chain_manifest",
            state="published",
            endpoint=target["endpoint"],
            bucket=target["bucket"],
            dispatch_token="retained-document",
        )
    publication.object_key = key
    publication.expected_plan = dict(
        schema=4,
        generation_id=generation.id,
        predecessor_id=None,
        manifest_canonical=raw.decode(),
        manifest_sha256=sha256(raw).hexdigest(),
    )
    publication.prepared_receipt = {
        "receipt": receipt,
        "receipt_canonical": receipt_bytes.decode(),
        "receipt_sha256": generation.manifest_receipt_sha256,
    }
    db.add(publication)
    db.commit()
    return generation, publication, raw


@pytest.fixture
def accepted_source(db_session, monkeypatch):
    return seed_accepted_source(db_session, monkeypatch)


def test_native_point_uses_trusted_vm_label_and_no_kubevirt_name_field(
    db_session, monkeypatch
):
    generation, _, _ = seed_accepted_source(db_session, monkeypatch, native=True)
    assert "vm_name" not in generation.accepted_request["plan"]
    result = accepted_evidence(db_session, generation.org_id, generation.backup_id)
    assert result.point["provider"] == "libvirt"
    assert result.point["name"] == "enrolled-native-vm"


def test_exact_signed_accepted_point_and_independently_saved_trust(
    db_session, session_factory, accepted_source
):
    generation, _, _ = accepted_source
    proof = accepted_evidence(db_session, generation.org_id, generation.backup_id)
    key = signing_key(session_factory)
    trust = recovery_trust(db_session, generation.org_id, factory=session_factory)
    signed = sign_point(proof.point, key)
    assert proof.point["provider"] == "kubevirt"
    assert proof.point["completed_at"] == "2026-11-20T12:00:00Z"
    assert proof.point["generation"]["version_id"] == "original-version"
    from core.recovery_signing import validate_recovery_trust

    assert validate_recovery_trust(trust) == trust
    with pytest.raises(RecoveryUnavailable):
        validate_recovery_trust({**trust, "key_id": "0" * 64})
    assert verify_point_envelope(signed, trust) == proof.point
    assert sign_point(proof.point, signing_key(session_factory)) == signed
    with pytest.raises(RecoveryUnavailable):
        verify_point_envelope(signed, {**trust, "org_id": str(uuid4())})
    with pytest.raises(RecoveryUnavailable):
        verify_point_envelope(signed, {**trust, "public_key": "a" * 43})
    with pytest.raises(RecoveryUnavailable):
        accepted_evidence(db_session, str(uuid4()), generation.backup_id)


def test_original_generation_hash_disagreement_never_attests(
    db_session, accepted_source
):
    generation, publication, _ = accepted_source
    publication.prepared_receipt = {
        **publication.prepared_receipt,
        "receipt_sha256": "0" * 64,
    }
    db_session.commit()
    with pytest.raises(RecoveryUnavailable):
        accepted_evidence(db_session, generation.org_id, generation.backup_id)


class Store:
    def __init__(self, proof, manifest, *, lose_ack=False):
        source = proof.point["generation"]
        self.meta = SimpleNamespace(
            endpoint_url=source["endpoint"],
            region_name=source["region"] or "us-east-1",
            events=SimpleNamespace(register=lambda *args: None),
        )
        self.bucket = source["bucket"]
        self.objects = {
            source["key"]: (
                manifest,
                source["etag"],
                source["version_id"],
                _metadata(proof.publication_snapshot),
            )
        }
        self.writes = 0
        self.lose_ack = lose_ack

    def get_object(self, Bucket, Key, **identity):
        assert Bucket == self.bucket
        if Key not in self.objects:
            # S3 can hide a missing key from writers that cannot list a bucket.
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        body, etag, version, meta = self.objects[Key]
        if identity:
            assert identity == {"IfMatch": etag, "VersionId": version}
        return dict(
            Body=BytesIO(body),
            ETag=etag,
            VersionId=version,
            ContentLength=len(body),
            Metadata=meta,
        )

    def put_object(self, Bucket, Key, Body, ContentType, IfNoneMatch):
        assert Bucket == self.bucket and IfNoneMatch == "*"
        assert Key.startswith("vesta-recovery/v1/") and Key not in self.objects
        self.writes += 1
        self.objects[Key] = Body, '"record"', "record-version", {}
        if self.lose_ack:
            raise TimeoutError()
        return {"ETag": '"record"', "VersionId": "record-version"}

    def close(self):
        pass


@pytest.mark.parametrize("lose_ack", [False, True])
def test_background_backfill_publishes_once_from_accepted_bytes(
    db_session, session_factory, monkeypatch, accepted_source, lose_ack
):
    generation, _, raw = accepted_source
    proof = accepted_evidence(db_session, generation.org_id, generation.backup_id)
    store = Store(proof, raw, lose_ack=lose_ack)
    monkeypatch.setattr(
        "core.recovery_publication._recorded_target_client", lambda *a, **kw: store
    )
    assert publish_one(session_factory, generation.org_id)
    row = db_session.get(RecoveryPublication, generation.id)
    assert row.published_at is not None
    assert row.publication_receipt["version_id"] == "record-version"
    trust = recovery_trust(db_session, generation.org_id, factory=session_factory)
    assert verify_point_envelope(store.objects[row.object_key][0], trust) == proof.point
    assert not publish_one(session_factory, generation.org_id)
    assert store.writes == 1
    assert store.objects[proof.point["generation"]["key"]][0] == raw


def test_due_old_failures_cannot_starve_new_recovery_points(
    db_session, session_factory, monkeypatch
):
    now = datetime(2026, 11, 27, 12, tzinfo=timezone.utc)

    class TickClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr(recovery_publication, "datetime", TickClock)
    stores = {}

    def new_point(completed_at, *, accessible):
        entry, _, raw = seed_accepted_source(
            db_session, monkeypatch, completed_at=completed_at
        )
        proof = accepted_evidence(db_session, entry.org_id, entry.backup_id)
        store = Store(proof, raw)
        if not accessible:

            def unavailable(**_):
                raise TimeoutError("archived fixture generation is unavailable")

            store.get_object = unavailable
        stores[entry.id] = store
        return entry

    old = [
        new_point(now - timedelta(days=7, hours=number), accessible=False)
        for number in range(8)
    ]
    org = old[0].org_id
    monkeypatch.setattr(recovery_publication, "organization_work_ids", lambda _: [org])
    monkeypatch.setattr(
        recovery_publication,
        "_recorded_target_client",
        lambda _, record, **kw: stores[record.id],
    )
    recovery_publication.run_recovery_publication(session_factory)
    db_session.expire_all()
    retained = db_session.query(RecoveryPublication).all()
    assert len(retained) == recovery_publication.BATCH_LIMIT
    assert all(row.attempt_count == 1 and row.last_failure_at for row in retained)
    assert all(row.published_at is None for row in retained)
    retry_status = publication_status(
        db_session, db_session.get(Backup, retained[0].backup_id)
    )
    assert retry_status["state"] == "retrying" and retry_status["next_attempt_at"]

    now += timedelta(minutes=5)
    first = new_point(now, accessible=True)
    backup = db_session.get(Backup, first.backup_id)
    assert publication_status(db_session, backup)["state"] == "pending"
    recovery_publication.run_recovery_publication(session_factory)
    db_session.expire_all()
    assert stores[first.id].writes == 1
    assert publication_status(db_session, backup)["state"] == "ready"

    now += timedelta(minutes=5)
    second = new_point(now, accessible=True)
    recovery_publication.run_recovery_publication(session_factory)
    db_session.expire_all()
    assert stores[second.id].writes == 1
    retries = (
        db_session.query(RecoveryPublication)
        .filter(RecoveryPublication.attempt_count > 1)
        .all()
    )
    assert retries and all(
        row.next_attempt_at - row.last_failure_at >= timedelta(minutes=10)
        for row in retries
    )
    assert recovery_publication._retry_delay(1_000_000) == timedelta(hours=6)
    backup.status = "deleting"
    assert publication_status(db_session, backup)["state"] == "unavailable"


def test_organization_visit_cursor_survives_a_new_tick_without_process_state(
    db_session, session_factory, monkeypatch
):
    organizations = sorted(str(uuid4()) for _ in range(3))
    monkeypatch.setattr(
        recovery_publication, "organization_work_ids", lambda _: organizations
    )
    monkeypatch.setattr(recovery_publication, "signing_key", lambda _: None)
    monkeypatch.setattr(recovery_publication, "BATCH_LIMIT", 2)
    visits = []

    def work(_, org_id, *, prefer_recent):
        visits.append((org_id, prefer_recent))
        return True

    monkeypatch.setattr(recovery_publication, "publish_one", work)
    for _ in range(3):
        recovery_publication.run_recovery_publication(session_factory)
    assert visits == [
        (org, prefer_recent) for org in organizations for prefer_recent in (True, False)
    ]
    from core.installation_config import RECOVERY_PUBLICATION_CURSOR
    from core.settings_service import SettingsService

    assert SettingsService(db_session).get(RECOVERY_PUBLICATION_CURSOR) is None


def test_public_trust_uses_existing_tenant_role_and_never_returns_seed(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from database import get_db
    from deps import get_current_user
    from routers.recovery_trust import router

    actor = SimpleNamespace(org_id=str(uuid4()), role="viewer")
    expected = {
        "schema": "vesta-recovery-trust/1",
        "installation_id": str(uuid4()),
        "org_id": actor.org_id,
        "key_id": "a" * 64,
        "public_key": "b" * 43,
    }
    reads = []

    def trust(db, org_id):
        reads.append(org_id)
        return expected

    monkeypatch.setattr("routers.recovery_trust.recovery_trust", trust)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_db] = lambda: None
    with TestClient(app) as client:
        assert client.get("/api/v1/recovery/trust").status_code == 403
        assert not reads
        actor.role = "admin"
        response = client.get("/api/v1/recovery/trust")
        assert (
            response.status_code == 200
            and response.headers["Cache-Control"] == "no-store"
        )
        assert response.json() == expected and reads == [actor.org_id]


def test_existing_signing_seed_is_never_replaced_on_decrypt_failure(
    db_session, session_factory, accepted_source
):
    from core.recovery_signing import SIGNING_SEED
    from models import SecretV3

    signing_key(session_factory)
    row = db_session.get(SecretV3, SIGNING_SEED)
    row.encrypted_value = "unsupported-ciphertext"
    db_session.commit()
    with pytest.raises(RecoveryUnavailable):
        signing_key(session_factory)
    db_session.expire_all()
    assert (
        db_session.get(SecretV3, SIGNING_SEED).encrypted_value
        == "unsupported-ciphertext"
    )


def test_recovery_signer_survives_restored_clone_with_rewrapped_root(
    db_session, session_factory, accepted_source, monkeypatch
):
    import base64

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from core import settings_service
    from core.installation_config import RECOVERY_SIGNER_IDENTITY, read_configuration
    from core.recovery_signing import SIGNING_SEED
    from models import Base, SecretV3, SettingV3

    generation, _, _ = accepted_source
    point = accepted_evidence(db_session, generation.org_id, generation.backup_id).point
    original_signed = sign_point(point, signing_key(session_factory))
    original_trust = recovery_trust(
        db_session, generation.org_id, factory=session_factory
    )
    seed = db_session.get(SecretV3, SIGNING_SEED).encrypted_value
    marker = db_session.get(SettingV3, RECOVERY_SIGNER_IDENTITY).value
    assert read_configuration(db_session, SecretV3, SIGNING_SEED) == []
    assert read_configuration(db_session, SettingV3, RECOVERY_SIGNER_IDENTITY) == []
    assert settings_service.SettingsService(db_session).get_secret(SIGNING_SEED) is None
    with pytest.raises(ValueError, match="reserved"):
        settings_service.SettingsService(db_session).set_secret(
            SIGNING_SEED, "replacement"
        )

    old, new = settings_service._fernet, Fernet(Fernet.generate_key())
    rewrapped = new.encrypt(old.decrypt(seed.encode())).decode()
    clone = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(clone)
    factory = sessionmaker(bind=clone)
    try:
        with factory() as db:
            db.add_all(
                [
                    StorageConfigurationClock(
                        slot=1, installation_id=point["installation_id"], revision=1
                    ),
                    SecretV3(
                        key=SIGNING_SEED,
                        encrypted_value=rewrapped,
                        source="installation",
                    ),
                    SettingV3(
                        key=RECOVERY_SIGNER_IDENTITY,
                        value=marker,
                        value_type="json",
                        source="installation",
                    ),
                ]
            )
            db.commit()
            monkeypatch.setattr(settings_service, "_fernet", new)
            assert sign_point(point, signing_key(factory)) == original_signed
            assert (
                recovery_trust(db, generation.org_id, factory=factory) == original_trust
            )

            stored = db.get(SecretV3, SIGNING_SEED)
            replacement = new.encrypt(base64.b64encode(b"x" * 32)).decode()
            stored.encrypted_value = replacement
            db.commit()
            with pytest.raises(RecoveryUnavailable):
                signing_key(factory)
            db.expire_all()
            assert db.get(SecretV3, SIGNING_SEED).encrypted_value == replacement

            db.delete(db.get(SecretV3, SIGNING_SEED))
            db.commit()
            with pytest.raises(RecoveryUnavailable, match="incomplete"):
                signing_key(factory)
            assert db.get(SecretV3, SIGNING_SEED) is None
    finally:
        clone.dispose()


def test_signed_history_refuses_initialization_after_loss_of_both_key_records(
    db_session, session_factory, monkeypatch, accepted_source
):
    from core.installation_config import RECOVERY_SIGNER_IDENTITY
    from core.recovery_signing import SIGNING_SEED
    from models import SecretV3, SettingV3

    generation, _, raw = accepted_source
    proof = accepted_evidence(db_session, generation.org_id, generation.backup_id)
    store = Store(proof, raw)
    monkeypatch.setattr(
        "core.recovery_publication._recorded_target_client",
        lambda *args, **kwargs: store,
    )
    assert publish_one(session_factory, generation.org_id)
    db_session.expire_all()
    published = db_session.get(RecoveryPublication, generation.id)
    assert published.published_at is not None
    previous = published.envelope
    db_session.delete(db_session.get(SecretV3, SIGNING_SEED))
    db_session.delete(db_session.get(SettingV3, RECOVERY_SIGNER_IDENTITY))
    db_session.commit()
    with pytest.raises(RecoveryUnavailable, match="retained records"):
        signing_key(session_factory)
    assert db_session.get(RecoveryPublication, generation.id).envelope == previous
    assert db_session.get(SecretV3, SIGNING_SEED) is None
