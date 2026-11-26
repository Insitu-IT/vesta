"""Ownership reservation controls; no storage mutation is performed here."""

import pytest
import uuid

from core.s3_ownership import (
    StorageOwnershipError,
    require_publication,
    reserve_publication,
    storage_identity,
    commit_artifact_plan,
)
from models import Agent, VM, Backup


def _completed_backup(db):
    agent = Agent(hostname="storage-owner-" + uuid.uuid4().hex)
    db.add(agent)
    db.flush()
    vm = VM(agent_id=agent.id, name="same-name")
    db.add(vm)
    db.flush()
    backup = Backup(vm_id=vm.id, status="completed", tags={})
    db.add(backup)
    db.commit()
    return backup


CONFIG = {
    "endpoint": "https://storage.example",
    "bucket": "backup",
    "prefix": "archive",
}


def test_artifact_plan_commits_and_cannot_change(db_session, session_factory):
    backup = _pending(db_session)
    artifacts = [
        dict(
            volume_id="persisted-disk-uid",
            role="volume_payload",
            plaintext_min=0,
            plaintext_max=100,
            ciphertext_min=0,
            ciphertext_max=200,
        )
    ]
    claim = commit_artifact_plan(db_session, backup.id, "payload", CONFIG, artifacts)
    backup_id, original = backup.id, claim.expected_plan
    with session_factory() as restarted:
        loaded = require_publication(restarted, backup_id, "payload", CONFIG)
        assert loaded.expected_plan == original
        with pytest.raises(StorageOwnershipError, match="differs"):
            commit_artifact_plan(
                restarted,
                backup_id,
                "payload",
                CONFIG,
                [dict(artifacts[0], plaintext_max=101)],
            )


def _pending(db):
    backup = _completed_backup(db)
    backup.status = "pending"
    backup.chain_id = backup.id
    db.commit()
    return backup


def test_reservation_survives_session_and_name_prefix_changes(
    db_session, session_factory
):
    backup = _pending(db_session)
    claim = reserve_publication(db_session, backup.id, "payload", CONFIG)
    key, claim_id, backup_id = claim.object_key, claim.id, backup.id
    assert key.endswith("/payload/")
    assert backup.vm.name not in key
    db_session.commit()
    backup.vm.name = "renamed"
    db_session.commit()
    with session_factory() as restarted:
        claim = reserve_publication(
            restarted, backup_id, "payload", dict(CONFIG, prefix="changed")
        )
        assert (claim.id, claim.object_key) == (claim_id, key)
        assert claim.state == "reserved"


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        dict(CONFIG, bucket="other"),
        dict(CONFIG, endpoint="http://storage.example"),
    ],
)
def test_changed_or_missing_target_never_rebinds_claim(db_session, config):
    backup = _pending(db_session)
    claim = reserve_publication(db_session, backup.id, "payload", CONFIG)
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        require_publication(db_session, backup.id, "payload", config)
    assert claim.endpoint == CONFIG["endpoint"]


def test_same_name_and_artifact_kinds_have_disjoint_keys(db_session):
    first, second = _pending(db_session), _pending(db_session)
    second.vm.name = first.vm.name
    claims = [
        reserve_publication(db_session, b.id, kind, CONFIG)
        for b in (first, second)
        for kind in ("payload", "chain_manifest")
    ]
    assert len({c.object_key for c in claims}) == 4
    for payload in (c for c in claims if c.kind == "payload"):
        assert all(
            not c.object_key.startswith(payload.object_key)
            for c in claims
            if c.id != payload.id
        )


def test_missing_and_historical_ownership_are_refusals(db_session):
    backup = _completed_backup(db_session)
    backup.storage_path = f"s3://backup/archive/{backup.id}"
    db_session.commit()
    with pytest.raises(StorageOwnershipError, match="No durable"):
        require_publication(db_session, backup.id, "payload", CONFIG)
    with pytest.raises(StorageOwnershipError, match="no automatic adoption"):
        reserve_publication(db_session, backup.id, "payload", CONFIG)
    with pytest.raises(StorageOwnershipError, match="not visible"):
        require_publication(db_session, "absent", "payload", CONFIG)


def test_child_cannot_claim_root_manifest(db_session):
    root = _pending(db_session)
    child = Backup(vm_id=root.vm_id, chain_id=root.id, status="pending", tags={})
    db_session.add(child)
    db_session.flush()
    with pytest.raises(StorageOwnershipError, match="chain root"):
        reserve_publication(db_session, child.id, "chain_manifest", CONFIG)


@pytest.mark.parametrize("state", ["cleanup_required", "deleted"])
def test_compensation_and_tombstone_prevent_republication(db_session, state):
    backup = _pending(db_session)
    claim = reserve_publication(db_session, backup.id, "payload", CONFIG)
    claim.state = state
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        reserve_publication(db_session, backup.id, "payload", CONFIG)


@pytest.mark.parametrize(
    "endpoint",
    [
        "storage.example",
        "ftp://storage.example",
        "https://u:p@storage.example",
        "https://storage.example/path",
        "https://storage.example?q=x",
    ],
)
def test_endpoint_identity_never_contains_credentials_or_guessed_tls(endpoint):
    with pytest.raises(StorageOwnershipError):
        storage_identity(dict(CONFIG, endpoint=endpoint))


def test_origin_canonicalization():
    assert storage_identity(dict(CONFIG, endpoint="https://STORAGE.example:443/")) == (
        CONFIG["endpoint"],
        CONFIG["bucket"],
    )


@pytest.mark.parametrize("published", [False, True])
def test_legacy_chain_requires_full_before_child_reservation(
    db_session, published, monkeypatch
):
    from core.backup_service import BackupService

    monkeypatch.setattr(
        "core.settings_service.SettingsService.get",
        lambda _, key: {
            "storage.s3.endpoint": CONFIG["endpoint"],
            "storage.s3.bucket": CONFIG["bucket"],
        }[key],
    )

    def no_credentials(*args, **kwargs):
        pytest.fail(
            "Chain selection must not resolve credentials before a committed plan"
        )

    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_secret", no_credentials
    )

    root = _pending(db_session)
    if published:
        for kind in ("payload", "chain_manifest"):
            claim = reserve_publication(db_session, root.id, kind, CONFIG)
            claim.state = "published"
    root.status = "completed"
    root.storage_path = f"s3://backup/legacy/{root.id}"
    db_session.commit()
    child = Backup(
        vm_id=root.vm_id, backup_type="incremental", status="pending", tags={}
    )
    db_session.add(child)
    db_session.flush()
    BackupService(db_session)._resolve_chain(child, root.vm_id)
    if published:
        assert child.backup_type == "incremental"
        assert child.parent_backup_id == root.id
    else:
        assert child.backup_type == "full"
        assert child.chain_id == child.id
        assert child.parent_backup_id is None
        assert (
            child.tags["full_required_reason"]
            == "legacy_uncommitted_or_split_s3_lineage"
        )
    claim = reserve_publication(db_session, child.id, "payload", CONFIG)
    assert claim.object_key.startswith("vnbui-owned/v1/")
    assert root.storage_path == f"s3://backup/legacy/{root.id}"
    assert root.status == "completed"


def test_direct_child_reservation_cannot_bypass_legacy_guard(db_session):
    root = _pending(db_session)
    root.status = "completed"
    child = Backup(
        vm_id=root.vm_id,
        chain_id=root.id,
        parent_backup_id=root.id,
        backup_type="incremental",
        status="pending",
        tags={},
    )
    db_session.add(child)
    db_session.commit()
    with pytest.raises(StorageOwnershipError, match="fresh full"):
        reserve_publication(db_session, child.id, "payload", CONFIG)


@pytest.mark.parametrize(
    "drift",
    ["manifest_bucket", "member_endpoint", "current_bucket", "current_endpoint"],
)
def test_chain_target_drift_promotes_before_reservation(db_session, monkeypatch, drift):
    from core.backup_service import BackupService
    from core.s3_ownership import owned_chain_target

    root = _pending(db_session)
    payload = reserve_publication(db_session, root.id, "payload", CONFIG)
    payload.state = "published"
    if drift == "manifest_bucket":
        from models import S3Publication

        # Construct the historical split directly. Current reservation must
        # refuse creating this inconsistent root in the first place.
        manifest = S3Publication(
            org_id=root.org_id,
            backup_id=root.id,
            kind="chain_manifest",
            endpoint=CONFIG["endpoint"],
            bucket="other",
            object_key=payload.object_key.removesuffix("payload/") + "chain.json",
            state="published",
        )
        db_session.add(manifest)
    else:
        manifest = reserve_publication(db_session, root.id, "chain_manifest", CONFIG)
        manifest.state = "published"
    root.status = "completed"
    root.storage_path = f"s3://backup/{payload.object_key}"
    db_session.commit()
    if drift == "member_endpoint":
        # A constructed historical split, not mutation of an immutable locator.
        from models import S3Publication

        member = Backup(
            vm_id=root.vm_id,
            chain_id=root.id,
            parent_backup_id=root.id,
            status="completed",
            storage_path="s3://backup/historical",
            tags={},
        )
        db_session.add(member)
        db_session.flush()
        db_session.add(
            S3Publication(
                org_id=root.org_id,
                backup_id=member.id,
                kind="payload",
                endpoint="https://other.example",
                bucket=CONFIG["bucket"],
                object_key="historical",
                state="published",
            )
        )
        db_session.commit()
    proposed = dict(CONFIG)
    if drift == "current_bucket":
        proposed["bucket"] = "changed"
    if drift == "current_endpoint":
        proposed["endpoint"] = "https://changed.example"
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get",
        lambda _, key: {
            "storage.s3.endpoint": proposed["endpoint"],
            "storage.s3.bucket": proposed["bucket"],
        }[key],
    )
    child = Backup(
        vm_id=root.vm_id, backup_type="incremental", status="pending", tags={}
    )
    db_session.add(child)
    db_session.flush()
    BackupService(db_session)._resolve_chain(child, root.vm_id)
    assert child.backup_type == "full"
    assert child.chain_id == child.id and child.parent_backup_id is None
    expected = (
        "s3_target_changed_or_unavailable"
        if drift.startswith("current")
        else "legacy_uncommitted_or_split_s3_lineage"
    )
    assert child.tags["full_required_reason"] == expected
    claim = reserve_publication(db_session, child.id, "payload", proposed)
    assert (claim.endpoint, claim.bucket) == storage_identity(proposed)
    assert root.status == "completed"
    assert owned_chain_target(db_session, root) == (
        storage_identity(CONFIG) if drift.startswith("current") else None
    )


def test_direct_child_target_change_is_refused(db_session):
    root = _pending(db_session)
    for kind in ("payload", "chain_manifest"):
        reserve_publication(db_session, root.id, kind, CONFIG).state = "published"
    root.status = "completed"
    child = Backup(
        vm_id=root.vm_id,
        chain_id=root.id,
        parent_backup_id=root.id,
        backup_type="incremental",
        status="pending",
        tags={},
    )
    db_session.add(child)
    db_session.commit()
    with pytest.raises(StorageOwnershipError, match="changed-target"):
        reserve_publication(
            db_session, child.id, "payload", dict(CONFIG, bucket="changed")
        )


def test_root_manifest_cannot_reserve_a_different_target(db_session):
    root = _pending(db_session)
    reserve_publication(db_session, root.id, "payload", CONFIG)
    with pytest.raises(StorageOwnershipError, match="differs"):
        reserve_publication(
            db_session, root.id, "chain_manifest", dict(CONFIG, bucket="changed")
        )
