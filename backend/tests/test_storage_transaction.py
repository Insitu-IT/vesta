"""Acceptance commits before acknowledgement and does not publish a backup."""

from types import SimpleNamespace
from copy import deepcopy

import pytest

from core.s3_ownership import commit_artifact_plan, StorageOwnershipError
from core.storage_transaction import accept_prepared_receipt
from models import Agent, VM, Backup, S3Publication


def prepare(db):
    agent = Agent(hostname="prepared-source")
    db.add(agent)
    db.flush()
    vm = VM(agent_id=agent.id, name="source")
    db.add(vm)
    db.flush()
    backup = Backup(vm_id=vm.id, status="running")
    db.add(backup)
    db.flush()
    backup.chain_id = backup.id
    config = dict(endpoint="https://store.example", bucket="owned")
    claim = commit_artifact_plan(
        db,
        backup.id,
        "payload",
        config,
        [
            dict(
                volume_id="persisted-volume",
                role="volume_payload",
                plaintext_min=1,
                plaintext_max=1,
                ciphertext_min=1,
                ciphertext_max=1,
            )
        ],
    )
    receipt = dict(
        schema=1,
        reservation_id=claim.id,
        backup_id=backup.id,
        endpoint=claim.endpoint,
        bucket=claim.bucket,
        objects=[
            dict(
                key=claim.expected_plan["artifacts"][0]["key"],
                role="volume_payload",
                volume_id="persisted-volume",
                version_id="v1",
                etag="opaque",
                plaintext_bytes=1,
                ciphertext_bytes=1,
                plaintext_sha256="a" * 64,
                ciphertext_sha256="b" * 64,
            )
        ],
    )
    return backup, agent, claim, receipt


def client_for(receipt, fail=False):
    def head_object(**request):
        if fail:
            raise OSError("store unavailable")
        obj = receipt["objects"][0]
        assert request["Key"] == obj["key"]
        return dict(
            ContentLength=1,
            VersionId="v1",
            ETag="opaque",
            Metadata={
                "vnbui-reservation-id": receipt["reservation_id"],
                "vnbui-backup-id": receipt["backup_id"],
                "vnbui-plaintext-sha256": obj["plaintext_sha256"],
                "vnbui-ciphertext-sha256": obj["ciphertext_sha256"],
                "vnbui-plaintext-bytes": "1",
                "vnbui-ciphertext-bytes": "1",
            },
        )

    return SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=receipt["endpoint"]), head_object=head_object
    )


def test_acceptance_survives_restart_without_publication(db_session, session_factory):
    backup, agent, claim, receipt = prepare(db_session)
    backup_id, agent_id, claim_id = backup.id, agent.id, claim.id
    result = accept_prepared_receipt(
        db_session, backup_id, agent_id, receipt, client_for(receipt)
    )
    assert result["accepted"]
    assert result["verification"]["scrub_required"]
    with session_factory() as restarted:
        persisted = restarted.get(S3Publication, claim_id)
        assert persisted.prepared_receipt == result["verification"]
        assert persisted.state == "reserved"
        assert restarted.get(Backup, backup_id).status == "running"
        assert (
            accept_prepared_receipt(
                restarted, backup_id, agent_id, receipt, client_for(receipt, fail=True)
            )
            == result
        )
        changed = deepcopy(receipt)
        changed["objects"][0]["etag"] = "replacement"
        with pytest.raises(StorageOwnershipError, match="conflicts"):
            accept_prepared_receipt(
                restarted, backup_id, agent_id, changed, client_for(changed)
            )
        assert persisted.prepared_receipt == result["verification"]


def test_wrong_agent_never_changes_ownership(db_session):
    backup, agent, claim, receipt = prepare(db_session)
    with pytest.raises(StorageOwnershipError, match="does not own"):
        accept_prepared_receipt(
            db_session, backup.id, "other-agent", receipt, client_for(receipt)
        )
    assert claim.state == "reserved" and claim.prepared_receipt is None


def test_uncommitted_input_cannot_be_accepted(db_session):
    backup, agent, claim, receipt = prepare(db_session)
    backup_id, agent_id = backup.id, agent.id
    backup.status = "uploading"
    with pytest.raises(StorageOwnershipError, match="clean transaction"):
        accept_prepared_receipt(
            db_session, backup_id, agent_id, receipt, client_for(receipt)
        )
    assert claim.prepared_receipt is None


def test_changed_target_never_constructs_client(db_session, monkeypatch):
    from core.settings_service import SettingsService
    import boto3

    backup, agent, claim, receipt = prepare(db_session)
    monkeypatch.setattr(
        SettingsService,
        "get_s3_config",
        lambda self: dict(endpoint="https://replacement.example", bucket="owned"),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Changed target must not be contacted")

    monkeypatch.setattr(boto3, "client", forbidden)
    with pytest.raises(StorageOwnershipError, match="credentials are unavailable"):
        accept_prepared_receipt(db_session, backup.id, agent.id, receipt)
    assert claim.state == "cleanup_required"


def test_commit_failure_never_acknowledges(db_session, session_factory, monkeypatch):
    backup, agent, claim, receipt = prepare(db_session)
    claim_id = claim.id

    def unavailable():
        raise RuntimeError("disposable commit refusal")

    monkeypatch.setattr(db_session, "commit", unavailable)
    with pytest.raises(RuntimeError, match="commit refusal"):
        accept_prepared_receipt(
            db_session, backup.id, agent.id, receipt, client_for(receipt)
        )
    db_session.rollback()
    with session_factory() as restarted:
        assert restarted.get(S3Publication, claim_id).prepared_receipt is None


@pytest.mark.parametrize("fault", ["store", "receipt"])
def test_refusal_durably_retains_exact_cleanup_authority(
    db_session, session_factory, fault
):
    backup, agent, claim, receipt = prepare(db_session)
    claim_id, key = claim.id, claim.object_key
    if fault == "receipt":
        receipt["objects"] = []
    with pytest.raises((StorageOwnershipError, OSError)):
        accept_prepared_receipt(
            db_session,
            backup.id,
            agent.id,
            receipt,
            client_for(receipt, fail=fault == "store"),
        )
    with session_factory() as restarted:
        retained = restarted.get(S3Publication, claim_id)
        assert retained.state == "cleanup_required"
        assert retained.object_key == key
        assert retained.prepared_receipt is None
