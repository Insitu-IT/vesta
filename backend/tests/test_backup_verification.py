"""Scrub admission/result controls; no provider I/O or SQL-trigger proof implied."""

from copy import deepcopy
import json
import uuid

import pytest

from backend.tests.test_kubevirt_restore import fixture as kubevirt_fixture
from backend.tests.test_native_restore import fixture as native_fixture
from core import backup_verification as scrub
from core.s3_ownership import StorageOwnershipError
from core.storage_wire import plan_digest
from core.tenant_context import PlatformContext
from models import (
    BackupVerification,
    Organization,
    OrganizationDefault,
    S3Publication,
    SettingV3,
    StorageLineageGeneration,
    VM,
)


def fixture(db, provider="kubevirt"):
    backup, actor, _ = (kubevirt_fixture if provider == "kubevirt" else native_fixture)(
        db
    )
    # The unit fixture models the supported one-org installation assignment.
    db.get(OrganizationDefault, "oss").org_id = actor.org_id
    db.add(
        SettingV3(
            key="backup.capacity_admission",
            value=scrub.canonical(
                dict(schema=1, revision=1, limit=2, maintenance=False)
            ).decode(),
            value_type="json",
            source="ui",
        )
    )
    claim = db.query(S3Publication).filter_by(backup_id=backup.id, kind="payload").one()
    request = deepcopy(claim.expected_plan["transaction"])
    request["plan"]["target"]["region"] = "us-east-1"
    request["plan_sha256"] = plan_digest(request["plan"])
    claim.expected_plan = dict(schema=3, transaction=request)
    generation = db.query(StorageLineageGeneration).filter_by(backup_id=backup.id).one()
    generation.accepted_request = deepcopy(request)
    if provider == "libvirt":
        publication = (
            db.query(S3Publication)
            .filter_by(backup_id=backup.id, kind="chain_manifest")
            .one()
        )
        manifest = json.loads(publication.expected_plan["manifest_canonical"])
        manifest["members"][-1]["request"] = deepcopy(request)
        publication.expected_plan = dict(
            publication.expected_plan,
            manifest_canonical=scrub.canonical(manifest).decode(),
            manifest_sha256=scrub.digest(manifest),
        )
    db.commit()
    row = scrub.enroll(
        db,
        backup_id=backup.id,
        org_id=actor.org_id,
        actor_id=actor.id,
        verification_id=str(uuid.uuid4()),
    )
    db.commit()
    return backup, actor, row


def response(row, status="passed"):
    plan, _ = scrub.load_plan(row)
    messages = {
        "passed": "artifact_bytes_verified",
        "failed": "artifact_verification_failed",
        "held": "readmission_required",
        "running": "reading_exact_artifacts",
        "pending": "awaiting_worker",
    }
    return dict(
        schema=scrub.PROGRESS_SCHEMA,
        verification_id=row.id,
        org_id=row.org_id,
        agent_id=row.verification_agent_id,
        plan_sha256=row.verification_plan_sha256,
        worker_id=str(uuid.uuid4()),
        status=status,
        message=messages[status],
        result=scrub.expected_result(plan) if status == "passed" else None,
    )


@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
def test_enrollment_is_original_nonsecret_and_idempotent(db_session, provider):
    backup, actor, row = fixture(db_session, provider)
    plan, authority = scrub.load_plan(row)
    assert plan["provider"] == provider
    assert authority["actor_id"] == actor.id and authority["org_id"] == actor.org_id
    assert plan["bundle"]["members"][-1]["request"]["backup_id"] == backup.id
    assert row.verification_result is None and row.status == "pending"
    assert not any(k in plan for k in ("keys", "s3", "access_key", "secret_key"))
    again = scrub.enroll(
        db_session,
        backup_id=backup.id,
        org_id=actor.org_id,
        actor_id=actor.id,
        verification_id=row.id,
    )
    assert again.id == row.id and db_session.query(BackupVerification).count() == 1
    assert scrub.readmit(db_session, row) == plan


@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
def test_full_result_binds_worker_before_completion_and_replays(db_session, provider):
    _, _, row = fixture(db_session, provider)
    value = response(row)
    assert scrub.apply_progress(row, value) is False
    assert row.status == "running" and row.verification_result is None
    assert row.verification_worker_id == value["worker_id"]
    db_session.commit()
    assert scrub.apply_progress(row, value) is True
    db_session.commit()
    assert (
        row.status == "passed"
        and row.verification_result == value["result"]
        and row.completed_at
    )
    assert scrub.apply_progress(row, value) is True
    assert not db_session.dirty
    late = response(row, "held")
    late["worker_id"] = value["worker_id"]
    with pytest.raises(StorageOwnershipError):
        scrub.apply_progress(row, late)


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "id",
        "org",
        "agent",
        "plan",
        "worker",
        "result-org",
        "receipt",
        "missing",
        "extra",
        "bool-count",
        "float-count",
        "nan",
        "pending-result",
        "unknown",
    ],
)
def test_bad_progress_never_binds_or_publishes_result(db_session, fault):
    _, _, row = fixture(db_session)
    value = response(row)
    if fault == "schema":
        value["schema"] = "other"
    elif fault == "id":
        value["verification_id"] = str(uuid.uuid4())
    elif fault == "org":
        value["org_id"] = str(uuid.uuid4())
    elif fault == "agent":
        value["agent_id"] = str(uuid.uuid4())
    elif fault == "plan":
        value["plan_sha256"] = "b" * 64
    elif fault == "worker":
        value["worker_id"] = "unknown"
    elif fault == "result-org":
        value["result"]["org_id"] = str(uuid.uuid4())
    elif fault == "receipt":
        value["result"]["members"][0]["receipt_sha256"] = "b" * 64
    elif fault == "missing":
        value["result"]["members"] = []
    elif fault == "extra":
        value["result"]["members"].append(deepcopy(value["result"]["members"][0]))
    elif fault == "bool-count":
        value["result"]["members"][0]["objects"] = True
    elif fault == "float-count":
        value["result"]["members"][0]["objects"] = float(
            value["result"]["members"][0]["objects"]
        )
    elif fault == "nan":
        value["result"]["members"][0]["objects"] = float("nan")
    elif fault == "pending-result":
        value["status"], value["message"] = "pending", "awaiting_worker"
    elif fault == "unknown":
        value["secret"] = "must-not-be-recorded"
    with pytest.raises(StorageOwnershipError):
        scrub.apply_progress(row, value)
    assert (
        row.status == "pending"
        and row.verification_result is None
        and row.verification_worker_id is None
    )
    assert not db_session.dirty


def test_worker_identity_is_never_replaced_and_cancel_cannot_pass(db_session):
    _, _, row = fixture(db_session)
    value = response(row, "pending")
    scrub.apply_progress(row, value)
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        scrub.apply_progress(row, response(row))
    value["status"], value["message"], value["result"] = (
        "passed",
        "artifact_bytes_verified",
        scrub.expected_result(scrub.load_plan(row)[0]),
    )
    row.verification_cancel_requested = True
    assert scrub.apply_progress(row, value) is True
    assert row.status == "cancelled" and row.verification_result is None
    assert row.completed_at is not None


def test_second_unfinished_id_for_same_backup_is_refused(db_session):
    backup, actor, _ = fixture(db_session)
    with pytest.raises(StorageOwnershipError):
        scrub.enroll(
            db_session,
            backup_id=backup.id,
            org_id=actor.org_id,
            actor_id=actor.id,
            verification_id=str(uuid.uuid4()),
        )
    assert db_session.query(BackupVerification).count() == 1


def test_agent_unfinished_queue_budget_is_enforced(db_session, monkeypatch):
    backup, actor, _ = fixture(db_session)
    # Isolate the agent-wide budget from the independently tested same-backup
    # check. Lowering the configured constant exercises the actual query.
    row = db_session.query(BackupVerification).one()
    row.backup_id = str(uuid.uuid4())
    db_session.commit()
    monkeypatch.setattr(scrub, "MAX_UNFINISHED_PER_AGENT", 1)
    with pytest.raises(StorageOwnershipError):
        scrub.enroll(
            db_session,
            backup_id=backup.id,
            org_id=actor.org_id,
            actor_id=actor.id,
            verification_id=str(uuid.uuid4()),
        )


@pytest.mark.parametrize("state", ["pending", "running", "held", "failed", "passed"])
def test_cancel_requires_exact_quiescent_worker(db_session, state):
    _, _, row = fixture(db_session)
    row.verification_cancel_requested = True
    value = response(row, state)
    terminal = state in {"held", "failed", "passed"}
    assert scrub.apply_progress(row, value) is terminal
    assert row.status == ("cancelled" if terminal else "held")
    assert row.verification_result is None
    assert (row.completed_at is not None) is terminal
    if terminal:
        assert scrub.apply_progress(row, value) is True
        assert row.verification_result is None


def test_cancel_pending_fence_does_not_complete_cancellation(db_session):
    _, _, row = fixture(db_session)
    row.verification_cancel_requested = True
    value = response(row, "running")
    value["message"] = "cancellation_pending"
    assert scrub.apply_progress(row, value) is False
    assert row.status == "held" and row.completed_at is None
    assert row.verification_result is None


@pytest.mark.parametrize(
    "fault",
    [
        "inactive",
        "role",
        "org-disabled",
        "epoch",
        "assignment",
        "agent",
        "payload",
        "cancel",
        "platform",
        "maintenance",
        "missing-policy",
    ],
)
def test_revocation_or_changed_custody_blocks_readmission(db_session, fault):
    backup, actor, row = fixture(db_session)
    if fault == "inactive":
        actor.is_active = False
    elif fault == "role":
        actor.role = "viewer"
    elif fault == "org-disabled":
        db_session.get(Organization, actor.org_id).enabled = False
    elif fault == "epoch":
        db_session.get(Organization, actor.org_id).scheduler_epoch += 1
    elif fault == "assignment":
        db_session.get(OrganizationDefault, "oss").org_id = str(uuid.uuid4())
    elif fault == "agent":
        db_session.get(VM, backup.vm_id).agent_id = str(uuid.uuid4())
    elif fault == "payload":
        db_session.query(S3Publication).filter_by(
            backup_id=backup.id, kind="payload"
        ).one().state = "deleted"
    elif fault == "cancel":
        row.verification_cancel_requested = True
    elif fault == "maintenance":
        db_session.get(SettingV3, "backup.capacity_admission").value = scrub.canonical(
            dict(schema=1, revision=2, limit=2, maintenance=True)
        ).decode()
    elif fault == "missing-policy":
        db_session.delete(db_session.get(SettingV3, "backup.capacity_admission"))
    db_session.commit()
    if fault == "platform":
        with PlatformContext(), pytest.raises(StorageOwnershipError):
            scrub.readmit(db_session, row)
    else:
        with pytest.raises(StorageOwnershipError):
            scrub.readmit(db_session, row)


@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
def test_credentials_are_delivered_only_after_readmission_and_not_saved(
    db_session, monkeypatch, provider
):
    _, _, row = fixture(db_session, provider)
    plan, _ = scrub.load_plan(row)
    cfg = dict(
        plan["bundle"]["members"][0]["request"]["plan"]["target"],
        access_key="read-only",
        secret_key="private-read-key",
        session_token="private-session",
    )
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config", lambda self: cfg
    )
    monkeypatch.setattr(
        "core.storage_attempt_key.unwrap_retained_attempt_key", lambda *args: None
    )
    request = scrub.hydrate_request(db_session, row)
    assert request["s3"]["secret_key"] == "private-read-key" and request["keys"] == {}
    assert "private-read-key" not in row.verification_plan_canonical
    assert "private-session" not in row.verification_plan_canonical
    assert request["plan"] == plan
    request["plan"]["bundle"]["members"].clear()
    assert scrub.load_plan(row)[0] == plan
    cfg["bucket"] = "foreign"
    with pytest.raises(StorageOwnershipError):
        scrub.hydrate_request(db_session, row)
