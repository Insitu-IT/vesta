"""Manual admission/hold evidence only; no affirmative upload claim."""

from types import SimpleNamespace
from unittest.mock import Mock
import asyncio

import pytest

from core.upload_retry import record_retry_hold, retry_boundary
from models import Agent, Backup, Organization, S3Publication, User, VM


@pytest.mark.parametrize(
    "state,claim,reason",
    [
        ("cancelled", None, "terminal_lifecycle"),
        ("completed", None, "committed_upload_plan_required"),
        ("upload_failed", None, "committed_upload_plan_required"),
        (
            "completed",
            {"expected_plan": {"schema": 2}},
            "committed_upload_plan_required",
        ),
        (
            "completed",
            {"expected_plan": {"schema": 3}},
            "first_upload_transaction_handoff_required",
        ),
        (
            "upload_failed",
            {"dispatch_token": "original"},
            "producer_reconciliation_required",
        ),
        (
            "upload_failed",
            {"provider_control": {"phase": "uncertain"}},
            "producer_reconciliation_required",
        ),
        (
            "completed",
            {"prepared_receipt": {"accepted": True}},
            "producer_reconciliation_required",
        ),
    ],
)
def test_retry_does_not_confuse_first_upload_and_uncertain_resend(state, claim, reason):
    if claim is not None:
        claim = SimpleNamespace(
            **dict(
                dict(
                    expected_plan=None,
                    dispatch_token=None,
                    provider_control=None,
                    prepared_receipt=None,
                ),
                **claim
            )
        )
    assert retry_boundary(SimpleNamespace(status=state), claim) == reason


@pytest.mark.parametrize("failure", [None, "flush", "commit"])
def test_retry_audit_is_separate_from_initiator_and_atomic(failure):
    caller = SimpleNamespace(id="caller", is_active=True, role="operator")
    original = SimpleNamespace(id="original", is_active=True, role="admin")
    backup = SimpleNamespace(
        id="backup", vm_id="vm", initiating_user_id="original", status="upload_failed"
    )
    rows = {
        Organization: SimpleNamespace(enabled=True),
        Backup: backup,
        VM: SimpleNamespace(agent_id="agent", inventory_present=True),
        Agent: SimpleNamespace(status="online"),
        S3Publication: None,
    }
    db = Mock()

    def query(model):
        q = Mock()

        def filter_by(**fields):
            row = (
                (caller if fields["id"] == "caller" else original)
                if model is User
                else rows[model]
            )
            q.populate_existing.return_value.with_for_update.return_value.one_or_none.return_value = (
                row
            )
            return q

        q.filter_by.side_effect = filter_by
        return q

    db.query.side_effect = query
    if failure:
        getattr(db, failure).side_effect = RuntimeError("injected")
        with pytest.raises(RuntimeError):
            record_retry_hold(db, "backup", "org", "caller")
        db.rollback.assert_called_once()
    else:
        assert (
            record_retry_hold(db, "backup", "org", "caller")
            == "committed_upload_plan_required"
        )
        db.commit.assert_called_once()
        db.rollback.assert_not_called()
    audit = db.add.call_args.args[0]
    assert audit.user_id == "caller"
    assert audit.details["initiating_user_id"] == "original"
    assert audit.details["retry_caller_id"] == "caller"
    assert backup.initiating_user_id == "original" and backup.status == "upload_failed"


@pytest.mark.parametrize("failure", [None, "commit"])
def test_local_handoff_commit_precedes_worker(failure):
    from core.backup_executor import BackupExecutor
    from unittest.mock import AsyncMock

    events = []
    db = Mock()

    def commit():
        events.append("commit")
        if failure:
            raise RuntimeError("commit uncertain")

    db.commit.side_effect = commit
    executor = BackupExecutor()

    async def upload(backup_id, **kw):
        events.append("worker")
        assert backup_id == "backup"
        assert kw == dict(
            org_id="org", initiating_user_id="original", origin="first_upload"
        )
        return {"status": "held"}

    executor.execute_upload = AsyncMock(side_effect=upload)
    backup = SimpleNamespace(id="backup", org_id="org", initiating_user_id="original")
    if failure:
        with pytest.raises(RuntimeError):
            asyncio.run(executor._handoff_local_upload(db, backup))
        executor.execute_upload.assert_not_called()
        assert events == ["commit"]
    else:
        assert asyncio.run(executor._handoff_local_upload(db, backup)) == {
            "status": "held"
        }
        assert events == ["commit", "worker"]


def test_local_upload_routing_hint_never_resolves_secrets(monkeypatch):
    from core.backup_executor import BackupExecutor
    from core.settings_service import SettingsService

    forbidden = Mock(side_effect=AssertionError("secret resolution"))
    monkeypatch.setattr(SettingsService, "get_s3_config", forbidden)
    monkeypatch.setattr(
        SettingsService,
        "get_many",
        lambda self, keys: {"storage.type": "s3", "storage.s3.bucket": "configured"},
    )
    assert BackupExecutor()._is_s3_configured(Mock()) is True
    forbidden.assert_not_called()


def test_periodic_retry_closes_session_before_readmission_without_bookkeeping(
    monkeypatch,
):
    from core.backup_queue_processor import BackupQueueProcessor
    from core import backup_executor as module
    from unittest.mock import AsyncMock

    backup = SimpleNamespace(
        id="backup",
        org_id="org",
        initiating_user_id="original",
        tags={"upload_attempts": 4, "upload_error": "retained"},
    )
    db = Mock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = (
        backup
    )

    async def upload(backup_id, **kw):
        db.close.assert_called_once()
        db.commit.assert_not_called()
        assert backup_id == "backup"
        assert kw == dict(
            org_id="org", initiating_user_id="original", origin="automatic_retry"
        )
        return {"status": "held"}

    worker = AsyncMock(side_effect=upload)
    monkeypatch.setattr(module.backup_executor, "execute_upload", worker)
    processor = BackupQueueProcessor(lambda: db, None)
    assert asyncio.run(processor._retry_tenant_upload()) is True
    worker.assert_awaited_once()
    assert backup.tags == {"upload_attempts": 4, "upload_error": "retained"}


def test_stale_upload_retains_uncertainty_instead_of_retry_eligibility():
    from services.cleanup_service import CleanupService

    backup = SimpleNamespace(
        id="backup", status="uploading", tags={"upload_error": "original"}
    )
    db = Mock()
    db.query.return_value.filter.return_value.all.side_effect = [[backup], [], []]
    result = asyncio.run(CleanupService().cleanup_stale_operations(db))
    assert result["backups_failed"] == 0
    assert backup.status == "uploading"
    assert backup.tags == {"upload_error": "original"}


@pytest.mark.parametrize("status", ["pending", "running"])
def test_creation_age_cannot_close_backup_or_restore(status):
    from services.cleanup_service import CleanupService

    backup = SimpleNamespace(id="backup", status=status, tags={"original": True})
    restore = SimpleNamespace(id="restore", status=status, error_message="original")
    db = Mock()
    db.query.return_value.filter.return_value.all.side_effect = [
        [backup],
        [restore],
        [],
    ]
    result = asyncio.run(CleanupService().cleanup_stale_operations(db))
    assert result["backups_failed"] == result["restores_failed"] == 0
    assert backup.status == restore.status == status
    assert backup.tags == {"original": True} and restore.error_message == "original"


@pytest.mark.parametrize("origin", ["first_upload", "automatic_retry"])
def test_delayed_admission_custody_wins_over_origin(origin):
    from core.upload_retry import inspect_upload_handoff
    from uuid import uuid4

    org, actor, backup_id = (str(uuid4()) for _ in range(3))
    backup = SimpleNamespace(
        id=backup_id,
        authority_kind="human",
        initiating_user_id=actor,
        vm_id="vm",
        status="completed",
    )
    rows = {
        Organization: SimpleNamespace(enabled=True),
        User: SimpleNamespace(is_active=True, role="operator"),
        Backup: backup,
        VM: SimpleNamespace(inventory_present=True, agent_id="agent"),
        Agent: SimpleNamespace(status="online"),
        S3Publication: SimpleNamespace(
            dispatch_token="original", provider_control=None, prepared_receipt=None
        ),
    }
    db = Mock()

    def query(model):
        q = Mock()
        locked = (
            q.filter_by.return_value.populate_existing.return_value.with_for_update.return_value
        )
        locked.one_or_none.return_value = rows[model]
        return q

    db.query.side_effect = query
    assert (
        inspect_upload_handoff(db, backup_id, org, actor, origin)
        == "producer_reconciliation_required"
    )
    db.commit.assert_not_called()
    db.add.assert_not_called()


def test_worker_cancellation_retains_evidence_and_releases_session(monkeypatch):
    from core import backup_executor as module
    from core import upload_retry
    from uuid import uuid4

    db = Mock()
    monkeypatch.setattr(module, "SessionLocal", lambda: db)

    def cancel(*args):
        raise asyncio.CancelledError()

    monkeypatch.setattr(upload_retry, "inspect_upload_handoff", cancel)
    executor = module.BackupExecutor()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            executor.execute_upload(
                str(uuid4()),
                org_id=str(uuid4()),
                initiating_user_id=str(uuid4()),
                origin="first_upload",
            )
        )
    db.rollback.assert_called_once()
    db.close.assert_called_once()
    db.commit.assert_not_called()
    assert executor.dispatch_lifetime.tasks == {}
