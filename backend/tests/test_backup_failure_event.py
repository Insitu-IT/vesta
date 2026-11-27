"""Durable, SMTP-independent backup-failure SystemEvent (#38).

notify_backup_failure must ALWAYS record a durable `backup_failed` SystemEvent so a
backup failure is visible in-product (activity feed / dashboard) even when email is
off or unconfigured — the silent-failure gap that let Mesh's 66 failures go unnoticed
for ~110 days. The event is written via its own DB session, so it lands regardless of
the caller's transaction state or SMTP configuration.
"""

import asyncio
import threading
import uuid
from types import SimpleNamespace

import pytest

from models import Backup, NotificationLog, SystemEvent


def _make_failed_backup(db):
    backup = Backup(
        id=str(uuid.uuid4()),
        vm_id="fixture-vm-id",
        status="failed",
        backup_type="full",
        tags={},
        storage_path="file:///var/lib/vnbui/backups/x",
    )
    db.add(backup)
    db.commit()
    db.refresh(backup)
    return backup


@pytest.mark.asyncio
async def test_backup_failure_records_durable_event_when_email_disabled(
    session_factory, monkeypatch
):
    """Email off (the Mesh case) → failure must still land a durable backup_failed event."""
    import core.notifications as notifications

    # _record_backup_failure_event opens its own SessionLocal() — bind it to the test DB.
    monkeypatch.setattr(notifications, "SessionLocal", session_factory)

    db = session_factory()
    backup = _make_failed_backup(db)

    # No email settings configured → send_backup_notification no-ops; event must persist.
    await notifications.notify_backup_failure(
        backup,
        vm_name="fixture-vm",
        error="Failed to send backup command to agent agent.example.test (http://192.0.2.101:8090)",
        db=db,
    )

    events = (
        db.query(SystemEvent).filter(SystemEvent.event_type == "backup_failed").all()
    )
    assert len(events) == 1, "a durable backup_failed SystemEvent must be recorded"
    ev = events[0]
    assert ev.source == "backup"
    assert ev.resource_type == "backup"
    assert ev.resource_id == backup.id
    assert ev.details["vm_name"] == "fixture-vm"
    assert ev.details["vm_id"] == "fixture-vm-id"
    assert "agent.example.test" in ev.details["error"]
    db.close()


@pytest.mark.asyncio
async def test_backup_failure_records_event_without_caller_db(
    session_factory, monkeypatch
):
    """db=None path (some callers pass none) still records the durable event."""
    import core.notifications as notifications

    monkeypatch.setattr(notifications, "SessionLocal", session_factory)

    setup = session_factory()
    backup = _make_failed_backup(setup)
    setup.close()

    await notifications.notify_backup_failure(
        backup, vm_name="v", error="boom", db=None
    )

    check = session_factory()
    events = (
        check.query(SystemEvent).filter(SystemEvent.event_type == "backup_failed").all()
    )
    assert len(events) == 1
    check.close()


@pytest.mark.asyncio
async def test_stale_sweep_detached_snapshot_records_failure_without_worker_session(
    session_factory, monkeypatch
):
    """The sweep closes its worker session before loop-owned notification."""
    import core.notifications as notifications

    monkeypatch.setattr(notifications, "SessionLocal", session_factory)
    setup = session_factory()
    backup = _make_failed_backup(setup)
    snapshot = SimpleNamespace(
        id=backup.id,
        vm_id=backup.vm_id,
        status=backup.status,
        backup_type=backup.backup_type,
        created_at=backup.created_at,
        tags={"error": "Agent heartbeat stale"},
    )
    setup.close()

    await notifications.notify_stale_backup_failure(
        snapshot, vm_name="disposable-vm", error="Agent heartbeat stale"
    )

    with session_factory() as check:
        event = (
            check.query(SystemEvent)
            .filter(SystemEvent.event_type == "backup_failed")
            .one()
        )
        assert event.resource_id == snapshot.id
        assert event.details["vm_id"] == snapshot.vm_id
        assert event.details["vm_name"] == "disposable-vm"


@pytest.mark.asyncio
async def test_stale_failure_sql_is_off_loop_but_smtp_keeps_owner_loop(
    session_factory, monkeypatch
):
    import core.notifications as notifications

    monkeypatch.setattr(notifications, "SessionLocal", session_factory)
    service = notifications.NotificationService()
    monkeypatch.setattr(notifications, "notification_service", service)
    with session_factory() as setup:
        backup = _make_failed_backup(setup)
        snapshot = SimpleNamespace(
            id=backup.id,
            vm_id=backup.vm_id,
            status="failed",
            backup_type=backup.backup_type,
            created_at=backup.created_at,
            tags={"error": "stale"},
        )

    owner_thread = threading.get_ident()
    owner_loop = asyncio.get_running_loop()
    database_threads = []
    real_log = service._log_notification

    def config(_db):
        database_threads.append(threading.get_ident())
        return {
            "enabled": True,
            "recipients": "ops@example.invalid",
            "server": "smtp.example.invalid",
            "from_email": "vnbui@example.invalid",
        }

    def prefs(_db):
        database_threads.append(threading.get_ident())
        return {"on_failure": True}

    def log(*args, **kwargs):
        database_threads.append(threading.get_ident())
        return real_log(*args, **kwargs)

    async def send(*_args, **_kwargs):
        assert asyncio.get_running_loop() is owner_loop
        return True

    monkeypatch.setattr(service, "_get_smtp_config", config)
    monkeypatch.setattr(service, "_get_notification_prefs", prefs)
    monkeypatch.setattr(service, "_log_notification", log)
    monkeypatch.setattr(service, "_send_email", send)

    await notifications.notify_stale_backup_failure(
        snapshot, vm_name="disposable-vm", error="stale"
    )

    assert len(database_threads) == 3
    assert all(thread != owner_thread for thread in database_threads)
    with session_factory() as check:
        assert (
            check.query(SystemEvent).filter_by(event_type="backup_failed").count() == 1
        )
        log_row = check.query(NotificationLog).one()
        assert log_row.event_type == "backup_failure"
        assert log_row.status == "sent"


@pytest.mark.asyncio
async def test_blocked_stale_notification_settings_do_not_block_api_loop(monkeypatch):
    import core.notifications as notifications

    service = notifications.NotificationService()
    monkeypatch.setattr(notifications, "notification_service", service)
    monkeypatch.setattr(notifications, "_record_backup_failure_event", lambda *a: None)
    monkeypatch.setattr(
        notifications, "_maybe_record_sustained_failure", lambda *a: None
    )
    entered = threading.Event()
    release = threading.Event()
    owner_thread = threading.get_ident()

    def blocked_settings(*_args):
        assert threading.get_ident() != owner_thread
        entered.set()
        assert release.wait(2)
        return None

    monkeypatch.setattr(service, "_prepare_stale_failure_email", blocked_settings)
    task = asyncio.create_task(
        notifications.notify_stale_backup_failure(
            SimpleNamespace(id="backup", vm_id="vm", status="failed"),
            vm_name="vm",
            error="stale",
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        await asyncio.wait_for(asyncio.sleep(0), 0.1)
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_send_backup_command_surfaces_agent_http_error(monkeypatch):
    """A 4xx from the agent surfaces as a diagnosable detail, not an opaque None (#38).

    One cause of a failed backup request is an X-Orchestrator-Key mismatch → the agent returns 403
    "Invalid orchestrator key", which previously collapsed into a generic "Failed to
    send backup command" and read as networking for ~110 days. The detail must now
    carry the real status + body so a credential/config fault is diagnosable at a glance.
    """
    import httpx
    from core.backup_executor import backup_executor

    req = httpx.Request("POST", "https://agent.example.test:8090/api/backups")
    resp = httpx.Response(403, text="Invalid orchestrator key", request=req)

    async def fake_post(*args, **kwargs):
        return resp

    monkeypatch.setattr(backup_executor.http_client, "post", fake_post)
    monkeypatch.setattr(backup_executor, "agent_tls_enabled", True)
    monkeypatch.setattr(backup_executor, "agent_verify_ssl", True)

    result, detail = await backup_executor._send_backup_command(
        "https://agent.example.test:8090", {"backup_id": "probe"}
    )
    assert result is None
    assert "403" in detail
    assert "Invalid orchestrator key" in detail


@pytest.mark.asyncio
async def test_unsupported_vm_provider_cannot_dispatch_legacy_secret(monkeypatch):
    from core import backup_executor as module

    backup = SimpleNamespace(
        vm_id="fixture-vm", authority_kind="human", status="pending"
    )
    vm = SimpleNamespace(provider="unsupported", inventory_present=True)

    class Session:
        def query(self, model):
            assert model in {module.Backup, module.VM}
            self.record = backup if model is module.Backup else vm
            return self

        def filter(self, _condition):
            return self

        def first(self):
            return self.record

        def close(self):
            pass

    async def refuse_any_send(*_args, **_kwargs):
        pytest.fail("unsupported provider sent a backup request")

    monkeypatch.setenv("ENABLE_ENCRYPTION", "true")
    monkeypatch.setenv("ENCRYPTION_KEY", "synthetic-ordinary-data")
    monkeypatch.setattr(module, "SessionLocal", Session)
    monkeypatch.setattr(module.backup_executor.http_client, "post", refuse_any_send)

    result = await module.backup_executor._execute_backup_scoped("fixture")
    assert result == {"status": "held", "reason": "unsupported_backup_provider"}
    assert backup.status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,verify",
    [
        ("http://agent.example.test:8090", True),
        ("https://agent.example.test:8090", False),
    ],
)
async def test_low_level_backup_send_holds_keys_without_verified_https(
    monkeypatch, url, verify
):
    from core.backup_executor import backup_executor

    async def refuse_any_send(*_args, **_kwargs):
        pytest.fail("unverified transport received a backup request")

    monkeypatch.setattr(backup_executor.http_client, "post", refuse_any_send)
    monkeypatch.setattr(backup_executor, "agent_tls_enabled", True)
    monkeypatch.setattr(backup_executor, "agent_verify_ssl", verify)
    result, detail = await backup_executor._send_backup_command(
        url, {"backup_id": "fixture", "encryption_key": "synthetic-ordinary-data"}
    )
    assert result is None and "Verified agent HTTPS" in detail
