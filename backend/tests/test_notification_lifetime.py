"""Controlled SMTP threads only: no external email or durable-delivery claim."""

import asyncio
import threading
import traceback
from types import SimpleNamespace
from unittest.mock import MagicMock
from email.mime.text import MIMEText

import pytest

from core.notifications import NotificationService, SMTPDeliveryUncertain
from core.tenant_context import TenantContext, identity

ORG = "d321cd87-74d5-4a1d-9a34-e2d8e0e6af80"
ACTOR = "e88f1ff8-9c11-4d3d-b0ab-8f624e009732"


def config():
    return dict(
        server="smtp.invalid",
        from_email="test@example.invalid",
        port=587,
        username="fixture-user",
        password="PRIVATE_SMTP_SECRET",
        use_tls=True,
    )


async def send(service):
    return await service._send_email(
        "PRIVATE_SUBJECT", "PRIVATE_BODY", ["test@example.invalid"], config()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("late_failure", [False, True])
async def test_cancelled_send_retains_worker_until_drain_and_never_replays(
    monkeypatch, caplog, late_failure
):
    service = NotificationService()
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    calls = []

    def smtp(*args):
        calls.append(identity())
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(3)
        if late_failure:
            raise RuntimeError("PRIVATE_SMTP_SECRET PRIVATE_BODY")

    monkeypatch.setattr(service, "_send_smtp", smtp)
    try:
        with TenantContext(ORG, user_id=ACTOR):
            task = asyncio.create_task(send(service))
            await asyncio.wait_for(entered.wait(), 1)
            worker = next(iter(service._workers))
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not worker.cancelled() and not worker.done()
            assert calls == [(None, None, False)]  # no DB/tenant authority on thread
            drain = asyncio.create_task(service.cleanup())
            await asyncio.sleep(0)
            assert not drain.done()
            with pytest.raises(RuntimeError, match="closed"):
                await send(service)
            release.set()
            await asyncio.wait_for(drain, 1)
            assert not service._workers
            service.start()
            assert len(calls) == 1  # start/reopen is not resend
            await service.cleanup()
        for private in ("PRIVATE_SMTP_SECRET", "PRIVATE_BODY", "PRIVATE_SUBJECT"):
            assert private not in caplog.text
    finally:
        release.set()


@pytest.mark.asyncio
async def test_drain_timeout_and_cancel_keep_closed_custody_until_explicit_drain(
    monkeypatch,
):
    service = NotificationService()
    service.drain_timeout = 0.01
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()

    def smtp(*args):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(3)

    monkeypatch.setattr(service, "_send_smtp", smtp)
    try:
        task = asyncio.create_task(send(service))
        await asyncio.wait_for(entered.wait(), 1)
        with pytest.raises(RuntimeError, match="drain incomplete"):
            await service.cleanup()
        assert task.cancelled() and len(service._workers) == 1
        with pytest.raises(RuntimeError, match="unresolved"):
            service.start()
        service.drain_timeout = 2
        drain = asyncio.create_task(service.cleanup())
        await asyncio.sleep(0)
        drain.cancel()
        with pytest.raises(asyncio.CancelledError):
            await drain
        assert len(service._workers) == 1
        release.set()
        await service.cleanup()
        service.start()
        await service.cleanup()
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["backup", "agent"])
async def test_cancelled_notification_logs_uncertain_on_caller_and_closes_owned_session(
    monkeypatch, kind
):
    import core.notifications as module

    service = NotificationService()
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    db = MagicMock()
    recorded = []
    db.add.side_effect = lambda row: recorded.append(
        (row.status, identity(), threading.get_ident())
    )
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    monkeypatch.setattr(
        service,
        "_get_smtp_config",
        lambda db: {**config(), "enabled": True, "recipients": "test@example.invalid"},
    )
    monkeypatch.setattr(
        service, "_get_notification_prefs", lambda db: {"on_agent_offline": True}
    )
    monkeypatch.setattr(service, "_build_agent_offline_email", lambda agent: "body")

    def smtp(*args):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(3)

    monkeypatch.setattr(service, "_send_smtp", smtp)
    try:
        with TenantContext(ORG, user_id=ACTOR):
            if kind == "backup":
                operation = service.send_backup_notification(
                    SimpleNamespace(id="backup", vm_id="vm"), "started"
                )
            else:
                operation = service.send_agent_offline_notification(
                    SimpleNamespace(id="agent", hostname="host")
                )
            task = asyncio.create_task(operation)
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert recorded == [("uncertain", identity(), threading.get_ident())]
            db.commit.assert_called_once()
            db.close.assert_called_once()
            release.set()
            await service.cleanup()
            assert len(recorded) == 1  # late acknowledgement cannot rewrite uncertainty
    finally:
        release.set()


@pytest.mark.asyncio
async def test_worker_error_is_redacted_uncertainty_and_next_explicit_send_can_run(
    monkeypatch, caplog
):
    service = NotificationService()

    def fail(*args):
        raise RuntimeError("PRIVATE_SMTP_SECRET PRIVATE_BODY")

    monkeypatch.setattr(service, "_send_smtp", fail)
    with pytest.raises(SMTPDeliveryUncertain) as caught:
        await send(service)
    assert "PRIVATE" not in "".join(traceback.format_exception(caught.value))
    assert "PRIVATE" not in caplog.text
    monkeypatch.setattr(service, "_send_smtp", lambda *args: None)
    assert await send(service) is True
    await service.cleanup()


@pytest.mark.asyncio
async def test_foreign_loop_and_closed_owner_refuse_before_worker(monkeypatch):
    service = NotificationService()
    smtp = MagicMock()
    monkeypatch.setattr(service, "_send_smtp", smtp)
    assert await send(service) is True

    def foreign():
        with pytest.raises(RuntimeError, match="owning event loop"):
            asyncio.run(send(service))
        with pytest.raises(RuntimeError, match="owning event loop"):
            asyncio.run(service.cleanup())

    await asyncio.to_thread(foreign)
    assert smtp.call_count == 1
    with pytest.raises(RuntimeError, match="closed"):
        await send(service)
    await service.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["server", "from_email", "capacity"])
async def test_local_refusal_has_zero_worker_submission(monkeypatch, missing):
    service = NotificationService()
    smtp = MagicMock()
    monkeypatch.setattr(service, "_send_smtp", smtp)
    cfg = config()
    if missing == "capacity":
        service.MAX_PENDING_SENDS = 0
    else:
        cfg[missing] = ""
    assert (
        await service._send_email("subject", "body", ["test@example.invalid"], cfg)
        is False
    )
    smtp.assert_not_called()
    await service.cleanup()


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_smtp_transport_closes_and_partial_refusal_is_uncertain(
    monkeypatch, tls, partial
):
    import core.notifications as module

    transport = MagicMock()
    server = transport.return_value.__enter__.return_value
    server.sendmail.return_value = (
        {"recipient": (550, b"PRIVATE_BODY")} if partial else {}
    )
    monkeypatch.setattr(module.smtplib, "SMTP", transport)
    cfg = {**config(), "use_tls": tls}
    if partial:
        with pytest.raises(SMTPDeliveryUncertain, match="partially accepted"):
            NotificationService()._send_smtp(MIMEText("body"), ["recipient"], cfg)
    else:
        NotificationService()._send_smtp(MIMEText("body"), ["recipient"], cfg)
    transport.assert_called_once_with("smtp.invalid", 587, timeout=30)
    transport.return_value.__exit__.assert_called_once()
    assert server.starttls.call_count == int(tls)
    if tls:
        import ssl

        context = server.starttls.call_args.kwargs["context"]
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    server.sendmail.assert_called_once()


@pytest.mark.asyncio
async def test_failed_outcome_persistence_never_replays_send(monkeypatch, caplog):
    service = NotificationService()
    smtp = MagicMock(side_effect=RuntimeError("PRIVATE_BODY"))
    monkeypatch.setattr(service, "_send_smtp", smtp)
    db = MagicMock()
    db.commit.side_effect = RuntimeError("PRIVATE_SMTP_SECRET")
    with pytest.raises(SMTPDeliveryUncertain):
        await service._send_logged_email(
            db=db,
            notification_type="test",
            recipients=["recipient"],
            subject="subject",
            body="body",
            config=config(),
        )
    assert db.add.call_args.args[0].status == "uncertain"
    db.commit.assert_called_once()
    await service.cleanup()
    service.start()
    smtp.assert_called_once()
    assert "PRIVATE" not in caplog.text
    await service.cleanup()


@pytest.mark.asyncio
async def test_pending_worker_consumes_capacity_and_owns_configuration_snapshot(
    monkeypatch,
):
    service = NotificationService()
    service.MAX_PENDING_SENDS = 1
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    recipients = ["first@example.invalid"]
    cfg = config()
    seen = []

    def smtp(message, selected, settings):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(3)
        seen.append((selected, settings["server"], identity()))

    monkeypatch.setattr(service, "_send_smtp", smtp)
    try:
        first = asyncio.create_task(
            service._send_email("subject", "body", recipients, cfg)
        )
        await asyncio.wait_for(entered.wait(), 1)
        recipients.append("foreign@example.invalid")
        cfg["server"] = "changed.invalid"
        assert await send(service) is False
        assert len(service._workers) == 1
        release.set()
        assert await first is True
        assert seen == [
            (["first@example.invalid"], "smtp.invalid", (None, None, False))
        ]
        await service.cleanup()
    finally:
        release.set()
