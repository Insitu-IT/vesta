"""Local admission/order controls; PostgreSQL acceptance is a separate suite."""

import asyncio
import uuid
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
import httpx

from core import restore_executor as module
from core.file_agent_http import AgentPeer, FileAgentHTTP
from models import Organization, User, Restore, Backup, VM, Agent

PEER = AgentPeer("127.0.0.1", 8090, "fixture", "a" * 64, "agent")


def bind_transport(owner, monkeypatch):
    owner.agent_tls_enabled = True
    owner.http_client = MagicMock(spec=FileAgentHTTP, aclose=AsyncMock())
    monkeypatch.setattr(module.settings, "orchestrator_to_agent_key", "test-only")
    monkeypatch.setattr(owner, "_agent_peer", lambda db, agent: PEER)


def specimen(monkeypatch):
    org, actor, restore_id = (str(uuid.uuid4()) for _ in range(3))
    rows = {
        Organization: NS(enabled=True),
        User: NS(is_active=True, role="operator"),
        Restore: NS(
            created_by=actor,
            status="pending",
            backup_id="backup",
            target_vm_id="vm",
            restore_to_original=True,
        ),
        Backup: NS(id="backup", status="completed", vm_id="vm"),
        VM: NS(id="vm", agent_id="agent"),
        Agent: NS(id="agent", status="online"),
    }
    db = MagicMock()

    def query(model):
        q = MagicMock()
        q.filter_by.return_value = q
        q.populate_existing.return_value = q
        q.with_for_update.return_value = q
        q.one_or_none.side_effect = lambda: rows[model]
        return q

    db.query.side_effect = query
    monkeypatch.setattr(module, "commercial_mode", lambda: True)
    return db, rows, (restore_id, org, actor)


@pytest.mark.parametrize(
    "refusal",
    [
        "none",
        "org",
        "actor",
        "role",
        "binding",
        "phase",
        "backup",
        "vm",
        "agent",
        "target",
    ],
)
def test_locked_restore_admission(monkeypatch, refusal):
    db, rows, args = specimen(monkeypatch)
    if refusal == "org":
        rows[Organization].enabled = False
    elif refusal == "actor":
        rows[User].is_active = False
    elif refusal == "role":
        rows[User].role = "viewer"
    elif refusal == "binding":
        rows[Restore].created_by = "other"
    elif refusal == "phase":
        rows[Restore].status = "dispatching"
    elif refusal == "backup":
        rows[Backup].status = "failed"
    elif refusal == "vm":
        rows[VM] = None
    elif refusal == "agent":
        rows[Agent].status = "offline"
    elif refusal == "target":
        rows[Restore].target_vm_id = "foreign"
    if refusal == "none":
        assert module.admit_restore(db, *args, "pending")[0] is rows[Restore]
    else:
        with pytest.raises(module.RestoreAdmissionError):
            module.admit_restore(db, *args, "pending")
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_worker_missing_provenance_has_no_database_effect(monkeypatch):
    db = MagicMock(side_effect=AssertionError("database reached"))
    monkeypatch.setattr(module, "SessionLocal", db)
    owner = module.RestoreExecutor()
    try:
        with pytest.raises(ValueError):
            await owner.execute_restore(str(uuid.uuid4()))
        db.assert_not_called()
    finally:
        await owner.cleanup()


@pytest.mark.parametrize("assignment", ["same", "foreign", "missing"])
def test_restore_oss_requires_persisted_default(monkeypatch, assignment):
    db, rows, args = specimen(monkeypatch)
    monkeypatch.setattr(module, "commercial_mode", lambda: False)
    db.get.return_value = (
        None
        if assignment == "missing"
        else NS(org_id=args[1] if assignment == "same" else "foreign")
    )
    if assignment == "same":
        assert module.admit_restore(db, *args, "pending")[0] is rows[Restore]
    else:
        with pytest.raises(module.RestoreAdmissionError):
            module.admit_restore(db, *args, "pending")
        db.query.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome", ["success", "commit_failure", "lost_reply", "cancel"]
)
async def test_worker_claim_precedes_request_and_never_replays(monkeypatch, outcome):
    db, rows, args = specimen(monkeypatch)
    restore = rows[Restore]
    restore.id, restore.target_vm_name = args[0], None
    restore.selected_disks, restore.until_checkpoint = [], None
    restore.auto_define, restore.adjust_config = False, False
    backup = rows[Backup]
    backup.storage_path, backup.tags, backup.id = "file:///fixture", {}, "backup"
    rows[Agent].hostname = "fixture"
    order = []

    def commit():
        order.append("commit")
        if outcome == "commit_failure":
            raise RuntimeError("commit failure")

    db.commit.side_effect = commit
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    owner = module.RestoreExecutor()
    bind_transport(owner, monkeypatch)

    async def send(*unused, **unused_kwargs):
        assert order == ["commit"] * 3 and restore.status == "dispatching"
        order.append("send")
        if outcome == "cancel":
            raise asyncio.CancelledError
        return (
            (None, "uncertain")
            if outcome == "lost_reply"
            else ({"status": "running"}, None)
        )

    monkeypatch.setattr(owner, "_send_restore_command", send)
    monkeypatch.setattr(owner, "monitor_restore", AsyncMock())
    try:
        if outcome == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await owner.execute_restore(*args)
        else:
            result = await owner.execute_restore(*args)
            assert result == (None if outcome == "success" else {"status": "held"})
        await asyncio.sleep(0)
        assert order == (
            ["commit"] * 3 + ["send", "commit"]
            if outcome == "success"
            else (
                ["commit"] if outcome == "commit_failure" else ["commit"] * 3 + ["send"]
            )
        )
        if outcome != "commit_failure":
            await owner.execute_restore(*args)
            assert order.count("send") == 1
        assert restore.status == ("running" if outcome == "success" else "dispatching")
    finally:
        await owner.cleanup()
    db.close.assert_called()


@pytest.mark.asyncio
async def test_restore_monitor_drain_closes_session_without_remote_rollback(
    monkeypatch,
):
    db, rows, args = specimen(monkeypatch)
    rows[Restore].status = "running"
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    owner = module.RestoreExecutor()
    bind_transport(owner, monkeypatch)
    entered = asyncio.Event()

    async def get(*args, **kwargs):
        entered.set()
        await asyncio.Future()

    owner.http_client.get = AsyncMock(side_effect=get)
    transport = owner.http_client
    # Only replace the timer, not the monitor/admission/transport ownership path.
    original_sleep = asyncio.sleep

    async def tick(delay):
        await original_sleep(0)

    monkeypatch.setattr(module.asyncio, "sleep", tick)
    task = asyncio.create_task(owner.monitor_restore(args[0], PEER, args[1], args[2]))
    owner.monitoring_tasks[args[0]] = task
    await asyncio.wait_for(entered.wait(), 1)
    await owner.cleanup()
    assert task.cancelled() and not owner.monitoring_tasks
    db.close.assert_called_once()
    db.commit.assert_called_once()
    transport.aclose.assert_awaited_once()
    assert rows[Restore].status == "running"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["http", "transport"])
async def test_restore_send_failure_does_not_log_remote_details(
    monkeypatch, caplog, kind
):
    owner = module.RestoreExecutor()
    bind_transport(owner, monkeypatch)
    request = httpx.Request("POST", "https://fixture/api/restores")
    response = httpx.Response(403, request=request, text="PRIVATE_RESTORE_DETAIL")
    post = AsyncMock(return_value=response)
    if kind == "transport":
        post.side_effect = RuntimeError("PRIVATE_RESTORE_DETAIL")
    monkeypatch.setattr(owner.http_client, "post", post)
    try:
        result, detail = await owner._send_restore_command(PEER, {})
        assert result is None
        assert "PRIVATE_RESTORE_DETAIL" not in caplog.text + detail
        post.assert_awaited_once()
    finally:
        await owner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "problem",
    [
        "valid",
        "wrong-id",
        "journal-created",
        "missing-no-store",
        "extra-field",
        "http-500",
    ],
)
async def test_only_exact_authenticated_prejournal_conflict_is_definitive(
    monkeypatch, problem
):
    owner = module.RestoreExecutor()
    bind_transport(owner, monkeypatch)
    request = {
        "kubevirt": {
            "restore_id": "restore-one",
            "target": {
                "vm_name": "fresh",
                "disks": [{"pvc_name": "z"}, {"pvc_name": "a"}],
            },
        }
    }
    proof = {
        "code": "prejournal_target_reserved",
        "restore_id": "restore-one",
        "target_vm_name": "fresh",
        "target_pvc_names": ["a", "z"],
        "journal_created": False,
    }
    if problem == "wrong-id":
        proof["restore_id"] = "foreign"
    elif problem == "journal-created":
        proof["journal_created"] = True
    elif problem == "extra-field":
        proof["unexpected"] = "value"
    headers = {} if problem == "missing-no-store" else {"Cache-Control": "no-store"}
    status = 500 if problem == "http-500" else 409
    response = httpx.Response(
        status,
        request=httpx.Request("POST", "https://fixture/api/restores"),
        json=proof,
        headers=headers,
    )
    monkeypatch.setattr(owner.http_client, "post", AsyncMock(return_value=response))
    try:
        result, detail = await owner._send_restore_command(PEER, request)
        assert result is None
        assert (detail == "prejournal_target_reserved") == (problem == "valid")
    finally:
        await owner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["prejournal", "lost-response"])
async def test_fresh_restore_definitive_refusal_is_terminal_but_loss_is_held(
    monkeypatch, outcome
):
    from core import kubevirt_restore

    db, rows, args = specimen(monkeypatch)
    restore = rows[Restore]
    restore.id = args[0]
    restore.status = "dispatching"
    restore.native_plan = None
    restore.kubevirt_plan = {"agent_id": "agent", "org_id": args[1]}
    restore.started_at = None
    rows[Agent].ip_address = None
    rows[Agent].hostname = "fixture"
    rows[Agent].port = 8090
    monkeypatch.setattr(module.settings, "orchestrator_to_agent_key", "test")
    monkeypatch.setattr(
        kubevirt_restore, "hydrate_request", lambda *_: {"kubevirt": {}}
    )
    owner = module.RestoreExecutor()
    bind_transport(owner, monkeypatch)
    monkeypatch.setattr(
        owner,
        "_send_restore_command",
        AsyncMock(
            return_value=(
                None,
                "prejournal_target_reserved" if outcome == "prejournal" else "HTTP 500",
            )
        ),
    )
    try:
        result = await owner._execute_fresh_restore(db, *args)
        if outcome == "prejournal":
            assert result is None
            assert restore.status == "failed"
            assert restore.completed_at is not None
            assert "reserved" in restore.error_message
        else:
            assert result == {"status": "held"}
            assert restore.status == "dispatching"
            assert not getattr(restore, "completed_at", None)
    finally:
        await owner.cleanup()


@pytest.mark.asyncio
async def test_fresh_restore_hold_propagates_through_executor_layers(monkeypatch):
    db, rows, args = specimen(monkeypatch)
    rows[Restore].kubevirt_plan = {"agent_id": "agent", "org_id": args[1]}
    rows[Restore].native_plan = None
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    owner = module.RestoreExecutor()
    fresh = AsyncMock(return_value={"status": "held"})
    monkeypatch.setattr(owner, "_execute_fresh_restore", fresh)
    try:
        assert await owner.execute_restore(*args) == {"status": "held"}
        fresh.assert_awaited_once_with(db, *args)
    finally:
        await owner.cleanup()


@pytest.mark.asyncio
async def test_historical_queued_restore_refuses_quarantined_catalog_before_claim(
    monkeypatch,
):
    db, rows, args = specimen(monkeypatch)
    rows[Backup].unverified_legacy_s3 = True
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    owner = module.RestoreExecutor()
    owner._send_restore_command = AsyncMock(side_effect=AssertionError("agent reached"))
    try:
        assert await owner.execute_restore(*args) == {"status": "held"}
        assert rows[Restore].status == "pending"
        db.commit.assert_not_called()
        owner._send_restore_command.assert_not_called()
    finally:
        await owner.cleanup()
