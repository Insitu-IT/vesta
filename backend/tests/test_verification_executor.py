"""Connected DB/transport sequencing; fake agent, not installed scrub evidence."""

from copy import deepcopy
from datetime import datetime, timedelta
from types import SimpleNamespace
import uuid

import httpx
import pytest

from backend.tests.test_backup_verification import fixture, response
from core import backup_verification as scrub
from core.file_agent_http import AgentPeer, FileAgentHTTP
from core import verification_executor as runtime
from models import Agent as AgentModel, BackupVerification


class Agent:
    def __init__(self, row):
        self.row = row
        self.calls = []
        self.remote = None
        self.wrong_capability = False
        self.lost_reply = False
        self.lost_completion_reply = None
        self.after_send = None
        self.busy = False
        self.busy_fault = None

    def reply(self, url, status, value):
        return httpx.Response(status, json=value, request=httpx.Request("GET", url))

    async def get(self, peer, path, **kw):
        assert kw["headers"]["X-Vesta-Agent-ID"] == peer.agent_id
        url = "https://" + peer.hostname + path
        self.calls.append(("GET", url, deepcopy(kw)))
        if url.endswith("/capability"):
            plan, _ = scrub.load_plan(self.row)
            return self.reply(
                url,
                200,
                dict(
                    schema=scrub.SCHEMA,
                    agent_id=(
                        str(uuid.uuid4()) if self.wrong_capability else plan["agent_id"]
                    ),
                    provider=plan["provider"],
                ),
            )
        if (
            self.remote
            and self.remote["status"] == "passed"
            and self.lost_completion_reply
        ):
            fault, self.lost_completion_reply = self.lost_completion_reply, None
            if fault == "timeout":
                raise httpx.ReadTimeout(
                    "lost completed reply; private transport detail"
                )
            if fault == "disconnect":
                raise httpx.ReadError("lost completed reply; private transport detail")
            assert fault == "truncated-json"
            return httpx.Response(
                200, content=b'{"schema":', request=httpx.Request("GET", url)
            )
        return self.reply(url, 404 if self.remote is None else 200, self.remote or {})

    async def post(self, peer, path, *, recheck, **kw):
        await recheck()
        assert kw["headers"]["X-Vesta-Agent-ID"] == peer.agent_id
        url = "https://" + peer.hostname + path
        self.calls.append(("POST", url, deepcopy(kw)))
        if url.endswith("/cancel"):
            assert kw["params"]["plan_sha256"] == self.row.verification_plan_sha256
            return self.reply(url, 202, self.remote or {})
        if self.busy:
            value = dict(
                schema="vnbui-backup-verification-admission/1",
                verification_id=self.row.id,
                org_id=self.row.org_id,
                agent_id=self.row.verification_agent_id,
                plan_sha256=self.row.verification_plan_sha256,
                status="not_admitted",
                reason="agent_busy",
            )
            if self.busy_fault == "unbound":
                value = {"detail": "rate limited"}
            elif self.busy_fault:
                value[self.busy_fault] = "wrong"
            if self.after_send:
                self.after_send()
            return self.reply(url, 429, value)
        if self.remote is None:
            self.remote = response(self.row, "pending")
        elif self.remote["status"] == "held":
            self.remote["status"], self.remote["message"] = "pending", "awaiting_worker"
        assert kw["json"]["plan"] == scrub.load_plan(self.row)[0]
        if self.after_send:
            self.after_send()
        if self.lost_reply:
            self.lost_reply = False
            raise httpx.ReadTimeout("simulated lost reply")
        return self.reply(url, 202, self.remote)

    def passed(self):
        self.remote["status"], self.remote["message"] = (
            "passed",
            "artifact_bytes_verified",
        )
        self.remote["result"] = scrub.expected_result(scrub.load_plan(self.row)[0])


def setup(db_session, session_factory, monkeypatch):
    backup, actor, row = fixture(db_session)
    plan, _ = scrub.load_plan(row)
    target = plan["bundle"]["members"][0]["request"]["plan"]["target"]
    monkeypatch.setattr(runtime, "SessionLocal", session_factory)
    monkeypatch.setattr(
        runtime,
        "vm_agent_peer",
        lambda db, agent: AgentPeer(
            agent.ip_address or agent.hostname,
            agent.port or 8090,
            agent.hostname,
            "a" * 64,
            agent.id,
        ),
    )
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config",
        lambda self: dict(target, access_key="read", secret_key="must-not-log"),
    )
    monkeypatch.setattr(
        "core.storage_attempt_key.unwrap_retained_attempt_key", lambda *args: None
    )
    agent = Agent(row)
    executor = runtime.VerificationExecutor()
    monkeypatch.setattr(
        executor, "_transport", lambda: (agent, {"X-Orchestrator-Key": "test"})
    )
    args = row.id, row.org_id, row.created_by
    return executor, agent, row, actor, args


@pytest.mark.asyncio
async def test_discovery_honors_held_backoff_and_due_time(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    assert any(item[0] == row.id for item in runtime._work_ids())
    agent.wrong_capability = True
    before = datetime.utcnow()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held"
    assert row.verification_next_poll_at >= before + timedelta(seconds=299)
    assert all(item[0] != row.id for item in runtime._work_ids())
    row.verification_next_poll_at = before - timedelta(seconds=1)
    db_session.commit()
    assert any(item[0] == row.id for item in runtime._work_ids())


@pytest.mark.asyncio
async def test_dispatch_poll_durable_result_and_terminal_noop(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    db_session.refresh(row)
    assert (
        row.status == "running"
        and row.verification_worker_id == agent.remote["worker_id"]
    )
    assert row.verification_result is None
    agent.passed()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "passed" and row.verification_result == agent.remote["result"]
    count = len(agent.calls)
    await executor.once(*args)
    assert len(agent.calls) == count
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1
    assert (
        "must-not-log"
        not in db_session.query(BackupVerification)
        .filter_by(id=row.id)
        .one()
        .verification_plan_canonical
    )


@pytest.mark.asyncio
async def test_lost_send_ack_reconciles_original_worker_without_resending(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    agent.lost_reply = True
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_worker_id is None
    agent.passed()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "running" and row.verification_result is None
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "passed"
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["timeout", "disconnect", "truncated-json"])
async def test_lost_completion_reply_retains_binding_and_never_resubmits(
    db_session, session_factory, monkeypatch, fault
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    db_session.refresh(row)
    worker, plan = row.verification_worker_id, row.verification_plan_sha256
    assert worker and row.verification_read_attempts == 1
    agent.passed()
    completed = deepcopy(agent.remote)
    agent.lost_completion_reply = fault

    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_result is None
    assert row.completed_at is None
    assert row.verification_worker_id == worker
    assert row.verification_plan_sha256 == plan
    assert row.verification_read_attempts == 1
    assert "private transport detail" not in row.result_message
    assert agent.remote == completed

    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "passed" and row.verification_result == completed["result"]
    assert row.verification_worker_id == worker
    assert row.verification_plan_sha256 == plan
    assert row.verification_read_attempts == 1
    assert len([call for call in agent.calls if call[0] == "POST"]) == 1
    calls = len(agent.calls)
    await executor.once(*args)
    assert len(agent.calls) == calls


@pytest.mark.asyncio
async def test_wrong_agent_identity_never_receives_read_credentials(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    agent.wrong_capability = True
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_worker_id is None
    assert not any(c[0] == "POST" for c in agent.calls)


@pytest.mark.asyncio
async def test_known_missing_worker_is_not_replaced(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    db_session.refresh(row)
    original = row.verification_worker_id
    agent.remote = None
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_worker_id == original
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1


@pytest.mark.asyncio
async def test_revoked_unknown_worker_after_lost_ack_is_cancelled_by_exact_plan(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    agent.lost_reply = True
    await executor.once(*args)
    actor.is_active = False
    db_session.commit()
    await executor.once(*args)
    db_session.refresh(row)
    assert (
        row.status == "held" and row.verification_worker_id == agent.remote["worker_id"]
    )
    assert len([c for c in agent.calls if c[1].endswith("/cancel")]) == 1
    assert (
        len([c for c in agent.calls if c[0] == "POST" and not c[1].endswith("/cancel")])
        == 1
    )


@pytest.mark.asyncio
async def test_cancel_stops_polling_only_after_original_worker_quiescence(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    row.verification_cancel_requested = True
    db_session.commit()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.completed_at is None
    agent.remote["status"], agent.remote["message"] = "held", "readmission_required"
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "cancelled" and row.completed_at is not None
    assert row.verification_result is None
    assert all(item[0] != row.id for item in runtime._work_ids())
    calls = len(agent.calls)
    await executor.once(*args)
    assert len(agent.calls) == calls


@pytest.mark.asyncio
async def test_unstarted_cancel_finishes_without_contacting_agent(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    row.verification_cancel_requested = True
    db_session.commit()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "cancelled" and row.completed_at is not None
    assert row.verification_worker_id is None and row.verification_result is None
    assert agent.calls == []


@pytest.mark.asyncio
async def test_cancel_missing_worker_remains_uncertain_without_resubmission(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    row.verification_cancel_requested = True
    db_session.commit()
    agent.remote = None
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.completed_at is None
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1


@pytest.mark.asyncio
async def test_revocation_before_result_acceptance_cancels_not_passes(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)

    def revoke():
        actor.is_active = False
        db_session.commit()

    agent.after_send = revoke
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_result is None
    assert any(c[1].endswith("/cancel") for c in agent.calls)


@pytest.mark.asyncio
async def test_failed_exact_worker_fact_survives_revocation(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    actor.is_active = False
    db_session.commit()
    agent.remote["status"], agent.remote["message"] = (
        "failed",
        "artifact_verification_failed",
    )
    info = dict(
        id=row.id,
        org_id=row.org_id,
        actor_id=row.created_by,
        peer=runtime.vm_agent_peer(
            db_session,
            db_session.query(AgentModel).filter_by(id=row.verification_agent_id).one(),
        ),
    )
    assert runtime._observe(info, agent.remote) == "failed"
    db_session.refresh(row)
    assert row.status == "failed" and row.verification_result is None


@pytest.mark.asyncio
async def test_busy_agent_does_not_exhaust_the_queued_read_budget(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    agent.busy = True
    for attempt in range(1, 6):
        await executor.once(*args)
        db_session.refresh(row)
        assert row.status == "held" and row.verification_worker_id is None
        assert row.verification_read_attempts == attempt
        assert row.verification_read_limit == attempt + 3
        assert row.verification_last_busy_attempt == attempt
        assert row.verification_next_poll_at > datetime.utcnow() + timedelta(
            seconds=290
        )
    assert agent.remote is None
    agent.busy = False
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "running" and row.verification_read_attempts == 6
    assert row.verification_read_limit == 8  # Only one possibly admitted read.


@pytest.mark.asyncio
async def test_busy_admission_exhaustion_stops_new_reads_but_preserves_observation(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    agent.busy = True
    await executor.once(*args)
    db_session.refresh(row)
    budget = deepcopy(row.verification_admission_budget)
    cutoff = datetime.fromisoformat(budget["deadline"])
    from core import operation_budget

    clock = SimpleNamespace(utcnow=lambda: cutoff, fromisoformat=datetime.fromisoformat)
    monkeypatch.setattr(operation_budget, "datetime", clock)
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and "budget exhausted" in row.result_message
    assert row.verification_read_attempts == 1 and row.verification_read_limit == 4
    assert row.verification_admission_budget == budget
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1
    with pytest.raises(scrub.StorageOwnershipError, match="budget exhausted"):
        scrub.grant_readmission(db_session, row, actor.id)
    # A delayed authenticated result still needs original custody validation;
    # expiry does not discard it or fabricate a new read.
    agent.remote = response(row, "pending")
    await executor.once(*args)
    agent.passed()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "passed" and row.verification_admission_budget == budget


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason", ["operation_budget_exhausted", "operation_budget_exhausted_or_missing"]
)
async def test_worker_budget_exhaustion_never_triggers_automatic_readmission(
    db_session, session_factory, monkeypatch, reason
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    agent.remote["status"], agent.remote["message"] = "held", reason
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.result_message == reason
    assert row.verification_read_attempts == 1
    assert len([c for c in agent.calls if c[0] == "POST"]) == 1
    with pytest.raises(scrub.StorageOwnershipError, match="budget exhausted"):
        scrub.grant_readmission(db_session, row, actor.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["unbound", "plan_sha256", "verification_id", "agent_id", "org_id"]
)
async def test_unbound_busy_reply_never_refunds_uncertain_reads(
    db_session, session_factory, monkeypatch, fault
):
    executor, agent, row, _, args = setup(db_session, session_factory, monkeypatch)
    agent.busy, agent.busy_fault = True, fault
    await executor.once(*args)
    db_session.refresh(row)
    assert row.status == "held" and row.verification_read_attempts == 1
    assert row.verification_read_limit == 3 and row.verification_last_busy_attempt == 0


@pytest.mark.asyncio
async def test_busy_credit_is_idempotent_and_cannot_borrow_revoked_authority(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    agent.busy = True
    await executor.once(*args)
    info = runtime._prepare(*args)
    value = dict(
        schema="vnbui-backup-verification-admission/1",
        verification_id=row.id,
        org_id=row.org_id,
        agent_id=row.verification_agent_id,
        plan_sha256=row.verification_plan_sha256,
        status="not_admitted",
        reason="agent_busy",
    )
    runtime._busy(info, 1, value)
    db_session.refresh(row)
    assert row.verification_read_limit == 4

    def revoke():
        actor.is_active = False
        db_session.commit()

    agent.after_send = revoke
    await executor.once(*args)
    db_session.refresh(row)
    assert row.verification_read_attempts == 2 and row.verification_read_limit == 4
    assert row.verification_last_busy_attempt == 1 and row.verification_result is None


@pytest.mark.asyncio
async def test_automatic_readmissions_are_bounded_and_original_operator_can_resume(
    db_session, session_factory, monkeypatch
):
    executor, agent, row, actor, args = setup(db_session, session_factory, monkeypatch)
    await executor.once(*args)
    for _ in range(4):
        agent.remote["status"], agent.remote["message"] = "held", "readmission_required"
        await executor.once(*args)
    db_session.refresh(row)
    assert (
        row.status == "held"
        and row.verification_read_attempts == 3
        and row.verification_read_limit == 3
    )
    assert len([c for c in agent.calls if c[0] == "POST"]) == 3
    with pytest.raises(scrub.StorageOwnershipError):
        scrub.grant_readmission(db_session, row, str(uuid.uuid4()))
    scrub.grant_readmission(db_session, row, actor.id)
    db_session.commit()
    await executor.once(*args)
    db_session.refresh(row)
    assert row.verification_read_attempts == 4 and row.verification_read_limit == 6
    assert len([c for c in agent.calls if c[0] == "POST"]) == 4


@pytest.mark.parametrize(
    "enabled,key,pinned,allowed",
    [
        (True, "key", True, True),
        (False, "key", True, False),
        (True, "", True, False),
        (True, "key", False, False),
    ],
)
def test_scrub_requires_the_enrolled_transport(
    monkeypatch, enabled, key, pinned, allowed
):
    from core import restore_executor as restore_module
    from config import settings
    from core.agent_http import AgentHTTP

    executor = restore_module.RestoreExecutor()
    executor.agent_tls_enabled = enabled
    client = (
        FileAgentHTTP(ca="/fixture/ca", certificate=("/fixture/cert", "/fixture/key"))
        if pinned
        else AgentHTTP()
    )
    executor.http_client = client
    monkeypatch.setattr(restore_module, "restore_executor", executor)
    monkeypatch.setattr(settings, "orchestrator_to_agent_key", key)
    if allowed:
        actual, headers = runtime.VerificationExecutor._transport()
        assert actual is client and headers == {"X-Orchestrator-Key": key}
    else:
        with pytest.raises(restore_module.RestoreAdmissionError):
            runtime.VerificationExecutor._transport()
