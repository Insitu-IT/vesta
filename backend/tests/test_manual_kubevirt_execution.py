"""Manual HTTP admission owns no checkpoint or publication authority."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
from datetime import datetime, timedelta

import httpx
import pytest

from core import backup_executor as module
from core.file_agent_http import AgentPeer, FileAgentHTTP
from models import Agent, AgentCertificate, Backup, S3Publication, VM


class CertifiedBackupTransport(FileAgentHTTP):
    """Retain the real version probe and recheck, replacing only socket I/O."""

    def __init__(self, peer, response):
        super().__init__(ca=None, certificate=None)
        self.peer = peer
        self.response = response
        self.failure = None
        self.on_probe = None
        self.on_send = None
        self._request = Mock(side_effect=self._exchange)

    def _exchange(self, peer, method, path, headers, payload, params):
        assert peer == self.peer
        assert headers == {
            "X-Orchestrator-Key": "fixture",
            "X-Vesta-Agent-ID": self.peer.agent_id,
        }
        assert params is None
        if method == "GET":
            assert path == "/api/version" and payload is None
            if self.on_probe is not None:
                self.on_probe()
            return httpx.Response(
                200,
                json={"version": "6.2.0"},
                request=httpx.Request("GET", "https://" + peer.hostname + path),
            )
        assert method == "POST" and path == "/api/backups"
        if self.failure is not None:
            raise self.failure
        if self.on_send is not None:
            self.on_send()
        return self.response

    def assert_not_contacted(self):
        self._request.assert_not_called()

    def assert_sent(self):
        probe, send = self._request.call_args_list
        assert probe.args[1:3] == ("GET", "/api/version")
        assert send.args[1:3] == ("POST", "/api/backups")
        return send.args[4]


def install_certified_backup_transport(db, owner, agent, monkeypatch, response):
    fingerprint = "a" * 64
    agent.ip_address = "127.0.0.1"
    agent.port = 8090
    agent.cert_fingerprint = fingerprint
    agent.mtls_enabled = True
    db.add(
        AgentCertificate(
            agent_id=agent.id,
            fingerprint=fingerprint,
            common_name=agent.hostname,
            status="active",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
    )
    db.commit()
    monkeypatch.delenv("VESTA_AGENT_SERVING_TRUST_FILE", raising=False)
    owner.agent_tls_enabled = owner.agent_verify_ssl = True
    monkeypatch.setattr(
        owner, "_get_agent_headers", lambda: {"X-Orchestrator-Key": "fixture"}
    )
    peer = AgentPeer(
        agent.ip_address, agent.port, agent.hostname, fingerprint, agent.id, fingerprint
    )
    owner.file_agent_http = CertifiedBackupTransport(peer, response)
    return owner.file_agent_http


@pytest.fixture
def case(db_session, session_factory, monkeypatch):
    agent = Agent(hostname="manual", status="online")
    db_session.add(agent)
    db_session.flush()
    vm = VM(agent_id=agent.id, name="vm", provider="kubevirt", inventory_present=True)
    db_session.add(vm)
    db_session.flush()
    backup = Backup(
        vm_id=vm.id,
        status="pending",
        authority_kind="human",
        initiating_user_id=str(uuid4()),
    )
    db_session.add(backup)
    db_session.commit()
    owner = module.BackupExecutor()
    monkeypatch.setattr(module, "SessionLocal", session_factory)
    monkeypatch.delenv("ENABLE_ENCRYPTION", raising=False)
    monkeypatch.setattr(
        "core.storage_dispatch.read_target",
        lambda _: {
            "capability_profile": "db-rooted-consumer-verified/1",
            "region": "us-east-1",
        },
    )
    calls = []
    monkeypatch.setattr(
        "core.backup_capacity.reserve_capacity",
        lambda factory, bid: calls.append(("capacity", bid)),
    )
    request = dict(
        backup_id=backup.id,
        agent_id=agent.id,
        org_id=agent.org_id,
        reservation_id="reservation",
        plan_sha256="a" * 64,
        plan=dict(
            provider="kubevirt",
            capability_profile="db-rooted-consumer-verified/1",
            target=dict(region="us-east-1"),
        ),
    )
    ack = dict(
        status="accepted",
        **{k: request[k] for k in ("backup_id", "reservation_id", "plan_sha256")}
    )

    async def dispatch(db, bid, send):
        from core.tenant_context import identity

        assert identity() == (backup.org_id, backup.initiating_user_id, False)
        calls.append(("dispatch", bid))
        assert calls[0] == ("capacity", bid)
        return await send(agent.id, request)

    monkeypatch.setattr("core.storage_dispatch.dispatch_kubevirt", dispatch)
    install_certified_backup_transport(
        db_session,
        owner,
        agent,
        monkeypatch,
        SimpleNamespace(status_code=202, json=lambda: ack),
    )
    return owner, backup, calls, ack


@pytest.mark.asyncio
async def test_contended_manual_admission_does_not_starve_health(case, monkeypatch):
    from routers.public import health_check

    owner, backup, calls, ack = case
    entered = threading.Event()
    release = threading.Event()

    def blocked_capacity(factory, backup_id):
        entered.set()
        assert release.wait(2), "test did not release admission wait"
        calls.append(("capacity", backup_id))

    monkeypatch.setattr("core.backup_capacity.reserve_capacity", blocked_capacity)
    task = asyncio.create_task(owner.execute_backup(backup.id))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert not release.is_set()
        assert await asyncio.wait_for(health_check(), 0.2) == {
            "status": "ok",
            "service": "vesta-api",
        }
        assert not task.done()
    finally:
        release.set()
    assert await task == ack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reader_name", ["_read_original_backup_authority", "_read_supported_provider"]
)
async def test_manual_pre_dispatch_db_wait_keeps_health_live(
    case, monkeypatch, reader_name
):
    from routers.public import health_check

    owner, backup, _, ack = case
    entered = threading.Event()
    release = threading.Event()
    original_reader = getattr(owner, reader_name)

    def blocked_reader(backup_id):
        entered.set()
        assert release.wait(2), "test did not release pre-dispatch database wait"
        return original_reader(backup_id)

    monkeypatch.setattr(owner, reader_name, blocked_reader)
    task = asyncio.create_task(owner.execute_backup(backup.id))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert await asyncio.wait_for(health_check(), 0.2) == {
            "status": "ok",
            "service": "vesta-api",
        }
        assert not task.done()
    finally:
        release.set()
    assert await task == ack


@pytest.mark.asyncio
async def test_cancelled_manual_admission_waits_and_never_sends(case, monkeypatch):
    owner, backup, _, _ = case
    entered = threading.Event()
    release = threading.Event()

    def blocked_capacity(factory, backup_id):
        entered.set()
        assert release.wait(2), "test did not release capacity wait"

    monkeypatch.setattr("core.backup_capacity.reserve_capacity", blocked_capacity)
    task = asyncio.create_task(owner.execute_backup(backup.id))
    assert await asyncio.to_thread(entered.wait, 1)
    task.cancel()
    await asyncio.sleep(0.05)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    owner.file_agent_http.assert_not_contacted()


@pytest.mark.asyncio
async def test_manual_dispatch_accepts_exact_ack_without_legacy_monitor(
    db_session, case
):
    owner, backup, calls, ack = case
    assert await owner.execute_backup(backup.id) == ack
    db_session.refresh(backup)
    assert backup.status == "running"
    assert [call[0] for call in calls] == ["capacity", "dispatch"]
    assert not owner.monitoring_tasks
    request = owner.file_agent_http.assert_sent()
    assert request["backup_id"] == ack["backup_id"]
    assert request["plan_sha256"] == ack["plan_sha256"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubevirt", "libvirt"])
async def test_reservation_refusal_uses_shared_pristine_closeout(
    case, monkeypatch, provider
):
    owner, backup, _, _ = case
    closed = []

    def refuse(*args):
        raise RuntimeError("New backup admission paused")

    def close(factory, backup_id):
        closed.append(backup_id)
        return {"status": "failed", "reason": "pre_dispatch_no_effect"}

    monkeypatch.setattr("core.backup_capacity.reserve_capacity", refuse)
    monkeypatch.setattr("core.backup_unreserved.close_unreserved", close)
    method = (
        owner._execute_kubevirt if provider == "kubevirt" else owner._execute_native
    )
    with module.SessionLocal() as db:
        assert await method(db, backup.id) == {
            "status": "failed",
            "reason": "pre_dispatch_no_effect",
        }
    assert closed == [backup.id]
    owner.file_agent_http.assert_not_contacted()


@pytest.mark.asyncio
async def test_missing_original_human_never_reaches_capacity_or_agent(db_session, case):
    owner, backup, calls, _ = case
    backup.initiating_user_id = None
    db_session.commit()

    assert await owner.execute_backup(backup.id) == {
        "status": "held",
        "reason": "original_authority_unavailable",
    }
    assert calls == []
    owner.file_agent_http.assert_not_contacted()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["lost-reply", "held", "wrong-attempt", "fake-completed"]
)
async def test_uncertain_admission_never_marks_failed_or_completed(
    db_session, case, failure
):
    owner, backup, calls, ack = case
    if failure == "lost-reply":
        owner.file_agent_http.failure = TimeoutError("lost reply")
    else:
        response = owner.file_agent_http.response
        if failure == "held":
            response.status_code = 423
        elif failure == "wrong-attempt":
            ack["reservation_id"] = "replacement"
        else:
            ack["status"] = "completed"
    result = await owner.execute_backup(backup.id)
    assert result["status"] == "held"
    assert owner.file_agent_http.assert_sent()["backup_id"] == backup.id
    db_session.refresh(backup)
    assert backup.status == "pending"
    assert not owner.monitoring_tasks
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_fast_publication_is_not_overwritten_with_running(
    db_session, session_factory, case
):
    owner, backup, _, ack = case

    def publish_during_send():
        with session_factory() as db:
            db.get(Backup, backup.id).status = "completed"
            db.commit()

    owner.file_agent_http.on_send = publish_during_send
    assert await owner.execute_backup(backup.id) == ack
    db_session.refresh(backup)
    assert backup.status == "completed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing", ["https", "verification", "authentication", "region"]
)
async def test_configuration_refuses_before_capacity_or_transport(
    db_session, case, monkeypatch, missing
):
    owner, backup, calls, _ = case
    if missing == "https":
        owner.agent_tls_enabled = False
    elif missing == "verification":
        owner.agent_verify_ssl = False
    elif missing == "authentication":
        monkeypatch.setattr(owner, "_get_agent_headers", lambda: {})
    elif missing == "region":
        monkeypatch.setattr(
            "core.storage_dispatch.read_target",
            lambda _: {
                "capability_profile": "db-rooted-consumer-verified/1",
                "region": "",
            },
        )
    assert (await owner.execute_backup(backup.id))["status"] == "held"
    assert calls == []
    owner.file_agent_http.assert_not_contacted()


@pytest.mark.asyncio
async def test_encrypted_manual_dispatch_uses_transaction_not_static_key(
    case, monkeypatch
):
    owner, backup, calls, ack = case
    monkeypatch.setenv("ENABLE_ENCRYPTION", "true")
    monkeypatch.setenv("ENCRYPTION_KEY", "must-not-be-transported")
    assert await owner.execute_backup(backup.id) == ack
    assert len(calls) == 2
    assert "must-not-be-transported" not in str(owner.file_agent_http.assert_sent())


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ["before-probe", "after-probe"])
async def test_manual_dispatch_keeps_payload_from_unverified_peer(
    db_session, session_factory, case, when
):
    owner, backup, _, _ = case
    transport = owner.file_agent_http

    def revoke():
        with session_factory() as db:
            db.query(AgentCertificate).filter_by(
                agent_id=transport.peer.agent_id
            ).one().status = "revoked"
            db.commit()

    if when == "before-probe":
        revoke()
    else:
        transport.on_probe = revoke
    assert (await owner.execute_backup(backup.id))["status"] == "held"
    contacted_methods = [call.args[1] for call in transport._request.call_args_list]
    assert contacted_methods == (["GET"] if when == "after-probe" else [])
    db_session.refresh(backup)
    assert backup.status == "pending" and not owner.monitoring_tasks


@pytest.mark.asyncio
async def test_source_refusal_before_publication_fails_and_releases_capacity(
    db_session, session_factory, case, monkeypatch
):
    owner, backup, calls, _ = case
    backup.capacity_state = "reserved"
    backup.capacity_id = str(uuid4())
    backup.capacity_reserved_at = datetime.utcnow()
    backup.capacity_policy_revision = 1
    db_session.commit()

    async def refuse_source(db, bid, send):
        from core.s3_ownership import StorageOwnershipError

        calls.append(("source_refused", bid))
        raise StorageOwnershipError("Explicitly exclude unsupported source disks")

    def release_no_effect(factory, bid, *, before_commit):
        with factory() as session:
            row = session.get(Backup, bid)
            row.capacity_state = "released"
            row.capacity_release = {
                "schema": 1,
                "capacity_id": row.capacity_id,
                "reason": "never_effect_admitted",
            }
            before_commit(session)
            session.commit()
        return {"disposition": "committed_custody"}

    monkeypatch.setattr("core.storage_dispatch.dispatch_kubevirt", refuse_source)
    monkeypatch.setattr("core.backup_capacity.release_never_effect", release_no_effect)

    assert await owner.execute_backup(backup.id) == {
        "status": "failed",
        "reason": "pre_dispatch_no_effect",
    }
    db_session.refresh(backup)
    assert backup.status == "failed"
    assert backup.capacity_state == "released"
    assert backup.tags["error"] == "pre_dispatch_refused"
    assert [call[0] for call in calls] == ["capacity", "source_refused"]
    owner.file_agent_http.assert_not_contacted()


@pytest.mark.asyncio
async def test_committed_publication_prevents_no_effect_release(
    db_session, session_factory, case, monkeypatch
):
    owner, backup, _, _ = case
    backup.capacity_state = "reserved"
    backup.capacity_id = str(uuid4())
    backup.capacity_reserved_at = datetime.utcnow()
    backup.capacity_policy_revision = 1
    db_session.add(
        S3Publication(
            backup_id=backup.id,
            kind="payload",
            endpoint="https://s3.example.org",
            bucket="fixture",
            object_key=backup.id,
        )
    )
    db_session.commit()

    async def refuse_source(db, bid, send):
        raise TimeoutError("delivery outcome unknown")

    def refuse_if_publication(factory, bid, *, before_commit):
        with factory() as session:
            row = session.get(Backup, bid)
            row.capacity_state = "released"
            row.capacity_release = {
                "schema": 1,
                "capacity_id": row.capacity_id,
                "reason": "never_effect_admitted",
            }
            before_commit(session)
            session.commit()
        return {"disposition": "committed_custody"}

    monkeypatch.setattr("core.storage_dispatch.dispatch_kubevirt", refuse_source)
    monkeypatch.setattr(
        "core.backup_capacity.release_never_effect", refuse_if_publication
    )
    assert (await owner.execute_backup(backup.id))["status"] == "held"
    db_session.refresh(backup)
    assert backup.status == "pending"
    assert backup.capacity_state == "reserved"
