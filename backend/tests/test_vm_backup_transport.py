"""Synthetic fixture for the backup producer's enrolled transport boundary."""

from types import SimpleNamespace

import httpx
import pytest

from core import vm_agent_peer
from core.backup_executor import BackupExecutor
from core.file_agent_http import AgentPeer
from core.s3_ownership import StorageOwnershipError


@pytest.mark.asyncio
@pytest.mark.parametrize("rotated", [False, True])
async def test_backup_dispatch_rechecks_certified_target_before_sending(
    monkeypatch, rotated
):
    agent = SimpleNamespace(id="fixture", status="online")
    peer = AgentPeer(
        "127.0.0.1", 8090, "agent.example.test", "a" * 64, "fixture", "a" * 64
    )
    changed = AgentPeer(
        "127.0.0.1", 8090, "agent.example.test", "b" * 64, "fixture", "b" * 64
    )
    current = peer
    sent = []

    class Session:
        def query(self, _):
            return self

        def filter_by(self, **filters):
            assert filters == {"id": "fixture", "org_id": "org"}
            return self

        def populate_existing(self):
            return self

        def one_or_none(self):
            return agent

    class Transport:
        async def post(self, target, path, *, headers, json, recheck):
            nonlocal current
            assert target == peer and path == "/api/backups"
            assert headers == {
                "X-Orchestrator-Key": "fixture",
                "X-Vesta-Agent-ID": "fixture",
            }
            await recheck()
            if rotated:
                current = changed
            await recheck()
            sent.append(json)
            return httpx.Response(202)

    monkeypatch.setattr(vm_agent_peer, "vm_agent_peer", lambda db, enrolled: current)
    executor = BackupExecutor()
    executor.agent_tls_enabled = True
    executor.agent_verify_ssl = True
    executor.file_agent_http = Transport()
    monkeypatch.setattr(
        executor, "_get_agent_headers", lambda: {"X-Orchestrator-Key": "fixture"}
    )
    request = {"backup_id": "fixture"}
    if rotated:
        with pytest.raises(StorageOwnershipError, match="identity changed"):
            await executor._post_certified_vm_backup(
                Session(), "fixture", "org", request
            )
        assert sent == []
    else:
        assert (
            await executor._post_certified_vm_backup(
                Session(), "fixture", "org", request
            )
        ).status_code == 202
        assert sent == [request]
