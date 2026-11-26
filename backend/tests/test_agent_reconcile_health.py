"""Agent reconciliation must not starve the shallow liveness endpoint."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient


def _health_during(client, request, entered, release):
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(request)
        assert entered.wait(1), "request did not enter the blocked database call"
        timer = threading.Timer(1, release.set)
        timer.start()
        try:
            start = time.monotonic()
            health = client.get("/health")
            elapsed = time.monotonic() - start
            assert health.status_code == 200
            assert elapsed < 0.5
        finally:
            release.set()
            timer.join()
        return pending.result(timeout=2)


@pytest.mark.parametrize("blocked_phase", ["credential_lookup", "tenant_update"])
def test_agent_auth_database_wait_keeps_same_app_health_responsive(
    monkeypatch, blocked_phase
):
    import database
    import deps
    from core.tenant_context import identity
    from database import get_db
    from routers import public

    entered = threading.Event()
    release = threading.Event()
    key_hash = deps.hash_api_key("test-key")
    agent = SimpleNamespace(
        id="agent", org_id="default", key_last_used_at=None, api_key_hash=key_hash
    )
    key = SimpleNamespace(enabled=True, key_hash=key_hash, is_expired=lambda: False)

    class KeyQuery:
        def filter(self, *criteria):
            return self

        def populate_existing(self):
            self.refreshed = True
            return self

        def with_for_update(self):
            assert self.refreshed
            self.locked = True
            return self

        def limit(self, count):
            assert count == 2 and self.locked
            return self

        def all(self):
            return [key]

    def maybe_wait(phase):
        if blocked_phase == phase:
            entered.set()
            assert release.wait(2), "test did not release agent authentication"

    class LookupSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    class TenantSession:
        def get(self, model, agent_id, *, populate_existing, with_for_update):
            assert populate_existing is True and with_for_update is True
            assert identity()[0] == "default"
            maybe_wait("tenant_update")
            assert agent_id == agent.id
            return agent

        def query(self, model):
            from models import AgentAPIKey

            assert model is AgentAPIKey
            return KeyQuery()

        def commit(self):
            return None

    def authenticate(key, fingerprint, lookup):
        assert key == "test-key" and fingerprint is None
        assert identity()[2] is True
        maybe_wait("credential_lookup")
        return agent

    monkeypatch.setattr(database, "SessionLocal", LookupSession)
    monkeypatch.setattr(deps, "_authenticate_agent", authenticate)
    monkeypatch.setattr(deps, "REQUIRE_MTLS", False)
    app = FastAPI()
    app.include_router(public.router)

    @app.get("/agent-probe")
    async def agent_probe(authenticated=Depends(deps.verify_agent_api_key)):
        return {"id": authenticated.id}

    app.dependency_overrides[get_db] = TenantSession
    with TestClient(app) as client:
        response = _health_during(
            client,
            lambda: client.get("/agent-probe", headers={"X-Agent-Key": "test-key"}),
            entered,
            release,
        )
    assert response.status_code == 200
    assert response.json() == {"id": agent.id}
    assert agent.key_last_used_at is not None


def test_pending_jobs_database_wait_keeps_same_app_health_responsive():
    from database import get_db
    from deps import verify_agent_api_key
    from routers import health, public

    entered = threading.Event()
    release = threading.Event()
    db = MagicMock()

    def blocked_vm_query():
        entered.set()
        assert release.wait(2), "test did not release pending-jobs query"
        return []

    db.query.return_value.filter.return_value.all.side_effect = blocked_vm_query
    app = FastAPI()
    app.include_router(health.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[verify_agent_api_key] = lambda: SimpleNamespace(id="agent")

    with TestClient(app) as client:
        response = _health_during(
            client,
            lambda: client.get("/api/v1/agents/agent/pending-jobs"),
            entered,
            release,
        )
    assert response.status_code == 200
    assert response.json() == {"backups": []}
