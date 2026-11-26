"""Schedule database waits must not block the serving API event loop."""

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_schedule_list_database_wait_keeps_same_app_health_responsive():
    from database import get_db
    from deps import get_current_user
    from routers import public, schedules

    entered = threading.Event()
    release = threading.Event()
    db = MagicMock()
    query = db.query.return_value.filter.return_value

    def blocked_count():
        entered.set()
        assert release.wait(15), "test did not release schedule query"
        return 0

    query.count.side_effect = blocked_count
    query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = (
        []
    )
    app = FastAPI()
    app.include_router(schedules.router)
    app.include_router(public.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="viewer", org_id="organization"
    )

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as workers:
        pending = workers.submit(client.get, "/api/v1/schedules")
        started = entered.wait(5)
        if not started and pending.done():
            response = pending.result(timeout=0)
            raise AssertionError(
                f"schedule request ended before query: {response.status_code} "
                f"{response.text[:200]}"
            )
        assert started, "schedule request did not reach the database query"
        try:
            # Prove independence from the blocked query, not runner speed.
            health = workers.submit(client.get, "/health").result(timeout=5)
            assert health.status_code == 200
            assert not release.is_set()
            assert not pending.done()
        finally:
            release.set()
        response = pending.result(timeout=5)
        assert response.status_code == 200
        assert response.json()["total"] == 0
