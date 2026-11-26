"""Bounded invalidation continuation without real sockets or mutations."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
import httpx
from core.realtime import RealtimeManager
from core.tenant_context import TenantContext
from deps import get_current_user
from routers import realtime as routes

ORG = "d321cd87-74d5-4a1d-9a34-e2d8e0e6af80"
OTHER = "b0d78398-5c7d-477d-ace0-58b7fce87827"


def manager(monkeypatch):
    result = RealtimeManager()

    async def no_socket(event):
        pass

    monkeypatch.setattr(result, "_broadcast_websocket", no_socket)
    return result


@pytest.mark.asyncio
async def test_cursor_ties_order_pagination_and_scope(monkeypatch):
    events = manager(monkeypatch)
    with TenantContext(ORG):
        cursor = events.get_event_page(user_id="alice", role="admin")["next_cursor"]
        for n in range(5):
            await events.emit_event("test", {"n": n})
        # Keep synthetic equal timestamps within retention regardless of test date.
        tied = datetime.now(timezone.utc)
        for event in events.event_history:
            event.timestamp = tied
        first = events.get_event_page(cursor, "alice", "admin", 2)
        second = events.get_event_page(first["next_cursor"], "alice", "admin", 2)
        third = events.get_event_page(second["next_cursor"], "alice", "admin", 2)
        assert [
            [e["payload"]["n"] for e in p["items"]] for p in [first, second, third]
        ] == [[0, 1], [2, 3], [4]]
        assert [p["has_more"] for p in [first, second, third]] == [True, True, False]
        assert (
            events.get_event_page(third["next_cursor"], "alice", "admin")["items"] == []
        )
        assert (
            events.get_event_page(cursor, "bob", "admin")["reset_reason"]
            == "scope_changed"
        )
        assert (
            events.get_event_page(cursor, "alice", "viewer")["reset_reason"]
            == "scope_changed"
        )
    with TenantContext(OTHER):
        reset = events.get_event_page(cursor, "alice", "admin")
        assert reset["reset_reason"] == "scope_changed" and not reset["items"]


@pytest.mark.asyncio
async def test_retention_overflow_restart_and_recovery_boundary(monkeypatch):
    events = manager(monkeypatch)
    with TenantContext(ORG):
        initial = events.get_event_page(user_id="alice")
        assert initial["reset_required"] and initial["reset_reason"] == "initial"
        for n in range(1001):
            await events.emit_event("test", {"n": n})
        assert len(events.event_history) == 1000
        reset = events.get_event_page(initial["next_cursor"], "alice")
        assert reset["reset_reason"] == "history_lost"
        await events.emit_event("during-snapshot", {})
        page = events.get_event_page(reset["next_cursor"], "alice")
        assert [e["type"] for e in page["items"]] == ["during-snapshot"]
        restarted = manager(monkeypatch).get_event_page(page["next_cursor"], "alice")
        assert restarted["reset_reason"] == "process_changed"
        for event in events.event_history:
            event.timestamp -= timedelta(seconds=301)
        expired = events.get_event_page(reset["next_cursor"], "alice")
        assert not events.event_history and expired["reset_required"]
        import core.realtime as module

        now = module.time.time()
        monkeypatch.setattr(module.time, "time", lambda: now + 301)
        assert (
            events.get_event_page(page["next_cursor"], "alice")["reset_reason"]
            == "cursor_expired"
        )


@pytest.mark.asyncio
async def test_filtered_events_never_leak_and_legacy_utc(monkeypatch):
    events = manager(monkeypatch)
    with TenantContext(ORG):
        cursor = events.get_event_page(user_id="alice", role="viewer")["next_cursor"]
        await events.emit_event("private", {}, user_id="bob")
        await events.emit_event("admin", {}, role="admin")
        await events.emit_event("visible", {})
        page = events.get_event_page(cursor, "alice", "viewer", 1)
        assert [e["type"] for e in page["items"]] == ["visible"] and not page[
            "has_more"
        ]
        since = datetime.now(timezone(timedelta(hours=2))) - timedelta(seconds=10)
        assert len(events.get_events_since(since, user_id="alice", role="viewer")) == 1
        with pytest.raises(ValueError):
            events.get_events_since(datetime.now())
        for invalid in ["bad", "e30", "W10", page["next_cursor"][:-3] + "abc"]:
            with pytest.raises(ValueError):
                events.get_event_page(invalid, "alice", "viewer")


@pytest.mark.asyncio
async def test_http_contract_timestamp_policy_and_cursor(monkeypatch):
    events = manager(monkeypatch)
    monkeypatch.setattr(routes, "realtime", events)
    app = FastAPI()
    app.include_router(routes.router)

    async def identity():
        return SimpleNamespace(id="alice", role="admin")

    app.dependency_overrides[get_current_user] = identity
    schema = app.openapi()
    response = schema["paths"]["/api/v1/updates"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert len(response["anyOf"]) == 2
    assert (
        schema["components"]["schemas"]["RealtimePage"]["properties"]["next_cursor"][
            "type"
        ]
        == "string"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test.invalid"
    ) as client:
        with TenantContext(ORG):
            for value in ["bad", "", "2026-11-08", "2026-11-08T12:00:00"]:
                assert (
                    await client.get("/api/v1/updates", params={"since": value})
                ).status_code == 400
            for value in ["2026-11-08T12:00:00Z", "2026-11-08T14:00:00+02:00"]:
                assert (
                    await client.get("/api/v1/updates", params={"since": value})
                ).json() == []
            page = (await client.get("/api/v1/updates?contract=2")).json()
            assert (
                page["delivery"] == "best_effort" and page["retention_seconds"] == 300
            )
            assert page["reset_required"]
            assert (
                await client.get(
                    "/api/v1/updates",
                    params={"contract": 2, "cursor": page["next_cursor"]},
                )
            ).json()["reset_required"] is False
            assert (
                await client.get("/api/v1/updates?contract=2&since=bad")
            ).status_code == 400
            assert (await client.get("/api/v1/updates?cursor=bad")).status_code == 400


@pytest.mark.asyncio
async def test_polling_refusals_have_stable_codes_and_match_error_schema(monkeypatch):
    import copy
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator

    corpus = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "tests/fixtures/operator-contract/realtime-errors.json"
        ).read_text()
    )
    events = manager(monkeypatch)
    monkeypatch.setattr(routes, "realtime", events)
    app = FastAPI()
    app.include_router(routes.router)

    async def identity():
        return SimpleNamespace(id="alice", role="admin")

    app.dependency_overrides[get_current_user] = identity
    schema = app.openapi()
    schema = copy.deepcopy(schema)
    schema["$ref"] = (
        "#/paths/~1api~1v1~1updates/get/responses/400/content/application~1json/schema"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test.invalid"
    ) as client:
        with TenantContext(ORG):
            for case in corpus["cases"]:
                response = await client.get("/api/v1/updates", params=case["query"])
                assert response.status_code == case["status"]
                assert response.json() == case["body"]
                Draft202012Validator(schema).validate(response.json())
            # Cursor contents are never reflected through arbitrary ValueErrors.
            monkeypatch.setattr(
                events,
                "get_event_page",
                lambda **kwargs: (_ for _ in ()).throw(
                    ValueError("private-cursor-control")
                ),
            )
            response = await client.get(
                "/api/v1/updates",
                params={"contract": 2, "cursor": "private-cursor-control"},
            )
            assert response.json()["detail"]["code"] == "realtime_cursor_invalid"
            assert "private-cursor-control" not in response.text
