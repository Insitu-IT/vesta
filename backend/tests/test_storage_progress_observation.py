"""Progress survives heartbeats but cannot acquire transaction authority."""

import asyncio
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.storage_progress_observation import observe_storage_progress
from .test_storage_hold_observation import held  # noqa: F401


@pytest.fixture
def uploading(db_session, request):
    agent, row, claim, _ = request.getfixturevalue("held")
    expected = deepcopy(claim.expected_plan)
    expected["transaction"]["plan"]["artifacts"] = [
        {"role": "volume_payload", "ciphertext_max": 256 << 20},
        {"role": "volume_manifest", "ciphertext_max": 16 << 20},
    ]
    claim.expected_plan = expected
    row.status = "pending"
    db_session.commit()
    return (
        agent,
        row,
        claim,
        dict(
            type="storage_transaction_progress",
            schema=1,
            backup_id=row.id,
            reservation_id=claim.id,
            plan_sha256="a" * 64,
            phase="uploading",
            bytes_transferred=8 << 20,
            total_bytes=64 << 20,
        ),
    )


def test_durable_snapshot_repeats_and_never_publishes(db_session, uploading):
    agent, row, claim, event = uploading
    custody = (
        row.capacity_state,
        row.capacity_id,
        row.capacity_release,
        row.completed_at,
        row.size_bytes,
        row.storage_path,
        claim.state,
        deepcopy(claim.expected_plan),
        claim.prepared_receipt,
    )
    result = observe_storage_progress(db_session, agent, event)
    assert result["progress"] == 12 and result["status"] == "running"
    assert row.tags == {"preserve": "existing"}
    assert row.storage_progress["bytes_transferred"] == 8 << 20
    db_session.commit()
    assert not observe_storage_progress(db_session, agent, event)
    assert not db_session.dirty
    event["bytes_transferred"] = event["total_bytes"]
    event["phase"] = "finalizing"
    assert observe_storage_progress(db_session, agent, event)["progress"] == 99
    assert row.status == "running"
    assert (
        row.capacity_state,
        row.capacity_id,
        row.capacity_release,
        row.completed_at,
        row.size_bytes,
        row.storage_path,
        claim.state,
        claim.expected_plan,
        claim.prepared_receipt,
    ) == custody


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("backup_id", "foreign"),
        ("reservation_id", "foreign"),
        ("plan_sha256", "0" * 64),
        ("phase", "completed"),
        ("phase", []),
        ("bytes_transferred", True),
        ("bytes_transferred", -1),
        ("bytes_transferred", 65 << 20),
        ("total_bytes", 257 << 20),
        ("total_bytes", 2**64),
        ("total_bytes", None),
        ("extra", "unrecognized"),
    ],
)
def test_invalid_snapshot_ignored_without_writes(db_session, uploading, field, value):
    agent, row, _, event = uploading
    event[field] = value
    assert not observe_storage_progress(db_session, agent, event)
    assert row.status == "pending" and row.tags == {"preserve": "existing"}
    assert not db_session.dirty


@pytest.mark.parametrize("field", ["id", "org_id"])
def test_other_agent_or_tenant_cannot_report(db_session, uploading, field):
    agent, row, _, event = uploading
    other = SimpleNamespace(id=agent.id, org_id=agent.org_id)
    setattr(other, field, "foreign")
    assert not observe_storage_progress(db_session, other, event)
    assert row.status == "pending"


@pytest.mark.parametrize(
    "field,value",
    [
        ("backup_id", "foreign"),
        ("org_id", "foreign"),
        ("agent_id", "foreign"),
        ("reservation_id", "foreign"),
        ("plan_sha256", "0" * 64),
        ("plan", {"provider": "libvirt"}),
        ("plan", []),
    ],
)
def test_recorded_request_binding_required(db_session, uploading, field, value):
    agent, row, claim, event = uploading
    expected = deepcopy(claim.expected_plan)
    expected["transaction"][field] = value
    claim.expected_plan = expected
    db_session.commit()
    assert not observe_storage_progress(db_session, agent, event)
    assert row.status == "pending" and not db_session.dirty


@pytest.mark.parametrize(
    "field,value",
    [
        ("bytes_transferred", 0),
        ("total_bytes", 65 << 20),
        ("phase", "preparing"),
    ],
)
def test_delayed_snapshots_cannot_regress_progress(db_session, uploading, field, value):
    agent, row, _, event = uploading
    assert observe_storage_progress(db_session, agent, event)
    db_session.commit()
    event[field] = value
    assert not observe_storage_progress(db_session, agent, event)
    assert row.progress == 12 and row.status == "running" and not db_session.dirty


@pytest.mark.parametrize(
    "status,capacity,publication",
    [
        ("cleanup_required", "reserved", "reserved"),
        ("completed", "reserved", "reserved"),
        ("deleted", "reserved", "reserved"),
        ("running", "released", "reserved"),
        ("running", "reserved", "published"),
        ("running", "reserved", "cleanup_required"),
    ],
)
def test_held_or_terminal_custody_untouched(
    db_session, uploading, status, capacity, publication
):
    agent, row, claim, event = uploading
    row.status, row.capacity_state, claim.state = status, capacity, publication
    if capacity == "released":
        row.capacity_release = {"reason": "fixture"}
    db_session.commit()
    assert not observe_storage_progress(db_session, agent, event)
    assert (row.status, row.capacity_state, claim.state) == (
        status,
        capacity,
        publication,
    )
    assert not db_session.dirty


@pytest.mark.asyncio
async def test_event_collection_does_not_broadcast_before_commit(
    db_session, uploading, monkeypatch
):
    from routers.health import _process_agent_events

    agent, row, _, event = uploading
    broadcast = AsyncMock()
    monkeypatch.setattr("routers.health.websocket_manager.send_scoped", broadcast)
    updates = await _process_agent_events(agent, [event], db_session)
    assert updates == [
        {
            "backup_id": row.id,
            "status": "running",
            "progress": 12,
            "phase": "uploading",
            "bytes_transferred": 8 << 20,
            "total_bytes": 64 << 20,
        }
    ]
    broadcast.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("delivery", ["success", "error", "stalled"])
async def test_heartbeat_commits_before_bounded_notification(
    db_session, uploading, monkeypatch, delivery
):
    from routers import health

    agent, row, claim, event = uploading
    request = SimpleNamespace(json=AsyncMock(return_value={"events": [event]}))
    monkeypatch.setattr(health, "get_setting", lambda db, name, default: default)
    monkeypatch.setattr(
        health,
        "SettingsService",
        lambda db: SimpleNamespace(get_s3_config=lambda: None),
    )
    commits = []
    commit = db_session.commit

    def committed():
        commit()
        commits.append(True)

    monkeypatch.setattr(db_session, "commit", committed)
    timeout = asyncio.timeout
    monkeypatch.setattr(health.asyncio, "timeout", lambda seconds: timeout(0.01))
    notifications = []

    async def notify(message, org_id):
        assert commits == [True] and not db_session.dirty
        assert org_id == agent.org_id and message["payload"]["backup_id"] == row.id
        notifications.append(message)
        if delivery == "error":
            raise RuntimeError("socket unavailable")
        if delivery == "stalled":
            await asyncio.Event().wait()

    monkeypatch.setattr(health.websocket_manager, "send_scoped", notify)
    result = await asyncio.wait_for(
        health.agent_heartbeat(agent.id, request, agent=agent, db=db_session),
        timeout=1,
    )
    assert result["status"] == "ok" and len(notifications) == 1
    db_session.expire_all()
    assert row.progress == 12 and row.storage_progress["bytes_transferred"] == 8 << 20
    assert row.capacity_state == "reserved" and claim.state == "reserved"
