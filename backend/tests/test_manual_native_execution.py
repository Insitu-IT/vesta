"""The native HTTP sender uses one committed intent and no legacy monitor."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from models import VM
from backend.tests import test_manual_kubevirt_execution as kubevirt_fixtures


@pytest.fixture
def native_case(db_session, session_factory, monkeypatch):
    owner, backup, calls, _ = kubevirt_fixtures.case.__wrapped__(
        db_session, session_factory, monkeypatch
    )
    db_session.get(VM, backup.vm_id).provider = "libvirt"
    db_session.commit()
    intent = dict(
        schema=1,
        org_id=backup.org_id,
        agent_id=db_session.get(VM, backup.vm_id).agent_id,
        backup_id=backup.id,
        attempt_id="native-attempt",
        source={},
    )

    def prepare(db, backup_id):
        calls.append(("native-intent", backup_id))
        return deepcopy(intent)

    monkeypatch.setattr("core.native_job.prepare_job", prepare)
    from core.native_inventory import digest

    ack = dict(
        status="accepted",
        backup_id=backup.id,
        attempt_id=intent["attempt_id"],
        intent_sha256=digest(intent),
    )
    owner.http_client.post.return_value = SimpleNamespace(
        status_code=202, json=lambda: ack
    )
    return owner, backup, calls, ack


@pytest.mark.asyncio
async def test_native_manual_dispatch_ack_is_exact_and_no_legacy_monitor(
    db_session, native_case
):
    owner, backup, calls, ack = native_case
    assert await owner.execute_backup(backup.id) == ack
    assert [call[0] for call in calls] == ["capacity", "native-intent", "native-intent"]
    assert (
        owner.http_client.post.call_args.kwargs["json"]["protocol"]
        == "vnbui-native-job/1"
    )
    db_session.refresh(backup)
    assert backup.status == "running" and not owner.monitoring_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "wrong-attempt", "not-accepted"])
async def test_native_uncertain_http_preserves_original_attempt(
    db_session, native_case, failure
):
    owner, backup, calls, ack = native_case
    if failure == "timeout":
        owner.http_client.post.side_effect = TimeoutError("lost response")
    elif failure == "wrong-attempt":
        ack["attempt_id"] = "different"
    else:
        owner.http_client.post.return_value.status_code = 423
    assert (await owner.execute_backup(backup.id))["status"] == "held"
    db_session.refresh(backup)
    assert backup.status == "pending" and not owner.monitoring_tasks
