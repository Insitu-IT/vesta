import json
from types import SimpleNamespace

import pytest

from core import backup_admission_pause as pause
from core.backup_service import BackupService
from models import SettingV3
from .conftest import make_agent, make_vm


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        {"schema": 1, "revision": 1, "paused": "false"},
        {"schema": 1, "revision": True, "paused": False},
        {"schema": 1, "revision": 2**63, "paused": False},
        {"schema": 1, "revision": 1, "paused": False, "extra": True},
    ],
)
def test_invalid_pause_is_unknown_not_open(monkeypatch, value):
    monkeypatch.setattr(
        pause,
        "read_configuration",
        lambda *a: [SimpleNamespace(value=json.dumps(value))],
    )
    with pytest.raises(ValueError, match="policy unavailable"):
        pause.new_backup_admission_paused(None)


def test_absent_pause_retains_capacity_policy_behavior(monkeypatch):
    monkeypatch.setattr(pause, "read_configuration", lambda *a: [])
    assert pause.new_backup_admission_paused(None) is False


@pytest.mark.parametrize(
    "value,code",
    [
        ({"schema": 1, "revision": 1, "paused": True}, "backup_admission_paused"),
        (
            {"schema": 1, "revision": 1, "paused": None},
            "backup_admission_policy_unavailable",
        ),
    ],
)
def test_manual_preflight_has_stable_pause_reason_without_creating_work(
    db_session, value, code
):
    vm = make_vm(db_session, make_agent(db_session))
    db_session.add(
        SettingV3(
            key="backup.admission_pause", value=json.dumps(value), value_type="json"
        )
    )
    db_session.commit()
    allowed, error, status = BackupService(db_session).can_start_backup(
        vm.id, check_maintenance=False, check_concurrent=False
    )
    assert not allowed and status == 409 and error["code"] == code
    assert not db_session.new and not db_session.dirty
