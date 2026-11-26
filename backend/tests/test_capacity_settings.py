"""An installation admin can actually configure the persisted admission policy."""

from unittest.mock import MagicMock

import pytest

from core.settings_service import SettingsService


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"schema": 1, "revision": 1, "limit": 0, "maintenance": False},
        {"schema": True, "revision": 1, "limit": 1, "maintenance": False},
        {"schema": 1, "revision": 1, "limit": 1, "maintenance": "false"},
        {"schema": 1, "revision": 0, "limit": 1, "maintenance": False},
        {
            "schema": 1,
            "revision": 1,
            "limit": 1,
            "maintenance": False,
            "override": True,
        },
    ],
)
def test_bad_capacity_settings_are_refused_before_persistence(value):
    db = MagicMock()
    with pytest.raises(ValueError):
        SettingsService(db).validate_update({"backup.capacity_admission": value})
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_capacity_policy_has_explicit_limit_and_monotonic_revision(monkeypatch):
    prior = {"schema": 1, "revision": 4, "limit": 2, "maintenance": False}
    monkeypatch.setattr(
        SettingsService,
        "get",
        lambda _, key: prior if key == "backup.capacity_admission" else False,
    )
    service = SettingsService(MagicMock())
    assert (
        service.validate_update({"backup.capacity_admission": prior})[
            "backup.capacity_admission"
        ]
        == prior
    )
    with pytest.raises(ValueError, match="increased revision"):
        service.validate_update({"backup.capacity_admission": dict(prior, limit=3)})
    next_policy = dict(prior, revision=5, maintenance=True)
    assert (
        service.validate_update({"backup.capacity_admission": next_policy})[
            "backup.capacity_admission"
        ]
        == next_policy
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"schema": True, "revision": 1, "paused": False},
        {"schema": 1, "revision": 0, "paused": False},
        {"schema": 1, "revision": True, "paused": False},
        {"schema": 1, "revision": 2**63, "paused": False},
        {"schema": 1, "revision": 1, "paused": "false"},
        {"schema": 1, "revision": 1, "paused": False, "maintenance": False},
    ],
)
def test_invalid_separate_admission_pause_never_persists(value):
    db = MagicMock()
    with pytest.raises(ValueError):
        SettingsService(db).validate_update({"backup.admission_pause": value})
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_admission_pause_revision_does_not_change_maintenance(monkeypatch):
    prior = {"schema": 1, "revision": 4, "paused": False}
    monkeypatch.setattr(
        SettingsService,
        "get",
        lambda _, key: prior if key == "backup.admission_pause" else False,
    )
    service = SettingsService(MagicMock())
    assert service.validate_update({"backup.admission_pause": prior}) == {
        "backup.admission_pause": prior,
    }
    with pytest.raises(ValueError, match="increased revision"):
        service.validate_update({"backup.admission_pause": dict(prior, paused=True)})
    paused = dict(prior, revision=5, paused=True)
    assert service.validate_update({"backup.admission_pause": paused}) == {
        "backup.admission_pause": paused,
    }
