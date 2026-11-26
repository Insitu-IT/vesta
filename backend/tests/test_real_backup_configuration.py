"""A missing execution flag must not manufacture completed backup records."""

import importlib

import pytest
from pydantic import ValidationError

from config import Settings


def test_missing_execution_flag_defaults_to_real(monkeypatch):
    monkeypatch.delenv("USE_REAL_BACKUP_EXECUTOR", raising=False)
    assert Settings(_env_file=None).use_real_backup_executor is True


@pytest.mark.parametrize("value", ["true", "TRUE", "1"])
def test_explicit_real_execution_is_supported(monkeypatch, value):
    monkeypatch.setenv("USE_REAL_BACKUP_EXECUTOR", value)
    assert Settings(_env_file=None).use_real_backup_executor is True


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "", "simulation"])
def test_disabled_or_invalid_execution_refuses_configuration(monkeypatch, value):
    monkeypatch.setenv("USE_REAL_BACKUP_EXECUTOR", value)
    with pytest.raises(ValidationError, match="use_real_backup_executor"):
        Settings(_env_file=None)


def test_direct_settings_cannot_opt_into_simulation():
    with pytest.raises(ValidationError, match="normal installations require real"):
        Settings(_env_file=None, use_real_backup_executor=False)


@pytest.mark.parametrize(
    "module", ["app", "scheduler", "routers.backups", "routers.bulk"]
)
def test_all_product_dispatch_paths_use_validated_setting(module):
    assert importlib.import_module(module).USE_REAL_BACKUP_EXECUTOR is True
