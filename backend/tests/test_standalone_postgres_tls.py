"""Standalone tools must enforce customer TLS before any engine can connect."""

from argparse import Namespace
from contextlib import nullcontext
import importlib
from pathlib import Path
import runpy
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from config import settings
from core import schema_parity
from core.postgres_profile import CustomerPostgresPrerequisiteError

ENTRYPOINTS = (
    "alembic",
    "schema_parity",
    "transition_preflight",
    "transition_stages",
    "legacy_capacity_review",
    "modern_capacity_review",
    "restore_cleanup_review",
)


class EngineCaptured(RuntimeError):
    pass


def alembic_context(monkeypatch, supplied=None):
    from alembic import context

    config = SimpleNamespace(
        attributes={} if supplied is None else {"connection": supplied},
        config_file_name=None,
        config_ini_section="alembic",
        set_main_option=lambda *args: None,
        get_section=lambda *args: {"sqlalchemy.url": settings.database_url},
    )
    monkeypatch.setattr(context, "config", config, raising=False)
    monkeypatch.setattr(context, "is_offline_mode", lambda: False)
    monkeypatch.setattr(context, "configure", MagicMock())
    monkeypatch.setattr(context, "begin_transaction", nullcontext)
    monkeypatch.setattr(context, "run_migrations", MagicMock())
    return context


def invoke(name, url, factory, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "database_url", url)
    if name == "alembic":
        alembic_context(monkeypatch)
        monkeypatch.setattr("sqlalchemy.engine_from_config", factory)
        runpy.run_path(str(Path(schema_parity.__file__).parents[1] / "alembic/env.py"))
    elif name == "schema_parity":
        monkeypatch.setattr("sqlalchemy.create_engine", factory)
        runpy.run_module("core.schema_parity", run_name="__main__")
    elif name == "transition_preflight":
        module = importlib.import_module("core." + name)
        monkeypatch.setattr(module, "create_engine", factory)
        module.preflight(url, "probe_runtime")
    elif name == "transition_stages":
        module = importlib.import_module("core." + name)
        monkeypatch.setattr(module, "create_engine", factory)
        monkeypatch.setattr(
            module, "migration_identity", lambda: ("reviewed", "a" * 64, None)
        )
        module.run_stage(
            url,
            Namespace(
                stage="parity",
                expected_head="reviewed",
                expected_migrations_sha256="a" * 64,
            ),
        )
    else:
        module = importlib.import_module("core." + name)
        monkeypatch.setattr(module, "create_engine", factory)
        monkeypatch.setattr(module, "validate", lambda _: [])
        monkeypatch.setenv("DATABASE_URL", url)
        plan = tmp_path / "review.json"
        plan.write_text("{}")
        monkeypatch.setattr(
            "sys.argv", [name, "--plan", str(plan), "--database", "probe"]
        )
        module.main()


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize(
    "url",
    [
        "postgresql://probe@db.invalid/probe?sslmode=require",
        "postgresql://probe@db.invalid/probe?sslmode=disable",
        "postgresql:///probe?host=/var/run/postgresql&sslmode=verify-full",
        "postgresql://probe@db.invalid/probe?gssencmode=require&sslmode=verify-full",
        "postgresql:///probe?sslmode=verify-full",
    ],
)
def test_customer_refuses_unsafe_transport_before_engine(
    monkeypatch, tmp_path, entrypoint, url
):
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/probe-ca.crt")
    factory = MagicMock(side_effect=EngineCaptured)
    with pytest.raises((CustomerPostgresPrerequisiteError, SystemExit)):
        invoke(entrypoint, url, factory, monkeypatch, tmp_path)
    factory.assert_not_called()


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_customer_requires_an_explicit_ca_before_engine(
    monkeypatch, tmp_path, entrypoint
):
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)
    factory = MagicMock(side_effect=EngineCaptured)
    with pytest.raises((CustomerPostgresPrerequisiteError, SystemExit)):
        invoke(
            entrypoint,
            "postgresql://probe@db.invalid/probe?sslmode=verify-full",
            factory,
            monkeypatch,
            tmp_path,
        )
    factory.assert_not_called()


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("profile", ["full", "customer-postgresql"])
def test_profile_arguments_preserve_url_options_and_existing_timeouts(
    monkeypatch, tmp_path, entrypoint, profile
):
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", profile)
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/probe-ca.crt")
    mode = "require" if profile == "full" else "verify-full"
    url = (
        "postgresql://probe:p%40ss@db.invalid/probe?sslmode="
        + mode
        + "&application_name=probe&options=-c%20statement_timeout%3D1s"
    )
    factory = MagicMock(side_effect=EngineCaptured)
    with pytest.raises((EngineCaptured, SystemExit)):
        invoke(entrypoint, url, factory, monkeypatch, tmp_path)
    factory.assert_called_once()
    actual_url = factory.call_args.args[0]
    if entrypoint == "alembic":
        actual_url = actual_url["sqlalchemy.url"]
    assert actual_url == url
    expected = {"connect_timeout": 10} if entrypoint.startswith("transition_") else {}
    if profile == "customer-postgresql":
        expected.update(
            sslmode="verify-full",
            sslrootcert="/trust/probe-ca.crt",
            gssencmode="disable",
        )
    assert factory.call_args.kwargs["connect_args"] == expected


def test_alembic_preserves_supplied_owner_transaction(monkeypatch):
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setattr(
        settings, "database_url", "postgresql:///unused?sslmode=disable"
    )
    supplied = object()
    context = alembic_context(monkeypatch, supplied)
    factory = MagicMock(side_effect=EngineCaptured)
    monkeypatch.setattr("sqlalchemy.engine_from_config", factory)
    runpy.run_path(str(Path(schema_parity.__file__).parents[1] / "alembic/env.py"))
    factory.assert_not_called()
    assert context.configure.call_args.kwargs["connection"] is supplied
    context.run_migrations.assert_called_once()
