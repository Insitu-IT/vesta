"""Operator CLI controls; database behavior is in restricted-PG CI."""

import json
from unittest.mock import MagicMock

import pytest

from core import transition_preflight as subject


def test_object_inventory_resolves_trigger_contract_once_per_inspection(monkeypatch):
    from core import transition_contract as contract

    connection = MagicMock()
    functions = [
        {"proname": name, "pronargs": 0, "trigger": trigger, "prosecdef": False}
        for name, trigger in (("first", True), ("second", True), ("first", False))
    ]
    connection.execute.return_value.mappings.return_value.all.side_effect = [
        [],
        functions,
    ]
    lookup = MagicMock(return_value={"first", "second"})
    monkeypatch.setattr(contract, "trigger_functions", lookup)
    _, observed, unknown, missing = contract.object_inventory(connection)
    assert observed == functions
    assert unknown == 1  # A same-named non-trigger still requires disposition.
    assert missing > 0
    lookup.assert_called_once_with()


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"proname": "foreign_helper"},
        {"pronargs": 3},
        {"trigger": True},
        {"prosecdef": True},
        {"argument_types": "25 25 25 25"},
        {"returns_jsonb": False},
    ],
)
def test_scrub_helper_classification_requires_exact_invoker_signature(change):
    from core import transition_contract as contract

    row = dict(
        proname="vnbui_verification_expected",
        pronargs=4,
        trigger=False,
        prosecdef=False,
        argument_types="3802 25 25 25",
        returns_jsonb=True,
    )
    assert contract.function_signature(row) == "(jsonb,text,text,text)"
    row.update(change)
    assert bool(contract._verification_function(row)) is (not change)
    assert "vnbui_verification_guard" in contract.trigger_functions()


@pytest.mark.parametrize("stage", subject.STAGES[1:])
def test_mutating_stages_are_held_without_connection(monkeypatch, capsys, stage):
    def forbidden(*args, **kwargs):
        pytest.fail("Held stage opened a database connection")

    monkeypatch.setattr(subject, "create_engine", forbidden)
    assert subject.main([stage]) == 4
    assert json.loads(capsys.readouterr().out)["code"] == "STAGE_EXECUTION_HELD"


def test_connection_failure_is_redacted(monkeypatch, capsys):
    marker = "private-credential-and-provider-detail"
    monkeypatch.setenv("TEST_TRANSITION_DSN", marker)

    def failure(*args):
        raise RuntimeError(marker)

    monkeypatch.setattr(subject, "preflight", failure)
    assert (
        subject.main(
            ["preflight", "--dsn-env", "TEST_TRANSITION_DSN", "--runtime-role", marker]
        )
        == 3
    )
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
    assert json.loads(captured.out)["ready"] is False


def test_completed_inspection_is_not_transition_authorization(monkeypatch, capsys):
    monkeypatch.setenv("TEST_TRANSITION_DSN", "memory-only")
    monkeypatch.setattr(
        subject, "preflight", lambda *args: {"ready": False, "unmet": ["FINAL_SCHEMA"]}
    )
    assert (
        subject.main(
            [
                "preflight",
                "--dsn-env",
                "TEST_TRANSITION_DSN",
                "--runtime-role",
                "runtime",
            ]
        )
        == 4
    )
    assert json.loads(capsys.readouterr().out)["unmet"] == ["FINAL_SCHEMA"]


def test_readonly_precedes_every_inspection_and_rollback_precedes_return(monkeypatch):
    from core import transition_contract

    engine = MagicMock()
    connection = (
        engine.connect.return_value.execution_options.return_value.__enter__.return_value
    )
    events = []
    connection.execute.side_effect = lambda query: events.append(str(query))
    connection.rollback.side_effect = lambda: events.append("ROLLBACK")
    monkeypatch.setattr(subject, "create_engine", lambda *args, **kwargs: engine)

    def inspect(*args):
        events.append("INSPECT")
        return {"ready": False}

    monkeypatch.setattr(subject, "inspect_snapshot", inspect)
    monkeypatch.setattr(transition_contract, "inspect_contract", lambda *args: [])
    monkeypatch.setattr(transition_contract, "inspect_attribution", lambda *args: [])
    connection.scalar.return_value = 123
    assert subject.preflight("postgresql://unused/disposable", "runtime") == {
        "ready": False,
        "database_oid": 123,
        "object_acl_findings": [],
        "attribution_findings": [],
    }
    assert events == [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL statement_timeout = '10s'",
        "SET LOCAL lock_timeout = '2s'",
        "INSPECT",
        "ROLLBACK",
    ]
    engine.dispose.assert_called_once()


def test_migration_identity_is_single_head_and_deterministic():
    first = subject.migration_identity()
    assert first == subject.migration_identity()
    assert first[0] in first[2] and len(first[1]) == 64


def test_absent_managed_input_does_not_connect(monkeypatch, capsys):
    monkeypatch.delenv("TEST_TRANSITION_DSN", raising=False)
    factory = MagicMock(side_effect=AssertionError("No connection allowed"))
    monkeypatch.setattr(subject, "create_engine", factory)
    assert (
        subject.main(
            [
                "preflight",
                "--dsn-env",
                "TEST_TRANSITION_DSN",
                "--runtime-role",
                "runtime",
            ]
        )
        == 2
    )
    factory.assert_not_called()
    assert json.loads(capsys.readouterr().out)["code"] == "MANAGED_DSN_INPUT_ABSENT"


@pytest.mark.parametrize(
    "readonly,isolation", [("off", "repeatable read"), ("on", "read committed")]
)
def test_snapshot_refuses_unprotected_connection(readonly, isolation):
    connection = MagicMock()
    connection.dialect.name = "postgresql"
    connection.scalar.side_effect = [readonly, isolation]
    with pytest.raises(ValueError):
        subject.inspect_snapshot(connection, "runtime")


def stage_arguments(stage="migration"):
    return [
        stage,
        "--runtime-role",
        "runtime",
        "--migrator-role",
        "owner",
        "--database",
        "disposable",
        "--database-oid",
        "123",
        "--expected-head",
        "candidate",
        "--expected-migrations-sha256",
        "a" * 64,
        "--dsn-env",
        "TEST_TRANSITION_DSN",
    ]


@pytest.mark.parametrize("stage", ["migration", "current-grants", "default-grants"])
def test_explicit_mutation_opt_in_precedes_connection(monkeypatch, capsys, stage):
    from core import transition_stages

    run = MagicMock(side_effect=AssertionError("No effects"))
    monkeypatch.setattr(transition_stages, "run_stage", run)
    monkeypatch.setenv("TEST_TRANSITION_DSN", "memory-only")
    assert subject.main(stage_arguments(stage)) == 4
    run.assert_not_called()
    assert not json.loads(capsys.readouterr().out)["ready"]


def test_stage_uncertain_commit_never_acknowledges_or_discloses(monkeypatch, capsys):
    import logging
    import sys
    from core import transition_stages

    marker = "private-connection-row-and-credential"
    monkeypatch.setenv("TEST_TRANSITION_DSN", marker)

    def noisy_failure(*args):
        print(marker)
        print(marker, file=sys.stderr)
        logging.critical(marker)
        raise RuntimeError(marker)

    run = MagicMock(side_effect=noisy_failure)
    monkeypatch.setattr(transition_stages, "run_stage", run)
    assert subject.main(stage_arguments() + ["--execute"]) == 3
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
    assert (
        json.loads(captured.out)["code"]
        == "STAGE_OUTCOME_UNKNOWN_INSPECT_BEFORE_RESTART"
    )
    assert run.call_count == 1  # No automatic retry after uncertainty.


def test_stage_success_is_never_cutover_authority(monkeypatch, capsys):
    from core import transition_stages

    monkeypatch.setenv("TEST_TRANSITION_DSN", "memory-only")
    monkeypatch.setattr(
        transition_stages,
        "run_stage",
        lambda *args: {"stage_pass": True, "ready": False},
    )
    assert subject.main(stage_arguments() + ["--execute"]) == 0
    assert json.loads(capsys.readouterr().out) == {"stage_pass": True, "ready": False}


def test_wrong_migration_digest_refuses_before_engine(monkeypatch):
    from argparse import Namespace
    from core import transition_stages

    engine = MagicMock(side_effect=AssertionError("No connection"))
    monkeypatch.setattr(transition_stages, "create_engine", engine)
    with pytest.raises(RuntimeError, match="migration identity"):
        transition_stages.run_stage(
            "memory-only",
            Namespace(
                stage="migration",
                expected_head="wrong",
                expected_migrations_sha256="0" * 64,
            ),
        )
    engine.assert_not_called()


@pytest.mark.parametrize(
    "url", ["sqlite:///must-not-be-created.db", "mysql://unused/test"]
)
def test_non_postgres_preflight_refuses_before_engine(monkeypatch, url):
    engine = MagicMock(side_effect=AssertionError("No connection"))
    monkeypatch.setattr(subject, "create_engine", engine)
    with pytest.raises(ValueError, match="PostgreSQL"):
        subject.preflight(url, "runtime")
    engine.assert_not_called()


@pytest.mark.parametrize(
    "actual",
    [
        ("db", 123, "owner", "other"),
        ("db", 999, "owner", "owner"),
        ("other", 123, "owner", "owner"),
        ("db", 123, "other", "owner"),
    ],
)
def test_database_and_actual_session_identity_binding(actual):
    from argparse import Namespace
    from core.transition_stages import bind_connection

    connection = MagicMock()
    args = Namespace(database="db", database_oid=123, migrator_role="owner")
    connection.execute.return_value.one.return_value = actual
    with pytest.raises(RuntimeError, match="identity differs"):
        bind_connection(connection, args)
    connection.execute.return_value.one.return_value = ("db", 123, "owner", "owner")
    bind_connection(connection, args)
