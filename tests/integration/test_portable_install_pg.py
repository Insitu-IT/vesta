"""The same fresh installer shipped in the OKD migration Job, on disposable PG."""

import uuid

import pytest
from sqlalchemy import inspect, text

from core.portable_install import (
    install_empty,
    grant_restored,
    transition_operation_safety,
)
from core.tenant_database import assert_non_bypass_role
from tests.integration.test_schema_parity_pg import database


def test_fresh_portable_install_and_nonowner_runtime():
    with database() as (url, engine), engine.begin() as connection:
        role = "portable_" + uuid.uuid4().hex
        connection.execute(text(f'CREATE ROLE "{role}" LOGIN NOINHERIT'))
        result = install_empty(
            connection, runtime_role=role, expected_database=url.database
        )
        assert result["runtime_role"] == role
        assert "backups" in inspect(connection).get_table_names()
        organizations = connection.execute(
            text("SELECT id,name FROM organizations ORDER BY id")
        ).all()
        options = dict(runtime_role=role, expected_database=url.database)
        for rollback, revision, prior in (
            (True, "operator_requests", "operator_requests"),
            (False, "backup_admission_pause", "operator_requests"),
            (True, "verification_budget", "verification_budget"),
            (False, "backup_admission_pause", "verification_budget"),
            (True, "storage_upload_progress", "storage_upload_progress"),
            (False, "backup_admission_pause", "storage_upload_progress"),
            (True, "backup_verification", "backup_verification"),
            (False, "backup_admission_pause", "backup_verification"),
        ):
            changed = transition_operation_safety(
                connection,
                **options,
                rollback=rollback,
                rollback_revision=prior,
            )
            assert changed["revision"] == revision
            columns = {c["name"] for c in inspect(connection).get_columns("backups")}
            assert ("storage_progress" in columns) is (
                revision != "backup_verification"
            )
            columns = {
                c["name"]
                for c in inspect(connection).get_columns("backup_verifications")
            }
            assert ("verification_admission_budget" in columns) is (
                revision not in {"backup_verification", "storage_upload_progress"}
            )
            assert (
                connection.execute(
                    text("SELECT id,name FROM organizations ORDER BY id")
                ).all()
                == organizations
            )
            with pytest.raises(RuntimeError, match="transition source"):
                transition_operation_safety(
                    connection, **options, rollback=rollback, rollback_revision=prior
                )
        endpoint = next(
            column
            for column in inspect(connection).get_columns("agents")
            if column["name"] == "ip_address"
        )
        assert endpoint["type"].length == 255
        connection.execute(text(f'SET LOCAL ROLE "{role}"'))
        assert_non_bypass_role(connection)
        assert not connection.scalar(
            text(
                "SELECT has_table_privilege(current_user,'storage_lineage_generations','INSERT')"
            )
        )
        assert connection.scalar(
            text(
                "SELECT has_function_privilege(current_user,'vnbui_publish_storage_generation(text,text,text,text)','EXECUTE')"
            )
        )
        connection.execute(text("RESET ROLE"))
        connection.execute(text(f'REVOKE SELECT ON public.users FROM "{role}"'))
        grant_restored(connection, runtime_role=role, expected_database=url.database)
        assert connection.scalar(
            text("SELECT has_table_privilege(:role,'users','SELECT')"), {"role": role}
        )
        with pytest.raises(RuntimeError, match="empty public schema"):
            install_empty(connection, runtime_role=role, expected_database=url.database)
        # Role creation is rolled back along with this disposable test database.
        connection.rollback()


@pytest.mark.parametrize(
    "hazard", ["same_role", "wrong_database", "unsafe_role", "existing_object"]
)
def test_install_refuses_ambiguous_or_unsafe_target(hazard):
    with database() as (url, engine), engine.begin() as connection:
        role = "portable_" + uuid.uuid4().hex
        connection.execute(text(f'CREATE ROLE "{role}" LOGIN NOINHERIT'))
        expected = url.database
        if hazard == "same_role":
            role = connection.scalar(text("SELECT current_user"))
        elif hazard == "wrong_database":
            expected = "not_this_database"
        elif hazard == "unsafe_role":
            connection.execute(text(f'ALTER ROLE "{role}" CREATEDB'))
        else:
            connection.execute(text("CREATE TABLE retain_me(id integer)"))
        with pytest.raises(RuntimeError):
            install_empty(connection, runtime_role=role, expected_database=expected)
        assert "backups" not in inspect(connection).get_table_names()
        connection.rollback()
