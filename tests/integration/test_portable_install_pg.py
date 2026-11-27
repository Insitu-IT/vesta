"""The same fresh installer shipped in the OKD migration Job, on disposable PG."""

import uuid

import pytest
from sqlalchemy import inspect, text

from core.portable_install import (
    install_empty,
    grant_restored,
    transition_managed_files,
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
        installation_id = connection.scalar(
            text("SELECT installation_id FROM storage_configuration_clock WHERE slot=1")
        )
        options = dict(
            runtime_role=role,
            expected_database=url.database,
            installation_id=installation_id,
        )
        with pytest.raises(RuntimeError, match="observed database installation UUID"):
            transition_managed_files(connection, **{**options, "installation_id": None})
        for rollback, revision in (
            (True, "backup_admission_pause"),
            (False, "managed_file_backups"),
        ):
            changed = transition_managed_files(connection, **options, rollback=rollback)
            assert changed["revision"] == revision
            tables = set(inspect(connection).get_table_names())
            assert ("file_backups" in tables) is not rollback
            assert ("file_schedules" in tables) is not rollback
            assert (
                connection.execute(
                    text("SELECT id,name FROM organizations ORDER BY id")
                ).all()
                == organizations
            )
            if rollback:
                with pytest.raises(RuntimeError, match="transition source"):
                    transition_managed_files(connection, **options, rollback=True)
            else:
                assert (
                    transition_managed_files(connection, **options)["revision"]
                    == revision
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
