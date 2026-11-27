"""Migration-only fresh/upgrade acceptance. Every database here is disposable.

SCHEMA_PARITY_TEST_ADMIN_URL must explicitly select the test PostgreSQL service.
No test applies DDL to DATABASE_URL or calls ORM create_all.
"""

from contextlib import contextmanager
from pathlib import Path
import os
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from core.schema_parity import assert_schema_current, schema_differences
from models import (
    Agent,
    AgentAPIKey,
    AgentRegistrationKey,
    Backup,
    OrganizationDefault,
    OrchestratorAPIKey,
    Schedule,
    SettingV3,
    User,
    VM,
    VMGroup,
)

ROOT = Path(__file__).resolve().parents[2]
PREDECESSOR = "add_demo_rate_buckets"
EXPECTED_HEAD = "managed_file_backups"

# Independent acceptance contract, not imported from the migration under test.
TENANT_POLICY_TABLES = {
    "recovery_publications",
    "file_backups",
    "file_schedules",
    "operator_requests",
    "operator_dispatches",
    "agent_key_rotations",
    "users",
    "agents",
    "vms",
    "vm_groups",
    "backups",
    "schedules",
    "scheduler_principals",
    "scheduler_grants",
    "schedule_occurrences",
    "schedule_occurrence_members",
    "restores",
    "notification_rules",
    "backup_verifications",
    "saved_searches",
    "reports",
    "report_executions",
    "notification_logs",
    "encryption_keys",
    "s3_publications",
    "storage_configuration_generations",
    "storage_configuration_activations",
    "storage_capability_evidence",
    "storage_capability_qualifications",
    "storage_capability_revocations",
    "s3_upload_parts",
    "s3_upload_results",
    "s3_part_observation_scans",
    "s3_part_observation_pages",
    "oidc_login_states",
    "storage_lineage_generations",
    "storage_lineage_heads",
}
PARENT_POLICY_TABLES = {
    "activity_logs",
    "orchestrator_api_keys",
    "agent_registration_keys",
    "agent_api_keys",
    "agent_certificates",
    "vm_group_members",
    "backup_queue",
}
EXPECTED_POLICIES = {
    ("storage_configuration_clock", "configuration_clock_read"): "SELECT",
    ("storage_configuration_clock", "configuration_clock_write"): "UPDATE",
    **{(table, f"tenant_isolation_{table}"): "ALL" for table in TENANT_POLICY_TABLES},
    **{(table, "tenant_parent_scope"): "ALL" for table in PARENT_POLICY_TABLES},
    **{
        (table, "installation_administration"): "ALL"
        for table in ("settings_v3", "secrets_v3", "system_settings")
    },
    **{
        (table, "demo_storage"): "ALL"
        for table in ("demo_sessions", "demo_rate_buckets")
    },
    ("access_audit", "audit_read"): "SELECT",
    ("access_audit", "audit_append"): "INSERT",
    ("system_events", "event_read"): "SELECT",
    ("system_events", "event_append"): "INSERT",
}


def assert_current_policy_contract(connection):
    policies = connection.execute(
        text(
            "SELECT tablename,policyname,roles,cmd,qual,with_check,permissive "
            "FROM pg_policies WHERE schemaname='public'"
        )
    ).all()
    actual = {(row.tablename, row.policyname): row.cmd for row in policies}
    assert len(policies) == len(actual) == len(EXPECTED_POLICIES)
    assert actual == EXPECTED_POLICIES
    forced = dict(
        connection.execute(
            text(
                "SELECT relname,relrowsecurity AND relforcerowsecurity FROM pg_class "
                "WHERE relnamespace='public'::regnamespace AND relkind='r'"
            )
        ).all()
    )
    assert all(forced[table] for table, _ in EXPECTED_POLICIES)
    custody = next(row for row in policies if row.tablename == "oidc_login_states")
    assert list(custody.roles) == ["public"] and custody.permissive == "PERMISSIVE"

    # PostgreSQL's deparser adds casts/parentheses to this two-arm equality OR.
    def normalized(expression):
        return (
            "".join(expression.replace("::text", "").split())
            .replace("(", "")
            .replace(")", "")
        )

    predicate = (
        "org_id = NULLIF(current_setting('app.current_org', true), '')"
        " OR current_setting('app.platform_admin', true) = 'true'"
    )
    assert normalized(custody.qual) == normalized(predicate)
    assert custody.with_check == custody.qual
    result = next(row for row in policies if row.tablename == "s3_upload_results")
    assert normalized(result.qual) == normalized(
        "org_id = NULLIF(current_setting('app.current_org', true), '')"
    )
    assert result.with_check == result.qual
    for table in (
        "s3_part_observation_scans",
        "s3_part_observation_pages",
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
        "storage_configuration_generations",
        "storage_configuration_activations",
        "file_schedules",
        "file_backups",
    ):
        row = next(row for row in policies if row.tablename == table)
        assert normalized(row.qual) == normalized(result.qual)
        assert row.with_check == row.qual
    clock = {
        row.policyname: row
        for row in policies
        if row.tablename == "storage_configuration_clock"
    }
    assert clock["configuration_clock_read"].qual == "true"
    assert clock["configuration_clock_read"].with_check is None
    write = clock["configuration_clock_write"]
    assert normalized(write.qual) == normalized(
        "current_setting('app.platform_admin', true) = 'true'"
    )
    assert write.with_check == write.qual
    for row in clock.values():
        assert list(row.roles) == ["public"] and row.permissive == "PERMISSIVE"
    part = next(row for row in policies if row.tablename == "s3_upload_parts")
    assert normalized(part.qual) == normalized(
        "org_id = NULLIF(current_setting('app.current_org', true), '')"
    )
    assert part.with_check == part.qual


def assert_empty_forward_custody(connection):
    import uuid

    assert connection.scalar(text("""SELECT count(*) FROM s3_publications
      WHERE cleanup_intent IS NOT NULL OR cleanup_transaction_id IS NOT NULL
      OR cleanup_result IS NOT NULL""")) == 0

    clock = connection.execute(
        text("SELECT slot,installation_id,revision FROM storage_configuration_clock")
    ).one()
    assert clock.slot == clock.revision == 1
    assert uuid.UUID(clock.installation_id).version == 4
    for table in (
        "s3_part_observation_scans",
        "s3_part_observation_pages",
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
        "storage_configuration_generations",
        "storage_configuration_activations",
    ):
        assert connection.scalar(text("SELECT count(*) FROM " + table)) == 0
    assert connection.scalar(text("SELECT count(*) FROM s3_upload_results")) == 0
    assert connection.scalar(text("SELECT count(*) FROM s3_upload_parts")) == 0
    assert "oidc_login_states" in inspect(connection).get_table_names()
    assert (
        connection.execute(text("SELECT count(*) FROM oidc_login_states")).scalar_one()
        == 0
    )
    assert (
        connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == EXPECTED_HEAD
    )
    # Upgrading fixed-mode history must not manufacture automatic authority.
    assert (
        connection.scalar(
            text("SELECT count(*) FROM schedules WHERE backup_policy IS NOT NULL")
        )
        == 0
    )
    assert (
        connection.scalar(
            text("SELECT count(*) FROM backup_queue WHERE backup_decision IS NOT NULL")
        )
        == 0
    )
    # Every pre-existing backup retains unresolved custody, regardless of status.
    assert (
        connection.scalar(
            text(
                "SELECT count(*) FROM backups WHERE capacity_state <> 'legacy_held' OR capacity_id IS NULL OR capacity_reserved_at IS NULL OR capacity_policy_revision IS NOT NULL OR capacity_release IS NOT NULL"
            )
        )
        == 0
    )
    assert (
        connection.scalar(
            text(
                "SELECT count(*) FROM settings_v3 WHERE key='backup.capacity_admission'"
            )
        )
        == 0
    )
    # Forward migration adds no guessed authority to historical requests.
    assert (
        connection.execute(
            text(
                "SELECT count(*) FROM backups WHERE native_job_intent IS NOT NULL "
                "OR native_job_transaction_id IS NOT NULL OR native_inventory IS NOT NULL "
                "OR native_inventory_transaction_id IS NOT NULL"
            )
        ).scalar_one()
        == 0
    )
    for table in ("storage_lineage_generations", "storage_lineage_heads"):
        assert (
            connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
        )
    for table in ("backups", "backup_queue"):
        assert (
            connection.execute(
                text(
                    f"SELECT count(*) FROM {table} WHERE initiating_user_id IS NOT NULL"
                )
            ).scalar_one()
            == 0
        )
    function = connection.execute(
        text("SELECT pg_get_functiondef('vnbui_oidc_state_transition()'::regprocedure)")
    ).scalar_one()
    assert "OLD.expires_at > now() - interval '24 hours'" in function
    assert_current_policy_contract(connection)


@contextmanager
def database(*, template=None):
    admin_url = os.environ.get("SCHEMA_PARITY_TEST_ADMIN_URL")
    assert (
        admin_url
    ), "Set SCHEMA_PARITY_TEST_ADMIN_URL to a disposable PostgreSQL service"
    name = "vnbui_parity_" + uuid.uuid4().hex
    source = "template0"
    if template is not None:
        # Only a same-service, disposable fixture snapshot may be cloned.
        # Fresh-install/upgrade tests omit this argument and still run real DDL.
        parsed = make_url(template)
        assert make_url(admin_url).set(database="postgres") == parsed.set(
            database="postgres"
        )
        assert parsed.database.startswith("vnbui_parity_")
        suffix = parsed.database.removeprefix("vnbui_parity_")
        assert len(suffix) == 32 and uuid.UUID(suffix).hex == suffix
        source = parsed.database
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(
            text(f'CREATE DATABASE "{name}" TEMPLATE "{source}" ALLOW_CONNECTIONS true')
        )
    url = make_url(admin_url).set(database=name)
    engine = create_engine(url)
    try:
        yield url, engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def migrate(url, revision="head", org_id=None, check=True):
    args = [sys.executable, "-m", "alembic"]
    if org_id:
        args += ["-x", f"default_organization_id={org_id}"]
    args += ["upgrade", revision]
    result = subprocess.run(
        args,
        cwd=ROOT / "backend",
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)},
    )
    if check:
        assert result.returncode == 0, result.stderr
    return result


def test_modern_review_upgrade_from_already_applied_legacy_head():
    """An older installed predecessor gains the column in its own transaction."""
    with database() as (url, engine):
        migrate(url, "legacy_capacity_review")
        # Model a site that applied that revision before the fresh-install
        # column ordering fix. This database is disposable and has no backups.
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE backups DROP COLUMN capacity_modern_reviews")
            )
        migrate(url)
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT column_default FROM information_schema.columns "
                        "WHERE table_schema='public' AND table_name='backups' "
                        "AND column_name='capacity_modern_reviews'"
                    )
                )
                == "'[]'::jsonb"
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT to_regprocedure('public.vnbui_review_modern_capacity(jsonb)')"
                    )
                )
                is not None
            )


def test_registration_scope_and_kek_custody_migrations():
    with database() as (url, engine):
        migrate(url, "restore_cleanup_review")
        with engine.begin() as connection:
            org_id = connection.scalar(
                text("SELECT org_id FROM organization_defaults WHERE slot='oss'")
            )
            connection.execute(
                text(
                    "INSERT INTO users(id,org_id,username,password_hash,role) "
                    "VALUES ('scope-issuer',:org,'scope-issuer','test','admin')"
                ),
                {"org": org_id},
            )
            connection.execute(
                text(
                    "INSERT INTO agent_registration_keys"
                    "(id,name,key_hash,key_prefix,created_by,enabled,use_count) "
                    "VALUES ('old-key','old-key',:hash,'old-key','scope-issuer',true,0)"
                ),
                {"hash": "a" * 64},
            )
            for key_id, locations in (
                ("export-only", '["file-export"]'),
                ("import-only", '["imported"]'),
                ("mixed-custody", '["file-export", "external-vault"]'),
            ):
                connection.execute(
                    text(
                        "INSERT INTO encryption_keys"
                        "(id,org_id,name,key_hash,status,provider,backed_up,"
                        "backed_up_at,backed_up_locations) "
                        "VALUES (:id,:org,:id,:id,'rotated','local',true,now(),"
                        "CAST(:locations AS jsonb))"
                    ),
                    {"id": key_id, "org": org_id, "locations": locations},
                )
        migrate(url)
        with engine.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT agent_hostname,enabled FROM agent_registration_keys "
                    "WHERE id='old-key'"
                )
            ).one() == (None, False)
            custody = {
                row.id: row
                for row in connection.execute(
                    text(
                        "SELECT id,backed_up,backed_up_at,backed_up_locations "
                        "FROM encryption_keys WHERE id IN "
                        "('export-only','import-only','mixed-custody')"
                    )
                )
            }
            for key_id in ("export-only", "import-only"):
                assert custody[key_id].backed_up is False
                assert custody[key_id].backed_up_at is None
                assert custody[key_id].backed_up_locations == []
            assert custody["mixed-custody"].backed_up is True
            assert custody["mixed-custody"].backed_up_at is not None
            assert custody["mixed-custody"].backed_up_locations == ["external-vault"]
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE agent_registration_keys SET enabled=true WHERE id='old-key'"
                )
            )


def test_default_privileges_require_explicit_object_review():
    from core.runtime_grants import apply_default_runtime_grants

    with database() as (_, engine), engine.connect() as connection:
        transaction = connection.begin()
        try:
            role = "runtime_control_" + uuid.uuid4().hex
            connection.execute(text(f'CREATE ROLE "{role}" NOINHERIT'))
            owner = connection.execute(text("SELECT current_user")).scalar_one()
            quote = connection.dialect.identifier_preparer.quote
            for scope in ("", " IN SCHEMA public"):
                for objects in ("TABLES", "SEQUENCES", "FUNCTIONS"):
                    connection.execute(
                        text(
                            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quote(owner)}{scope} "
                            f"GRANT ALL ON {objects} TO {quote(role)}, PUBLIC"
                        )
                    )
            connection.execute(text("CREATE TABLE public.before_control(id int)"))
            assert connection.execute(
                text(
                    "SELECT has_table_privilege(:role,'public.before_control','SELECT')"
                ),
                {"role": role},
            ).scalar_one()
            apply_default_runtime_grants(connection, role)
            connection.execute(text("CREATE TABLE public.after_control(id int)"))
            connection.execute(text("CREATE SEQUENCE public.after_sequence"))
            connection.execute(
                text(
                    "CREATE FUNCTION public.after_function() RETURNS int LANGUAGE sql AS 'SELECT 1'"
                )
            )
            for predicate in (
                "has_table_privilege(:role,'public.after_control','SELECT')",
                "has_table_privilege(:role,'public.after_control','INSERT')",
                "has_sequence_privilege(:role,'public.after_sequence','USAGE')",
                "has_function_privilege(:role,'public.after_function()','EXECUTE')",
            ):
                assert not connection.execute(
                    text("SELECT " + predicate), {"role": role}
                ).scalar_one()
            # Default ACL changes do not repair existing objects.
            assert connection.execute(
                text(
                    "SELECT has_table_privilege(:role,'public.before_control','SELECT')"
                ),
                {"role": role},
            ).scalar_one()
        finally:
            transaction.rollback()  # Includes the disposable cluster role.


def test_runtime_preflight_rejects_privilege_paths():
    from core.tenant_database import assert_non_bypass_role

    with database() as (_, engine), engine.connect() as connection:
        transaction = connection.begin()
        try:
            role = "runtime_control_" + uuid.uuid4().hex
            parent = "parent_control_" + uuid.uuid4().hex
            quote = connection.dialect.identifier_preparer.quote
            target = quote(role)
            connection.execute(text(f"CREATE ROLE {target} NOINHERIT"))
            connection.execute(text(f"CREATE ROLE {quote(parent)}"))
            connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
            connection.execute(text(f"SET LOCAL ROLE {target}"))
            assert_non_bypass_role(connection)
            connection.execute(text("RESET ROLE"))
            for hazard in (
                f"GRANT {quote(parent)} TO {target}",
                f"ALTER ROLE {target} CREATEDB",
                f"ALTER ROLE {target} CREATEROLE",
                f"ALTER ROLE {target} INHERIT",
                f"ALTER ROLE {target} REPLICATION",
                f"GRANT CREATE ON SCHEMA public TO {target}",
                f"ALTER SCHEMA public OWNER TO {target}",
            ):
                with connection.begin_nested() as savepoint:
                    connection.execute(text(hazard))
                    connection.execute(text(f"SET LOCAL ROLE {target}"))
                    with pytest.raises(RuntimeError):
                        assert_non_bypass_role(connection)
                    connection.execute(text("RESET ROLE"))
                    savepoint.rollback()
            for definition, change in (
                (
                    "CREATE TABLE public.owned(id int)",
                    f"ALTER TABLE public.owned OWNER TO {target}",
                ),
                (
                    "CREATE SEQUENCE public.owned",
                    f"ALTER SEQUENCE public.owned OWNER TO {target}",
                ),
                (
                    "CREATE FUNCTION public.owned() RETURNS int LANGUAGE sql AS 'SELECT 1'",
                    f"ALTER FUNCTION public.owned() OWNER TO {target}",
                ),
            ):
                with connection.begin_nested() as savepoint:
                    connection.execute(text(definition))
                    connection.execute(text(change))
                    connection.execute(text(f"SET LOCAL ROLE {target}"))
                    with pytest.raises(RuntimeError):
                        assert_non_bypass_role(connection)
                    connection.execute(text("RESET ROLE"))
                    savepoint.rollback()
        finally:
            transaction.rollback()


def replay_forward_migration(connection):
    """Exercise upgrade() idempotence, not just Alembic's head no-op."""
    import importlib.util
    from unittest.mock import patch
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    spec = importlib.util.spec_from_file_location(
        "parity_migration", ROOT / "backend/alembic/versions/20260905_schema_parity.py"
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with Operations.context(MigrationContext.configure(connection)):
        with patch("alembic.context.get_x_argument", return_value={}):
            migration.upgrade()


@pytest.fixture(scope="module")
def fresh():
    with database() as (url, engine):
        migrate(url)
        yield url, engine


def test_fresh_migration_supports_active_orm_crud(fresh):
    url, engine = fresh
    with engine.connect() as connection:
        assert_schema_current(connection)
        assert_empty_forward_custody(connection)
        from core.table_scope import assert_classified

        assert_classified(
            set(inspect(connection).get_table_names()) - {"alembic_version"}
        )
    with Session(engine) as session:
        org = session.query(OrganizationDefault).one().org_id
        user = User(username="parity-admin", password_hash="test-only", role="admin")
        agent = Agent(hostname="parity-host", display_name="Display survives")
        session.add_all([user, agent])
        session.flush()
        vm = VM(name="parity-vm", agent_id=agent.id, uuid=str(uuid.uuid4()))
        group = VMGroup(name="parity-group", tags=["test"])
        session.add_all([vm, group])
        session.flush()
        group.vms.append(vm)
        backup = Backup(
            authority_kind="human",
            initiating_user_id=user.id,
            id="chain-control",
            vm_id=vm.id,
            size_bytes=5 * 1024**3,
            storage_path="s3://test/prefix",
            chain_id="chain-control",
            chain_position=0,
        )
        schedule = Schedule(
            name="parity-schedule", vm_group_id=group.id, cron_expression="0 0 * * *"
        )
        session.add_all(
            [
                backup,
                schedule,
                SettingV3(key="parity", value="retained"),
                AgentAPIKey(agent_id=agent.id, key_hash="a" * 64, key_prefix="a" * 8),
                AgentRegistrationKey(
                    name="registration",
                    agent_hostname="parity-agent",
                    created_by=user.id,
                    key_hash="b" * 64,
                    key_prefix="b" * 8,
                ),
                OrchestratorAPIKey(
                    name="orchestrator",
                    created_by=user.id,
                    key_hash="c" * 64,
                    key_prefix="c" * 8,
                ),
            ]
        )
        session.flush()
        for row in (user, agent, vm, group, backup, schedule):
            assert row.org_id == org
        session.expire_all()
        assert session.query(Backup).one().size_bytes == 5 * 1024**3
        assert session.query(Backup).one().storage_path == "s3://test/prefix"
        agent.display_name = "Updated"
        session.flush()
        assert session.get(Agent, agent.id).display_name == "Updated"
        session.delete(schedule)
        session.flush()
        assert session.query(Schedule).count() == 0
        session.rollback()


@pytest.mark.parametrize("ambiguous", [False, True])
def test_ruleless_notification_history_requires_unambiguous_owner(ambiguous):
    with database() as (url, engine):
        migrate(url, "oss_schema_parity")
        with engine.begin() as connection:
            original_org = connection.execute(
                text("SELECT id FROM organizations")
            ).scalar_one()
            connection.execute(
                text(
                    """INSERT INTO notification_logs
                (id,event_type,recipient,body) VALUES
                ('historical','backup_failure','synthetic@example.invalid','preserve me')"""
                )
            )
            if ambiguous:
                connection.execute(
                    text("INSERT INTO organizations(id,name) VALUES ('other','Other')")
                )
        result = migrate(url, check=False)
        if ambiguous:
            assert result.returncode != 0
            assert (
                "Unattributed notification history requires operator disposition"
                in result.stderr
            )
            with engine.connect() as connection:
                assert (
                    connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                    == "oss_schema_parity"
                )
                assert (
                    connection.execute(
                        text("SELECT body FROM notification_logs WHERE id='historical'")
                    ).scalar_one()
                    == "preserve me"
                )
        else:
            assert result.returncode == 0, result.stderr
            with engine.connect() as connection:
                assert connection.execute(
                    text(
                        "SELECT org_id,body FROM notification_logs WHERE id='historical'"
                    )
                ).one() == (original_org, "preserve me")


@pytest.mark.parametrize(
    "mutation",
    [
        "ALTER TABLE agents DROP COLUMN display_name",
        "ALTER TABLE backups ALTER COLUMN size_bytes TYPE INTEGER",
        "ALTER TABLE agents ALTER COLUMN config DROP NOT NULL",
        "ALTER TABLE agents ALTER COLUMN capabilities DROP DEFAULT",
        "ALTER TABLE backups DROP CONSTRAINT backups_vm_id_fkey",
        "ALTER TABLE orchestrator_api_keys DROP CONSTRAINT orchestrator_api_keys_key_hash_key",
        "DROP INDEX ix_activity_logs_action",
        "DROP INDEX ix_users_oidc_subject; CREATE UNIQUE INDEX ix_users_oidc_subject ON users(oidc_subject,oidc_issuer)",
        "ALTER TABLE demo_rate_buckets DROP CONSTRAINT demo_rate_buckets_pkey",
    ],
)
def test_parity_rejects_structural_drift(fresh, mutation):
    _, engine = fresh
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            assert_schema_current(connection)
            connection.execute(text(mutation))
            assert schema_differences(connection), mutation
            with pytest.raises(RuntimeError, match="schema differs"):
                assert_schema_current(connection)
        finally:
            transaction.rollback()


def seed_predecessor(connection):
    org = connection.execute(text("SELECT id FROM organizations")).scalar_one()
    for statement in (
        "INSERT INTO users(id,username,password_hash,role,org_id) VALUES ('user','upgrade-user','test-only','admin',:org)",
        "INSERT INTO agents(id,hostname,org_id) VALUES ('agent','upgrade-agent',:org)",
        "INSERT INTO vms(id,name,agent_id,uuid,org_id) VALUES ('vm','upgrade-vm','agent','stable-provider-identity',:org)",
        "INSERT INTO backups(id,vm_id,status,tags,retention_days,chain_id,chain_position,org_id) VALUES ('backup','vm','completed','{\"keep\":\"me\"}',30,'backup',0,:org)",
        "INSERT INTO vm_groups(id,name,tags,org_id) VALUES ('group','upgrade-group','[\"keep\"]',:org)",
        "INSERT INTO vm_group_members(vm_id,group_id) VALUES ('vm','group')",
        "INSERT INTO schedules(id,name,vm_group_id,cron_expression,org_id) VALUES ('schedule','upgrade-schedule','group','0 0 * * *',:org)",
        "INSERT INTO settings_v3(key,value) VALUES ('upgrade-setting','preserve-value')",
    ):
        connection.execute(text(statement), {"org": org})
    return org


@pytest.mark.parametrize(
    "shape", ["empty", "prior", "measured", "current", "ambiguous"]
)
def test_operator_preflight_readonly_shapes(shape):
    from core.transition_preflight import preflight

    with database() as (url, engine):
        if shape == "prior":
            migrate(url, PREDECESSOR)
            with engine.begin() as connection:
                seed_predecessor(connection)
        elif shape == "current":
            migrate(url)
        elif shape == "ambiguous":
            with engine.begin() as connection:
                connection.execute(
                    text("CREATE TABLE public.alembic_version(version_num text)")
                )
                connection.execute(
                    text(
                        "INSERT INTO public.alembic_version VALUES ('add_demo_rate_buckets'),('unknown')"
                    )
                )
        elif shape == "measured":
            raw = (ROOT / "tests/fixtures/deployed_schema_20260905.sql").read_text()
            sql = "\n".join(
                line for line in raw.splitlines() if not line.startswith("\\")
            )
            with engine.begin() as connection:
                connection.exec_driver_sql(sql)
                connection.execute(
                    text(
                        "INSERT INTO public.alembic_version VALUES ('add_demo_rate_buckets')"
                    )
                )

        def snapshot():
            with engine.connect() as connection:
                tables = inspect(connection).get_table_names(schema="public")
                quote = connection.dialect.identifier_preparer.quote
                return {
                    name: connection.execute(
                        text(
                            f"SELECT to_jsonb(t)::text FROM public.{quote(name)} t ORDER BY 1"
                        )
                    ).all()
                    for name in tables
                }

        before = snapshot()
        result = preflight(url, "absent_operator_preflight_runtime")
        assert snapshot() == before
        assert result["ready"] is False and result["unmet"]
        codes = {f["code"]: f.get("count") for f in result["findings"]}
        assert "RUNTIME_ROLE_ABSENT" in codes
        if shape == "empty":
            assert result["observed_shape"] == "empty"
        elif shape == "ambiguous":
            assert result["observed_shape"] == "unrecognized_or_ambiguous"
        elif shape == "current":
            assert result["observed_shape"] == "current_revision_unverified_parity"
            assert codes["UNKNOWN_PUBLIC_TABLES"] == 0
        else:
            assert (
                result["observed_shape"]
                == "measured_predecessor_revision_unverified_shape"
            )
        if shape == "measured":
            assert codes["ORGANIZATION_ROWS"] == 0
            assert "EXPLICIT_ATTRIBUTION_DECISION_REQUIRED" in codes


def test_operator_preflight_enforced_readonly_and_restricted_visibility():
    from core.transition_preflight import inspect_snapshot, preflight
    from core.tenant_database import assert_non_bypass_role
    from database import sync_engine as runtime_engine

    # This engine is the migration-built, separately provisioned runtime identity.
    # No application hooks: the operator command never boots the API.
    engine = create_engine(runtime_engine.url)
    with engine.connect().execution_options(
        isolation_level="REPEATABLE READ"
    ) as connection:
        with connection.begin():
            assert_non_bypass_role(connection)
            # Validation queries started this transaction; SET TRANSACTION must
            # precede data access, so use a new transaction for the actual observer.
            connection.rollback()
        with connection.begin():
            connection.execute(text("SET TRANSACTION READ ONLY"))
            role = connection.scalar(text("SELECT current_user"))
            report = inspect_snapshot(connection, role)
            codes = {f["code"]: f.get("count") for f in report["findings"]}
            assert codes["RUNTIME_UNSAFE_FLAGS"] == 0
            assert codes["RUNTIME_MEMBERSHIPS"] == 0
            assert codes["RUNTIME_OWNED_OBJECTS"] == 0
            assert "ATTRIBUTION_UNINSPECTED_OBSERVER_VISIBILITY" in codes
            with pytest.raises(Exception) as failure:
                connection.execute(
                    text("CREATE TABLE public.preflight_forbidden(id int)")
                )
            assert failure.value.orig.pgcode == "25006"
            connection.rollback()
    report = preflight(engine.url, role)
    assert report["ready"] is False
    engine.dispose()


def test_operator_preflight_redacted_collision_unknown_and_unsafe_role_findings():
    import json
    from core.transition_preflight import preflight

    marker = "private-fixture-value-not-for-report"
    with database() as (url, engine):
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE public.agent_api_keys(key_hash text)")
            )
            connection.execute(
                text("INSERT INTO public.agent_api_keys VALUES (:value),(:value)"),
                {"value": marker},
            )
            connection.execute(
                text('CREATE TABLE public."private-fixture-object"(id int)')
            )
            connection.execute(text("CREATE SEQUENCE public.private_fixture_sequence"))
            connection.execute(
                text("CREATE VIEW public.private_fixture_view AS SELECT 1 AS id")
            )
            role = connection.scalar(text("SELECT current_user"))
        result = preflight(url, role)
        assert marker not in json.dumps(result)
        assert "private-fixture-object" not in json.dumps(result)
        codes = {f["code"]: f.get("count") for f in result["findings"]}
        assert codes["AGENT_CREDENTIAL_COLLISION_GROUPS"] == 1
        assert codes["UNKNOWN_PUBLIC_TABLES"] == 1
        assert codes["PUBLIC_SEQUENCES_OBSERVED"] == 1
        assert codes["PUBLIC_OTHER_RELATIONS_UNCLASSIFIED"] == 1
        assert codes["RUNTIME_UNSAFE_FLAGS"] > 0
        assert codes["RUNTIME_OWNED_OBJECTS"] > 0
        assert codes["RUNTIME_UNSAFE_TABLE_GRANTS"] == 2
        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT count(*) FROM public.agent_api_keys"))
                == 2
            )


@contextmanager
def operator_stage_database():
    """Independent disposable database and LOGIN role, never the live role."""

    from argparse import Namespace
    from core.transition_preflight import migration_identity

    admin_url = os.environ.get("SCHEMA_PARITY_TEST_ADMIN_URL")
    assert admin_url, "Disposable PostgreSQL service required"
    role = "transition_" + uuid.uuid4().hex
    password = (
        uuid.uuid4().hex
    )  # Memory-only test login; not printed or returned in reports.
    admin = create_engine(admin_url, hide_parameters=True)
    with admin.begin() as connection:
        connection.execute(
            text(
                f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB '
                "NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD :password"
            ),
            {"password": password},
        )
    try:
        with database() as (url, engine):
            with engine.connect() as connection:
                owner = connection.scalar(text("SELECT current_user"))
                oid = connection.scalar(
                    text("SELECT oid FROM pg_database WHERE datname=current_database()")
                )
            head, digest, _ = migration_identity()
            args = Namespace(
                stage="migration",
                runtime_role=role,
                migrator_role=owner,
                database=url.database,
                database_oid=oid,
                expected_head=head,
                expected_migrations_sha256=digest,
                execute=True,
                default_organization_id=None,
            )
            yield url, url.set(username=role, password=password), engine, args
    finally:
        # The context above drops its exact disposable DB before cluster-role removal.
        with admin.begin() as connection:
            connection.execute(text(f'DROP ROLE "{role}"'))
        admin.dispose()


@pytest.mark.parametrize("shape", ["empty", "prior", "measured", "current"])
def test_operator_stages_migration_grants_restart_and_runtime_login(
    shape, monkeypatch, capsys
):
    import json
    from core.transition_preflight import main
    from core.transition_preflight import preflight
    from core.transition_stages import run_stage

    with operator_stage_database() as (url, runtime_url, engine, args):
        if shape == "prior":
            migrate(url, PREDECESSOR)
            with engine.begin() as connection:
                seed_predecessor(connection)
        elif shape == "measured":
            raw = (ROOT / "tests/fixtures/deployed_schema_20260905.sql").read_text()
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "\n".join(x for x in raw.splitlines() if not x.startswith("\\"))
                )
                connection.execute(
                    text(
                        "INSERT INTO public.alembic_version VALUES ('add_demo_rate_buckets')"
                    )
                )
        elif shape == "current":
            migrate(url)
        for stage in ("migration", "parity", "current-grants", "default-grants"):
            args.stage = stage
            first = run_stage(url, args)
            assert first["stage_pass"] and not first["ready"] and first["unmet"]
            assert run_stage(url, args) == first  # New engine/connection each time.
        report = preflight(url, args.runtime_role, args.migrator_role)
        assert all(f.get("count", 0) == 0 for f in report["object_acl_findings"])
        assert not any(
            "UNKNOWN" in f["code"] and "count" not in f
            for f in report["object_acl_findings"]
        )
        args.stage = "runtime-acceptance"
        assert run_stage(runtime_url, args)["stage_pass"]
        restricted = preflight(runtime_url, args.runtime_role, args.migrator_role)
        assert restricted["attribution_findings"] == [
            {"code": "FULL_ATTRIBUTION_UNKNOWN_VISIBILITY"}
        ]
        assert not restricted["ready"]
        monkeypatch.setenv(
            "TEST_OPERATOR_RUNTIME_DSN",
            runtime_url.render_as_string(hide_password=False),
        )
        capsys.readouterr()
        assert (
            main(
                [
                    "runtime-acceptance",
                    "--dsn-env",
                    "TEST_OPERATOR_RUNTIME_DSN",
                    "--runtime-role",
                    args.runtime_role,
                    "--migrator-role",
                    args.migrator_role,
                    "--database",
                    args.database,
                    "--database-oid",
                    str(args.database_oid),
                    "--expected-head",
                    args.expected_head,
                    "--expected-migrations-sha256",
                    args.expected_migrations_sha256,
                ]
            )
            == 0
        )
        captured = capsys.readouterr()
        assert json.loads(captured.out)["stage_pass"] is True
        assert runtime_url.password not in captured.out + captured.err
        args.migrator_role = "missing_migration_identity"
        with pytest.raises(RuntimeError, match="selected migrator"):
            run_stage(runtime_url, args)


def test_recovery_signer_runtime_bootstrap_preserves_the_public_identity(monkeypatch):
    import json

    from cryptography.fernet import Fernet
    from sqlalchemy.orm import sessionmaker

    from core import settings_service
    from core.recovery_signing import (
        RecoveryUnavailable,
        SIGNING_SEED,
        recovery_trust,
        signing_key,
    )
    from core.tenant_context import PlatformContext, TenantContext
    from core.tenant_database import TenantSession, install_tenant_enforcement
    from core.transition_stages import run_stage

    monkeypatch.setattr(settings_service, "_fernet", Fernet(Fernet.generate_key()))
    with operator_stage_database() as (owner, runtime, engine, args):
        for stage in ("migration", "current-grants"):
            args.stage = stage
            run_stage(owner, args)
        with engine.connect() as connection:
            org_id = connection.scalar(
                text("SELECT org_id FROM organization_defaults WHERE slot='oss'")
            )
        app = create_engine(runtime)
        install_tenant_enforcement(app)
        factory = sessionmaker(bind=app, class_=TenantSession)
        try:
            with TenantContext(org_id), factory() as db:
                with pytest.raises(RecoveryUnavailable, match="not initialized"):
                    recovery_trust(db, org_id, factory=factory)
            signing_key(factory)
            with TenantContext(org_id), factory() as db:
                issued = recovery_trust(db, org_id, factory=factory)
            with PlatformContext(), factory.begin() as db:
                db.execute(
                    text("DELETE FROM secrets_v3 WHERE key=:key"), {"key": SIGNING_SEED}
                )
            with pytest.raises(RecoveryUnavailable, match="custody is incomplete"):
                signing_key(factory)
            replacements = (
                "UPDATE settings_v3 SET value='{}' WHERE key=:key",
                "DELETE FROM settings_v3 WHERE key=:key",
            )
            for statement in replacements:
                with (
                    pytest.raises(IntegrityError, match="Recovery signer identity"),
                    PlatformContext(),
                    factory.begin() as db,
                ):
                    db.execute(text(statement), {"key": "recovery.signing_identity.v1"})
            with PlatformContext(), factory() as db:
                observed = db.scalar(
                    text("SELECT value FROM settings_v3 WHERE key=:key"),
                    {"key": "recovery.signing_identity.v1"},
                )
            assert json.loads(observed)["key_id"] == issued["key_id"]
        finally:
            app.dispose()


def test_operator_effective_grants_membership_public_columns_and_defaults():
    from core.transition_contract import (
        default_acl_hazards,
        grant_mismatches,
        object_inventory,
    )
    from core.transition_stages import apply_stage, require_runtime_admission, run_stage

    with operator_stage_database() as (url, _, engine, args):
        run_stage(url, args)
        args.stage = "current-grants"
        run_stage(url, args)
        with engine.connect() as connection, connection.begin():
            relations, functions, unknown, missing = object_inventory(connection)
            assert unknown == missing == 0
            assert (
                grant_mismatches(connection, args.runtime_role, relations, functions)
                == 0
            )
            for hazard in (
                "GRANT UPDATE ON public.access_audit TO PUBLIC",
                "GRANT UPDATE(id) ON public.access_audit TO PUBLIC",
                "GRANT UPDATE ON public.access_audit_id_seq TO PUBLIC",
                "GRANT EXECUTE ON FUNCTION public.audit_access() TO PUBLIC",
                "GRANT EXECUTE ON FUNCTION public.vnbui_verification_guard() TO PUBLIC",
                (
                    "GRANT EXECUTE ON FUNCTION "
                    "public.vnbui_verification_expected(jsonb,text,text,text) "
                    f'TO "{args.runtime_role}" WITH GRANT OPTION'
                ),
                f'GRANT SELECT ON public.users TO "{args.runtime_role}" WITH GRANT OPTION',
                f'GRANT SELECT(id) ON public.users TO "{args.runtime_role}" WITH GRANT OPTION',
            ):
                with connection.begin_nested() as savepoint:
                    connection.execute(text(hazard))
                    assert (
                        grant_mismatches(
                            connection, args.runtime_role, relations, functions
                        )
                        > 0
                    )
                    savepoint.rollback()
                assert (
                    grant_mismatches(
                        connection, args.runtime_role, relations, functions
                    )
                    == 0
                )
            quote = connection.dialect.identifier_preparer.quote
            with connection.begin_nested() as savepoint:
                connection.execute(text("CREATE ROLE transition_membership_control"))
                connection.execute(
                    text(
                        f"GRANT transition_membership_control TO {quote(args.runtime_role)}"
                    )
                )
                with pytest.raises(RuntimeError, match="membership"):
                    require_runtime_admission(connection, args)
                savepoint.rollback()
            require_runtime_admission(connection, args)
            # Built-in NULL function ACL grants PUBLIC EXECUTE. Explicit global
            # and schema grants are additive, and clearing another owner is inert.
            assert default_acl_hazards(connection, args.migrator_role) > 0
            args.stage = "default-grants"
            apply_stage(connection, args)
            assert default_acl_hazards(connection, args.migrator_role) == 0
            for scope in ("", " IN SCHEMA public"):
                connection.execute(
                    text(
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quote(args.migrator_role)}{scope} "
                        "GRANT ALL ON TABLES TO PUBLIC"
                    )
                )
                assert default_acl_hazards(connection, args.migrator_role) > 0
                apply_stage(connection, args)
                assert default_acl_hazards(connection, args.migrator_role) == 0
            with connection.begin_nested() as savepoint:
                # Clearing a different identity's defaults cannot cure the
                # actual creator's grant; foreign grantees require disposition.
                foreign = quote(args.runtime_role + "_foreign")
                connection.execute(text(f"CREATE ROLE {foreign}"))
                connection.execute(
                    text(
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quote(args.migrator_role)} "
                        f"GRANT SELECT ON TABLES TO {foreign}"
                    )
                )
                assert default_acl_hazards(connection, args.runtime_role) > 0
                from core.runtime_grants import apply_default_runtime_grants

                connection.execute(text(f"SET LOCAL ROLE {quote(args.runtime_role)}"))
                apply_default_runtime_grants(connection, args.runtime_role)
                connection.execute(text("RESET ROLE"))
                assert default_acl_hazards(connection, args.migrator_role) > 0
                with pytest.raises(RuntimeError, match="Other grantees"):
                    apply_stage(connection, args)
                savepoint.rollback()
            assert default_acl_hazards(connection, args.migrator_role) == 0
            connection.rollback()


def test_operator_stage_unknown_objects_owners_and_failed_commit(monkeypatch):
    from sqlalchemy import event
    from core.transition_contract import inspect_contract
    from core.transition_stages import run_stage

    with operator_stage_database() as (url, _, engine, args):
        run_stage(url, args)
        args.stage = "current-grants"
        with engine.connect() as connection, connection.begin():
            for ddl in (
                "CREATE VIEW public.unclassified AS SELECT 1 AS id",
                "CREATE SEQUENCE public.unclassified",
                "CREATE FUNCTION public.unclassified() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            ):
                with connection.begin_nested() as savepoint:
                    connection.execute(text(ddl))
                    findings = {
                        f["code"]: f.get("count")
                        for f in inspect_contract(
                            connection, args.runtime_role, args.migrator_role
                        )
                    }
                    assert findings["UNKNOWN_OBJECT_CONTRACT"] == 1
                    savepoint.rollback()
                assert {
                    f["code"]: f.get("count")
                    for f in inspect_contract(
                        connection, args.runtime_role, args.migrator_role
                    )
                }["UNKNOWN_OBJECT_CONTRACT"] == 0
            with connection.begin_nested() as savepoint:
                connection.execute(
                    text(
                        f'ALTER TABLE public.demo_sessions OWNER TO "{args.runtime_role}"'
                    )
                )
                findings = {
                    f["code"]: f.get("count")
                    for f in inspect_contract(
                        connection, args.runtime_role, args.migrator_role
                    )
                }
                assert findings["NON_MIGRATOR_OBJECT_OWNERS"] == 1
                savepoint.rollback()
            connection.rollback()
        from core import transition_stages

        original = transition_stages.create_engine
        commits = []

        def fail_commit(*positional, **keywords):
            created = original(*positional, **keywords)

            def refuse(connection):
                commits.append(True)
                raise RuntimeError("Injected commit refusal")

            event.listen(created, "commit", refuse)
            return created

        monkeypatch.setattr(transition_stages, "create_engine", fail_commit)
        with pytest.raises(RuntimeError, match="Injected"):
            run_stage(url, args)
        assert commits == [True]
        with engine.connect() as connection:
            assert not connection.scalar(
                text("SELECT has_table_privilege(:role,'public.users','SELECT')"),
                {"role": args.runtime_role},
            )
        monkeypatch.setattr(transition_stages, "create_engine", original)
        assert run_stage(url, args)["stage_pass"]
        with engine.begin() as connection:
            connection.execute(
                text(f'REVOKE SELECT ON public.users FROM "{args.runtime_role}"')
            )
        original_bind = transition_stages.bind_connection
        observations = []

        def lose_postcommit_observation(connection, selected, runtime=False):
            original_bind(connection, selected, runtime)
            observations.append(True)
            if len(observations) == 3:
                raise RuntimeError("Injected postcommit observation loss")

        monkeypatch.setattr(
            transition_stages, "bind_connection", lose_postcommit_observation
        )
        with pytest.raises(RuntimeError, match="postcommit"):
            run_stage(url, args)
        assert len(observations) == 3  # No automatic retry or false rollback assertion.
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT has_table_privilege(:role,'public.users','SELECT')"),
                {"role": args.runtime_role},
            )
        monkeypatch.setattr(transition_stages, "bind_connection", original_bind)
        assert run_stage(url, args)["stage_pass"]  # Explicit same-contract restart.


def test_operator_migration_failed_postcondition_rolls_back_ddl(monkeypatch):
    from core import transition_stages

    with operator_stage_database() as (url, _, engine, args):
        original = transition_stages.require_current

        def refuse(*args, **kwargs):
            raise RuntimeError("Injected postcondition refusal")

        monkeypatch.setattr(transition_stages, "require_current", refuse)
        with pytest.raises(RuntimeError, match="Injected"):
            transition_stages.run_stage(url, args)
        with engine.connect() as connection:
            assert inspect(connection).get_table_names(schema="public") == []
        monkeypatch.setattr(transition_stages, "require_current", original)
        assert transition_stages.run_stage(url, args)["stage_pass"]


def test_operator_source_attribution_and_cross_store_collisions_are_not_guessed():
    from core.transition_contract import inspect_attribution

    # Deliberately incomplete predecessor: source FK contracts are inspected
    # even when the old DB lacks their constraints. Missing checks stay UNKNOWN.
    with database() as (_, engine), engine.connect() as connection, connection.begin():
        for statement in (
            "CREATE TABLE organizations(id text)",
            "INSERT INTO organizations VALUES ('one'),('two')",
            "CREATE TABLE users(id text,org_id text,username text,oidc_issuer text,oidc_subject text)",
            "INSERT INTO users VALUES ('u1','one','same','issuer','subject'),('u2','two','same','issuer','subject')",
            "CREATE TABLE agents(id text,org_id text,api_key_hash text,cert_fingerprint text)",
            "INSERT INTO agents VALUES ('a1','one','test-opaque-hash',NULL),('a2','two',NULL,NULL)",
            "CREATE TABLE agent_api_keys(agent_id text,key_hash text)",
            "INSERT INTO agent_api_keys VALUES ('a1','test-opaque-hash')",
            "CREATE TABLE vms(id text,org_id text,agent_id text)",
            "INSERT INTO vms VALUES ('vm','one','a1')",
            "CREATE TABLE vm_groups(id text,org_id text)",
            "INSERT INTO vm_groups VALUES ('group','two')",
            "CREATE TABLE vm_group_members(vm_id text,group_id text)",
            "INSERT INTO vm_group_members VALUES ('vm','group')",
        ):
            connection.execute(text(statement))

        def findings():
            return {f["code"]: f.get("count") for f in inspect_attribution(connection)}

        before = findings()
        assert before["ATTRIBUTION_CONFLICTS"] == 1
        assert before["IDENTITY_CREDENTIAL_COLLISIONS"] == 0
        assert before["ATTRIBUTION_CHECKS_UNKNOWN"] > 0
        connection.execute(text("UPDATE vm_groups SET org_id='one'"))
        assert findings()["ATTRIBUTION_CONFLICTS"] == 0
        connection.execute(text("UPDATE agent_api_keys SET agent_id='a2'"))
        assert findings()["IDENTITY_CREDENTIAL_COLLISIONS"] == 1
        connection.execute(text("UPDATE agent_api_keys SET agent_id='a1'"))
        assert findings()["IDENTITY_CREDENTIAL_COLLISIONS"] == 0
        connection.execute(text("INSERT INTO users SELECT * FROM users WHERE id='u1'"))
        assert findings()["IDENTITY_CREDENTIAL_COLLISIONS"] == 2
        # PK, login identity and the scheduler's same-org user binding key.
        assert findings()["SCHEMA_UNIQUENESS_COLLISIONS"] == 3
        connection.rollback()


def attribution_snapshot(connection):
    result = {}
    result["oidc_custody_present"] = (
        "oidc_login_states" in inspect(connection).get_table_names()
    )
    for table in (
        "organizations",
        "users",
        "agents",
        "vms",
        "backups",
        "vm_groups",
        "schedules",
    ):
        columns = "id" if table == "organizations" else "id,org_id"
        result[table] = connection.execute(
            text(f"SELECT {columns} FROM {table} ORDER BY id")
        ).all()
    result["policies"] = connection.execute(
        text(
            "SELECT tablename,policyname,roles,cmd,qual,with_check FROM pg_policies WHERE schemaname='public' ORDER BY tablename,policyname"
        )
    ).all()
    result["rls"] = connection.execute(
        text(
            "SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relnamespace='public'::regnamespace AND relrowsecurity ORDER BY relname"
        )
    ).all()
    result["triggers"] = connection.execute(
        text(
            "SELECT tgname,pg_get_triggerdef(oid) FROM pg_trigger WHERE NOT tgisinternal ORDER BY tgname"
        )
    ).all()
    result["audit"] = connection.execute(
        text("SELECT * FROM access_audit ORDER BY id")
    ).all()
    result["audit_shape"] = connection.execute(
        text(
            "SELECT column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_name='access_audit' ORDER BY ordinal_position"
        )
    ).all()
    result["audit_function"] = connection.execute(
        text("SELECT pg_get_functiondef('audit_access()'::regprocedure)")
    ).scalar_one()
    result["group"] = connection.execute(
        text("SELECT vm_id,group_id FROM vm_group_members ORDER BY vm_id,group_id")
    ).all()
    result["backup"] = connection.execute(
        text("SELECT id,vm_id,chain_id,chain_position,tags FROM backups ORDER BY id")
    ).all()
    result["vm"] = connection.execute(
        text("SELECT id,agent_id,uuid FROM vms ORDER BY id")
    ).all()
    result["settings"] = connection.execute(
        text("SELECT key,value FROM settings_v3 ORDER BY key")
    ).all()
    return result


def test_upgrade_preserves_attribution_and_database_owned_controls():
    with database() as (url, engine):
        migrate(url, PREDECESSOR)
        with engine.begin() as connection:
            org = seed_predecessor(connection)
            before = attribution_snapshot(connection)
            assert (
                connection.execute(
                    text("SELECT count(*) FROM pg_policies")
                ).scalar_one()
                == 24
            )
            assert len(before["triggers"]) == 3
            assert len(before["audit"]) == 3
        # The structural migration must preserve the old controls byte-for-byte.
        # Tenant enforcement is a distinct reviewed transition of those policies.
        migrate(url, "oss_schema_parity")
        with engine.begin() as connection:
            assert attribution_snapshot(connection) == before
            replay_forward_migration(connection)
            assert attribution_snapshot(connection) == before
        migrate(url)
        with engine.connect() as connection:
            assert_schema_current(connection)
            assert_tenant_transition_preserves_data(connection, before)
            assert (
                connection.execute(
                    text("SELECT org_id FROM organization_defaults")
                ).scalar_one()
                == org
            )
        with Session(engine) as session:
            assert session.get(Agent, "agent").hostname == "upgrade-agent"
            assert session.get(Backup, "backup").tags == {"keep": "me"}
            session.add(Agent(hostname="post-upgrade-write"))
            session.flush()
            session.rollback()
        migrate(url)
        with engine.begin() as connection:
            assert_tenant_transition_preserves_data(connection, before)


def assert_tenant_transition_preserves_data(connection, before):
    after = attribution_snapshot(connection)
    assert before["oidc_custody_present"] is False
    assert_empty_forward_custody(connection)
    for key in before.keys() - {
        "policies",
        "rls",
        "triggers",
        "audit_function",
        "audit",
        "oidc_custody_present",
    }:
        assert after[key] == before[key], key
    assert after["audit"][: len(before["audit"])] == before["audit"]
    appended = after["audit"][len(before["audit"]) :]
    # Preserve the predecessor's exact migration-audit batch, then require
    # exactly one additional audited legacy-capacity classification per backup.
    width = len(before["backups"])
    assert len(appended) == 2 * width
    for batch in (appended[:width], appended[width:]):
        assert len(batch) == len(before["backups"])
        assert {
            (r.table_name, r.operation, r.org_id, r.row_id, r.user_id) for r in batch
        } == {
            ("backups", "UPDATE", org, identifier, None)
            for identifier, org in before["backups"]
        }
    assert "audited.org_id" in after["audit_function"]
    assert "search_path TO 'pg_catalog'" in after["audit_function"]
    assert "SECURITY DEFINER" not in after["audit_function"]
    assert set(before["triggers"]).issubset(set(after["triggers"]))
    assert all(enabled and forced for _, enabled, forced in after["rls"])
    assert not any(
        row.policyname.startswith("admin_bypass_") for row in after["policies"]
    )
    assert {
        row.tablename
        for row in after["policies"]
        if row.policyname.startswith("tenant_isolation_")
    } == TENANT_POLICY_TABLES
    # Migration never converts a historical storage_path into asserted ownership.
    assert (
        connection.execute(text("SELECT count(*) FROM s3_publications")).scalar_one()
        == 0
    )
    assert {
        row.tablename
        for row in after["policies"]
        if row.policyname == "tenant_parent_scope"
    } == PARENT_POLICY_TABLES


def test_audit_history_stays_unassigned_and_runtime_append_failure_is_atomic():
    from core.runtime_grants import apply_current_runtime_grants
    from sqlalchemy.exc import DBAPIError

    with database() as (url, engine):
        migrate(url, PREDECESSOR)
        with engine.begin() as connection:
            org = seed_predecessor(connection)
            historical = connection.execute(
                text("SELECT * FROM access_audit ORDER BY id")
            ).all()
            assert len(historical) == 3
            assert all(not row.org_id for row in historical)
        migrate(url)
        runtime_url = make_url(os.environ["DATABASE_URL"]).set(database=url.database)
        role = runtime_url.username
        with engine.begin() as connection:
            apply_current_runtime_grants(connection, role)
            # Idempotent grants may neither widen audit access nor lose it.
            apply_current_runtime_grants(connection, role)
        runtime = create_engine(runtime_url)
        try:
            with runtime.begin() as connection:
                connection.execute(
                    text(
                        "SELECT set_config('app.current_org',:org,true), "
                        "set_config('app.platform_admin','false',true)"
                    ),
                    {"org": org},
                )
                # Classification appends an honest migration write, without
                # assigning a human or rewriting any of the three old records.
                assert connection.execute(
                    text(
                        "SELECT org_id,table_name,operation,row_id,user_id FROM access_audit WHERE id=4"
                    )
                ).one() == (org, "backups", "UPDATE", "backup", None)
                assert connection.execute(
                    text(
                        "SELECT org_id,table_name,operation,row_id,user_id FROM access_audit WHERE id>4"
                    )
                ).one() == (org, "backups", "UPDATE", "backup", None)
                connection.execute(
                    text("UPDATE agents SET hostname='audited-change' WHERE id='agent'")
                )
                assert connection.execute(
                    text(
                        "SELECT org_id,table_name,operation,row_id FROM access_audit WHERE table_name='agents'"
                    )
                ).one() == (org, "agents", "UPDATE", "agent")
            with runtime.begin() as connection:
                connection.execute(
                    text("SELECT set_config('app.platform_admin','true',true)")
                )
                assert (
                    connection.execute(
                        text("SELECT * FROM access_audit WHERE id<=3 ORDER BY id")
                    ).all()
                    == historical
                )
                with pytest.raises(DBAPIError):
                    connection.execute(
                        text(
                            "INSERT INTO access_audit(table_name,operation) VALUES ('agents','INSERT')"
                        )
                    )
            with engine.begin() as connection:
                quoted = connection.dialect.identifier_preparer.quote(role)
                connection.execute(
                    text(f"REVOKE INSERT ON public.access_audit FROM {quoted}")
                )
            with runtime.begin() as connection:
                connection.execute(
                    text("SELECT set_config('app.current_org',:org,true)"), {"org": org}
                )
                with pytest.raises(DBAPIError):
                    connection.execute(
                        text(
                            "UPDATE agents SET hostname='must-rollback' WHERE id='agent'"
                        )
                    )
            with engine.connect() as connection:
                assert (
                    connection.execute(
                        text("SELECT hostname FROM agents WHERE id='agent'")
                    ).scalar_one()
                    == "audited-change"
                )
                assert (
                    connection.execute(
                        text("SELECT count(*) FROM access_audit")
                    ).scalar_one()
                    == 6  # Three historical, two migration classifications, runtime update.
                )
        finally:
            runtime.dispose()


@pytest.mark.parametrize(
    "scenario",
    [
        "single_unowned",
        "backup",
        "rotation",
        "conflict",
        "unowned_multi",
        "rotation_conflict",
    ],
)
def test_encryption_history_requires_consistent_component_owner(scenario):
    with database() as (url, engine):
        migrate(url, "oss_schema_parity")
        with engine.begin() as connection:
            org = seed_predecessor(connection)
            if scenario in {"conflict", "unowned_multi", "rotation_conflict"}:
                connection.execute(
                    text(
                        "INSERT INTO organizations(id,name) VALUES ('second','Second')"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO users(id,username,password_hash,role,org_id) VALUES ('second-user','second','test-only','admin','second')"
                    )
                )
            creator = (
                "second-user"
                if scenario == "conflict"
                else "user" if scenario == "rotation_conflict" else None
            )
            connection.execute(
                text(
                    "INSERT INTO encryption_keys(id,name,key_hash,encrypted_material,created_by) VALUES ('k1','Retained','test-hash','retained-ciphertext',:creator)"
                ),
                {"creator": creator},
            )
            if scenario in {"backup", "conflict"}:
                connection.execute(
                    text("UPDATE backups SET encryption_key_id='k1' WHERE id='backup'")
                )
            if scenario in {"rotation", "rotation_conflict"}:
                creator = "second-user" if scenario == "rotation_conflict" else "user"
                connection.execute(
                    text(
                        "INSERT INTO encryption_keys(id,name,key_hash,created_by) VALUES ('k2','Replacement','test-hash-two',:creator)"
                    ),
                    {"creator": creator},
                )
                connection.execute(
                    text("UPDATE encryption_keys SET replaced_by_id='k2' WHERE id='k1'")
                )
            columns = [
                c["name"] for c in inspect(connection).get_columns("encryption_keys")
            ]
            query = text(f"SELECT {','.join(columns)} FROM encryption_keys ORDER BY id")
            before = connection.execute(query).all()
        result = migrate(url, check=False)
        rejected = scenario in {"conflict", "unowned_multi", "rotation_conflict"}
        assert (result.returncode != 0) == rejected, result.stderr
        if rejected:
            assert "Ambiguous encryption-key history" in result.stderr
        with engine.connect() as connection:
            assert connection.execute(query).all() == before
            if rejected:
                assert (
                    connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                    == "oss_schema_parity"
                )
                assert "org_id" not in {
                    c["name"]
                    for c in inspect(connection).get_columns("encryption_keys")
                }
            else:
                assert set(
                    connection.execute(
                        text("SELECT org_id FROM encryption_keys")
                    ).scalars()
                ) == {org}


@pytest.mark.parametrize(
    "scenario", ["resource", "source", "unresolved", "conflict", "operator"]
)
def test_system_event_history_preserves_attribution_evidence(scenario):
    with database() as (url, engine):
        migrate(url, "oss_schema_parity")
        with engine.begin() as connection:
            org = seed_predecessor(connection)
            source_id = None
            if scenario == "conflict":
                connection.execute(
                    text(
                        "INSERT INTO organizations(id,name) VALUES ('second','Second')"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO agents(id,hostname,org_id) VALUES ('other','Other','second')"
                    )
                )
                source_id = "other"
            elif scenario == "source":
                source_id = "agent"
            connection.execute(
                text(
                    """INSERT INTO system_events
                (id,event_type,source,source_id,resource_type,resource_id,details)
                VALUES ('history','retained',:origin,:source,'backup',:resource,'{"retained": true}')"""
                ),
                {
                    "source": source_id,
                    "origin": "operator_command" if scenario == "operator" else "agent",
                    "resource": (
                        "backup"
                        if scenario in {"resource", "conflict", "operator"}
                        else "deleted"
                    ),
                },
            )
            columns = [
                c["name"] for c in inspect(connection).get_columns("system_events")
            ]
            query = text(
                f"SELECT {','.join(columns)} FROM system_events WHERE id='history'"
            )
            before = connection.execute(query).one()
        result = migrate(url, check=False)
        assert (result.returncode != 0) == (scenario == "conflict"), result.stderr
        with engine.connect() as connection:
            assert connection.execute(query).one() == before
            if scenario == "conflict":
                assert "Conflicting system-event ownership" in result.stderr
                assert "attribution" not in {
                    c["name"] for c in inspect(connection).get_columns("system_events")
                }
            else:
                row = connection.execute(
                    text(
                        "SELECT org_id,attribution FROM system_events WHERE id='history'"
                    )
                ).one()
                assert tuple(row) == (
                    (None, "legacy_unattributed")
                    if scenario in {"unresolved", "operator"}
                    else (org, "tenant")
                )


def test_ambiguous_default_requires_explicit_existing_identity():
    with database() as (url, engine):
        migrate(url, PREDECESSOR)
        with engine.begin() as connection:
            original = seed_predecessor(connection)
            connection.execute(
                text(
                    "INSERT INTO organizations(id,name) VALUES ('second-org','Second')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO agents(id,hostname,org_id) VALUES ('second-agent','Second host','second-org')"
                )
            )
            before = attribution_snapshot(connection)
        rejected = migrate(url, check=False)
        assert rejected.returncode != 0
        assert "ambiguous or absent" in rejected.stderr
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one()
                == PREDECESSOR
            )
            assert attribution_snapshot(connection) == before
            assert "organization_defaults" not in inspect(connection).get_table_names()
        migrate(url, "oss_schema_parity", org_id=original)
        with engine.connect() as connection:
            assert attribution_snapshot(connection) == before
        migrate(url)
        with engine.connect() as connection:
            assert_schema_current(connection)
            assert_tenant_transition_preserves_data(connection, before)


def pg_environment(url):
    result = dict(os.environ)
    result.update(
        PGHOST=url.query.get("host", url.host or "localhost"),
        PGPORT=str(url.query.get("port", url.port or 5432)),
        PGUSER=url.username,
        PGPASSWORD=url.password or "",
        PGDATABASE=url.database,
    )
    return result


def test_pre_migration_dump_restore_rehearsal(tmp_path):
    with database() as (source_url, source), database() as (restored_url, restored):
        migrate(source_url, PREDECESSOR)
        with source.begin() as connection:
            seed_predecessor(connection)
            before = attribution_snapshot(connection)
        dump = tmp_path / "before-migration.dump"
        subprocess.run(
            ["pg_dump", "--format=custom", "--file", str(dump)],
            env=pg_environment(source_url),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "pg_restore",
                "--exit-on-error",
                "--dbname",
                restored_url.database,
                str(dump),
            ],
            env=pg_environment(restored_url),
            check=True,
            capture_output=True,
        )
        with restored.connect() as connection:
            assert attribution_snapshot(connection) == before
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one()
                == PREDECESSOR
            )
        migrate(restored_url, "oss_schema_parity")
        with restored.connect() as connection:
            assert attribution_snapshot(connection) == before
        migrate(restored_url)
        with restored.connect() as connection:
            assert_schema_current(connection)
            assert_tenant_transition_preserves_data(connection, before)


@pytest.mark.parametrize("existing_org", [False, True])
def test_measured_deployed_shape_converges_without_data_loss(existing_org):
    import hashlib

    fixture = ROOT / "tests/fixtures/deployed_schema_20260905.sql"
    raw = fixture.read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == "0aa22e4c347ec6195b68bf0dbc08f98626f12ce5afa573cbf2fde5cdbe441b82"
    )
    sql = "\n".join(
        line for line in raw.decode().splitlines() if not line.startswith("\\")
    )
    with database() as (url, engine):
        with engine.begin() as connection:
            connection.exec_driver_sql(sql)
            connection.execute(text("SET search_path TO public"))
            connection.execute(
                text("INSERT INTO alembic_version VALUES ('add_demo_rate_buckets')")
            )
            if existing_org:
                connection.execute(
                    text(
                        "INSERT INTO organizations(id,name) VALUES ('existing-org','Existing')"
                    )
                )
            connection.execute(
                text(
                    "INSERT INTO agents(id,hostname,display_name,capabilities,metrics) VALUES ('agent','deployed-host','Keep display','{}','{}')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO vms(id,name,agent_id,uuid) VALUES ('vm','deployed-vm','agent','provider-uid')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO backups(id,vm_id,chain_id,chain_position,retention_days,tags,size_bytes,storage_path) VALUES ('backup','vm','backup',0,30,'{}',5368709120,'s3://retained/chain')"
                )
            )
            connection.execute(text("""INSERT INTO system_events
                (id,event_type,source,resource_type,resource_id,details)
                VALUES ('live-known','retained','system','backup','backup','{}'),
                       ('live-unknown','retained','system','backup','deleted','{}')"""))
            before = {}
            assert "oidc_login_states" not in inspect(connection).get_table_names()
            for table in inspect(connection).get_table_names():
                if table in ("alembic_version", "organizations"):
                    continue
                columns = [c["name"] for c in inspect(connection).get_columns(table)]
                before[table] = (
                    columns,
                    connection.execute(
                        text(f"SELECT {','.join(columns)} FROM {table}")
                    ).all(),
                )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM pg_policies")
                ).scalar_one()
                == 0
            )
        migrate(url, "oss_schema_parity")
        for _ in range(2):
            with engine.begin() as connection:
                replay_forward_migration(connection)
                for table, (columns, rows) in before.items():
                    assert (
                        connection.execute(
                            text(f"SELECT {','.join(columns)} FROM {table}")
                        ).all()
                        == rows
                    )
                org = connection.execute(
                    text("SELECT org_id FROM organization_defaults")
                ).scalar_one()
                if existing_org:
                    assert org == "existing-org"
                assert (
                    connection.execute(text("SELECT org_id FROM backups")).scalar_one()
                    == org
                )
                assert (
                    connection.execute(
                        text("SELECT count(*) FROM pg_policies")
                    ).scalar_one()
                    == 0
                )
                assert "access_audit" not in inspect(connection).get_table_names()
                assert "oidc_login_states" not in inspect(connection).get_table_names()
        migrate(url)
        with engine.connect() as connection:
            assert_schema_current(connection)
            for table, (columns, rows) in before.items():
                assert (
                    connection.execute(
                        text(f"SELECT {','.join(columns)} FROM {table}")
                    ).all()
                    == rows
                )
            assert_empty_forward_custody(connection)
            assert connection.execute(
                text(
                    "SELECT policyname,cmd,qual=with_check FROM pg_policies WHERE tablename='s3_publications'"
                )
            ).all() == [("tenant_isolation_s3_publications", "ALL", True)]
            assert (
                connection.execute(
                    text("SELECT count(*) FROM s3_publications")
                ).scalar_one()
                == 0
            )
            assert {
                row.tablename
                for row in connection.execute(
                    text(
                        "SELECT tablename FROM pg_policies "
                        "WHERE policyname='installation_administration' "
                        "AND cmd='ALL' AND qual=with_check"
                    )
                )
            } == {"settings_v3", "secrets_v3", "system_settings"}
            assert {
                row.tablename
                for row in connection.execute(
                    text(
                        "SELECT tablename FROM pg_policies WHERE policyname='demo_storage' AND cmd='ALL' AND qual=with_check"
                    )
                )
            } == {"demo_sessions", "demo_rate_buckets"}
            assert {
                row.policyname
                for row in connection.execute(
                    text(
                        "SELECT policyname FROM pg_policies WHERE tablename='access_audit'"
                    )
                )
            } == {"audit_read", "audit_append"}
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_trigger WHERE tgname IN "
                        "('audit_users_access','audit_agents_access','audit_backups_access')"
                    )
                ).scalar_one()
                == 3
            )
        with Session(engine) as session:
            session.add(Agent(hostname="new-deployed-shape-write"))
            session.flush()
            session.rollback()
            migrate(url)
