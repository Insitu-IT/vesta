"""Upgrade and custody on PostgreSQL with the production runtime grants."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.portable_install import transition_managed_files
from models import Agent, Organization, OrganizationDefault, Schedule, User, VM
from tests.integration.test_schema_parity_pg import database, migrate


def test_upgrade_retains_legacy_schedules_and_fences_managed_file_custody():
    with database() as (url, engine):
        migrate(url, "backup_admission_pause")
        capability = {
            "provider": "none",
            "managed_file_sets": ["archive"],
            "managed_file_storage": {
                "endpoint": "https://backup.example.test",
                "region": "us-east-1",
                "bucket": "file-backups",
                "prefix": "site",
                "recipient_sha256": {"archive": "a" * 64},
            },
        }
        with engine.begin() as connection, Session(connection) as db:
            organization = db.get(OrganizationDefault, "oss").org_id
            staff = User(
                username="file-admin",
                password_hash="test-only",
                role="admin",
                org_id=organization,
            )
            host = Agent(
                hostname="enrolled-linux",
                org_id=organization,
                capabilities=capability,
            )
            foreign = Organization(name="Another tenant")
            db.add_all([staff, host, foreign])
            db.flush()
            foreign_host = Agent(
                hostname="other-linux",
                org_id=foreign.id,
                capabilities=capability,
            )
            db.add(foreign_host)
            vm = VM(name="legacy-source", agent_id=host.id, org_id=organization)
            db.add(vm)
            db.flush()
            prior = Schedule(
                name="Legacy VM schedule",
                vm_id=vm.id,
                cron_expression="0 2 * * *",
                enabled=False,
                org_id=organization,
            )
            db.add(prior)
            db.flush()
            keys = (
                organization,
                foreign.id,
                host.id,
                foreign_host.id,
                staff.id,
                prior.id,
            )

        org_id, foreign_id, agent_id, other_agent_id, actor_id, schedule_id = keys
        with engine.begin() as connection:
            role = "file_runtime_" + uuid.uuid4().hex
            connection.execute(text(f'CREATE ROLE "{role}" LOGIN NOINHERIT'))
            installation_id = connection.scalar(
                text(
                    "SELECT installation_id FROM storage_configuration_clock WHERE slot=1"
                )
            )
            options = dict(
                runtime_role=role,
                expected_database=url.database,
                installation_id=installation_id,
            )
            with pytest.raises(RuntimeError, match="Database installation differs"):
                transition_managed_files(
                    connection, **{**options, "installation_id": str(uuid.uuid4())}
                )
            before = connection.scalar(
                text("SELECT to_jsonb(s)::text FROM schedules s WHERE id=:id"),
                {"id": schedule_id},
            )
            assert (
                transition_managed_files(connection, **options)["revision"]
                == "managed_file_backups"
            )
            assert (
                connection.scalar(
                    text("SELECT to_jsonb(s)::text FROM schedules s WHERE id=:id"),
                    {"id": schedule_id},
                )
                == before
            )
            connection.execute(text(f'SET LOCAL ROLE "{role}"'))
            for table in ("file_schedules", "file_backups"):
                assert connection.scalar(
                    text("SELECT has_table_privilege(current_user, :table, 'UPDATE')"),
                    {"table": table},
                )
                assert not connection.scalar(
                    text("SELECT has_table_privilege(current_user, :table, 'DELETE')"),
                    {"table": table},
                )
            connection.execute(
                text("SELECT set_config('app.current_org', :org, true)"),
                {"org": org_id},
            )

            row = dict(id=str(uuid.uuid4()), agent=agent_id, org=org_id, actor=actor_id)
            insert = text(
                """
                INSERT INTO file_backups
                  (id, org_id, agent_id, file_set, actor_id, status, created_at, next_check_at,
                   storage_endpoint, storage_region, storage_bucket, storage_prefix, storage_recipient_sha256)
                VALUES (:id, :org, :agent, 'archive', :actor, 'pending', now(), now(),
                  'https://backup.example.test', 'us-east-1', 'file-backups', 'site', repeat('a',64))
            """
            )
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(insert, {**row, "agent": other_agent_id})
            connection.execute(insert, row)
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(
                    text(
                        "UPDATE file_backups SET storage_region='eu-east-1' WHERE id=:id"
                    ),
                    row,
                )
            assert connection.scalar(text("SELECT count(*) FROM file_backups")) == 1
            connection.execute(
                text("SELECT set_config('app.current_org', :org, true)"),
                {"org": foreign_id},
            )
            assert connection.scalar(text("SELECT count(*) FROM file_backups")) == 0
            connection.execute(
                text("SELECT set_config('app.platform_admin','true',true)")
            )
            assert connection.scalar(text("SELECT count(*) FROM file_backups")) == 0
            connection.execute(text("RESET ROLE"))
            with pytest.raises(
                Exception, match="Managed file custody is retained"
            ), connection.begin_nested():
                transition_managed_files(connection, **options, rollback=True)
            connection.rollback()


def test_upgrade_preserves_unverified_s3_history_and_refuses_runtime_reclassification():
    """Retained fixtures exercise custody without any object-store access."""
    with database() as (url, engine):
        migrate(url, "backup_admission_pause")
        with engine.begin() as connection, Session(connection) as db:
            dflt = db.get(OrganizationDefault, "oss").org_id
            actor = User(
                username="legacy-reviewer",
                password_hash="test-only",
                org_id=dflt,
                role="admin",
            )
            agent = Agent(hostname="legacy-enrolled", org_id=dflt)
            db.add_all([actor, agent])
            db.flush()
            vm = VM(name="legacy-enrolled-vm", agent_id=agent.id, org_id=dflt)
            db.add(vm)
            db.flush()
            actor_id, vm_id = actor.id, vm.id
            rows = {
                "old_s3": ("s3://archive-bucket/retained", "{}"),
                "old_import_audit": (None, "{}"),
                "trusted_local": ("file:///backups/recorded", "{}"),
            }
            for identifier, (locator, tags) in rows.items():
                connection.execute(
                    text(
                        """
                        INSERT INTO backups (id, vm_id, org_id, initiating_user_id, authority_kind,
                                             status, storage_path, chain_id, tags, retention_days,
                                             created_at, completed_at)
                        VALUES (:id, :vm, :org, :actor, 'human', 'completed', :locator,
                                :id, CAST(:tags AS jsonb), 30, now(), now())
                    """
                    ),
                    {
                        "id": identifier,
                        "vm": vm_id,
                        "org": dflt,
                        "actor": actor_id,
                        "locator": locator,
                        "tags": tags,
                    },
                )
            connection.execute(
                text(
                    """
                    INSERT INTO activity_logs(id,user_id,action,resource_type,resource_id)
                    VALUES ('legacy-import-audit',:actor,'s3_chain_imported','backup_chain','old_import_audit')
                """
                ),
                {"actor": actor_id},
            )
        with engine.begin() as connection:
            role = "legacy_file_runtime_" + uuid.uuid4().hex
            connection.execute(text(f'CREATE ROLE "{role}" LOGIN NOINHERIT'))
            installation = connection.scalar(
                text(
                    "SELECT installation_id FROM storage_configuration_clock WHERE slot=1"
                )
            )
            options = dict(
                runtime_role=role,
                expected_database=url.database,
                installation_id=installation,
            )
            transition_managed_files(connection, **options)
            actual = connection.execute(
                text(
                    "SELECT id, unverified_legacy_s3, storage_path, status FROM backups ORDER BY id"
                )
            ).all()
            assert actual == [
                ("old_import_audit", True, None, "completed"),
                ("old_s3", True, "s3://archive-bucket/retained", "completed"),
                ("trusted_local", False, "file:///backups/recorded", "completed"),
            ]
            connection.execute(text(f'SET LOCAL ROLE "{role}"'))
            connection.execute(
                text("SELECT set_config('app.current_org', :org, true)"), {"org": dflt}
            )
            for statement in (
                "UPDATE backups SET unverified_legacy_s3=false WHERE id='old_s3'",
                "DELETE FROM backups WHERE id='old_s3'",
                "UPDATE backups SET parent_backup_id='old_s3' WHERE id='trusted_local'",
            ):
                with pytest.raises(IntegrityError), connection.begin_nested():
                    connection.execute(text(statement))
            connection.execute(text("RESET ROLE"))
            with pytest.raises(
                Exception, match="Unverified legacy S3 custody is retained"
            ), connection.begin_nested():
                transition_managed_files(connection, **options, rollback=True)
            connection.rollback()
