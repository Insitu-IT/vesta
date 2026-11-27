"""Explicit installation/schema operations; never called by an API process.

DATABASE_URL is the separately mounted migration-owner credential. No password
is accepted in argv, emitted in a manifest, or printed in an error report.
"""

import argparse
import os
from pathlib import Path
from uuid import UUID

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from core.runtime_grants import (
    apply_current_runtime_grants,
    apply_default_runtime_grants,
)
from core.schema_parity import assert_schema_current
from core.postgres_profile import (
    CustomerPostgresPrerequisiteError,
    connection_parameters,
    customer_postgresql_profile,
)


def _customer_prerequisites(connection, version):
    """Read-only checks, before advisory locks, grants or schema effects."""
    if not customer_postgresql_profile():
        return
    # PG15 has CI schema evidence; PG17 has dedicated-install evidence. This
    # narrower external-service policy must be qualified for each candidate.
    if not 170000 <= version < 180000:
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL profile requires PostgreSQL 17.x"
        )
    driver = connection.connection.driver_connection
    parameters = driver.get_dsn_parameters()
    if (
        parameters.get("sslmode") != "verify-full"
        or not parameters.get("sslrootcert")
        or not driver.info.ssl_in_use
    ):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires verify-full TLS and an explicit CA trust file"
        )
    if not connection.scalar(
        text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='plpgsql')")
    ):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires the plpgsql extension"
        )
    if connection.scalar(text("SELECT pg_is_in_recovery()")):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires a writable primary"
        )
    if (
        connection.scalar(
            text("SELECT current_setting('default_transaction_read_only')")
        )
        != "off"
    ):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires default_transaction_read_only=off"
        )


def _target(connection, runtime_role, expected_database, *, lock=True):
    if connection.dialect.name != "postgresql":
        raise RuntimeError("Portable installation requires PostgreSQL 15 or newer")
    database, owner, version = connection.execute(
        text(
            "SELECT current_database(), current_user, current_setting('server_version_num')::int"
        )
    ).one()
    if database != expected_database or version < 150000:
        raise RuntimeError(
            "Database identity or PostgreSQL prerequisite differs from installation plan"
        )
    _customer_prerequisites(connection, version)
    if not runtime_role or runtime_role == owner:
        raise RuntimeError("Separate migration owner and runtime role are required")
    role = (
        connection.execute(
            text(
                "SELECT oid, rolcanlogin, rolsuper OR rolbypassrls OR rolcreatedb OR "
                "rolcreaterole OR rolreplication OR rolinherit AS unsafe FROM pg_roles WHERE rolname=:role"
            ),
            {"role": runtime_role},
        )
        .mappings()
        .one_or_none()
    )
    if role is None or not role["rolcanlogin"] or role["unsafe"]:
        raise RuntimeError(
            "Precreate a LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT runtime role"
        )
    if connection.scalar(
        text("SELECT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=:oid)"),
        {"oid": role["oid"]},
    ):
        raise RuntimeError("Runtime role must have no role memberships")
    if connection.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=:oid "
            "UNION ALL SELECT 1 FROM pg_namespace WHERE nspname='public' AND nspowner=:oid)"
        ),
        {"oid": role["oid"]},
    ):
        raise RuntimeError("Runtime role cannot own the database or public schema")
    if lock:
        connection.execute(text("SELECT pg_advisory_xact_lock(783518920164)"))
    return database


def _configuration(connection):
    configuration = Config()
    configuration.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "alembic")
    )
    configuration.attributes["connection"] = connection
    return configuration


def install_empty(connection, *, runtime_role, expected_database):
    """Migrate and grant in the caller's transaction, refusing populated schemas."""
    database = _target(connection, runtime_role, expected_database)
    if connection.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace "
            "UNION ALL SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace)"
        )
    ):
        raise RuntimeError(
            "Fresh install requires an empty public schema; "
            "use the reviewed upgrade procedure for existing installations"
        )
    apply_default_runtime_grants(connection, runtime_role)
    command.upgrade(_configuration(connection), "head")
    apply_current_runtime_grants(connection, runtime_role)
    assert_schema_current(connection)
    return {
        "database": database,
        "runtime_role": runtime_role,
        "revision": connection.scalar(text("SELECT version_num FROM alembic_version")),
    }


def grant_restored(connection, *, runtime_role, expected_database):
    """Reapply classified runtime grants after an exact-schema restore.

    Before restoring into a new database, establish private default privileges
    under the actual replacement owner there. Changing defaults here cannot
    revoke PUBLIC EXECUTE already attached to restored functions at creation.
    Preserve and compare the reviewed effective grants independently.
    """
    database = _target(connection, runtime_role, expected_database)
    head = ScriptDirectory.from_config(_configuration(connection)).get_current_head()
    revisions = list(
        connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
    )
    if revisions != [head]:
        raise RuntimeError(
            "Restored schema must match this exact release; use its matching images or the reviewed upgrade procedure"
        )
    assert_schema_current(connection)
    apply_default_runtime_grants(connection, runtime_role)
    apply_current_runtime_grants(connection, runtime_role)
    return {"database": database, "runtime_role": runtime_role, "revision": head}


def transition_operation_safety(
    connection,
    *,
    runtime_role,
    expected_database,
    rollback=False,
    rollback_revision="verification_budget",
):
    """Only reviewed predecessor heads and retained operator-request custody.

    Run while application writers are stopped and new admission is paused.
    The caller owns the transaction; upgrade reapplies classified runtime grants.
    """
    # Include the migration advisory lock in the bounded wait.
    connection.execute(text("SET LOCAL lock_timeout = '30s'"))
    connection.execute(text("SET LOCAL statement_timeout = '5min'"))
    database = _target(connection, runtime_role, expected_database)
    configuration = _configuration(connection)
    supported = {
        "backup_verification",
        "storage_upload_progress",
        "verification_budget",
        "operator_requests",
    }
    new = "backup_admission_pause"
    if rollback_revision not in supported:
        raise RuntimeError("Unsupported rollback schema")
    if ScriptDirectory.from_config(configuration).get_current_head() != new:
        raise RuntimeError("This command supports only the operation-safety release")
    revisions = list(
        connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
    )
    if (rollback and revisions != [new]) or (
        not rollback and (len(revisions) != 1 or revisions[0] not in supported)
    ):
        raise RuntimeError("Schema differs from the reviewed transition source")
    if rollback:
        assert_schema_current(connection)
        command.downgrade(configuration, rollback_revision)
    else:
        command.upgrade(configuration, new)
        assert_schema_current(connection)
        apply_current_runtime_grants(connection, runtime_role)
    return {
        "database": database,
        "runtime_role": runtime_role,
        "revision": rollback_revision if rollback else new,
    }


MANAGED_FILES_HEAD = "managed_file_backups"
MANAGED_FILES_PREDECESSOR = "backup_admission_pause"


def _assert_managed_file_guards(connection):
    for table in ("file_backups", "file_schedules"):
        ready = connection.scalar(
            text("""
                SELECT c.relrowsecurity AND c.relforcerowsecurity
                AND EXISTS (
                  SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
                    AND p.polname='tenant_isolation_' || c.relname
                    AND p.polqual IS NOT NULL AND p.polwithcheck IS NOT NULL
                )
                AND EXISTS (
                  SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid
                    AND t.tgname='file_custody' AND t.tgenabled IN ('O','A')
                    AND t.tgfoid='public.vnbui_file_custody()'::regprocedure
                )
                FROM pg_class c
                WHERE c.relnamespace='public'::regnamespace AND c.relname=:table
            """),
            {"table": table},
        )
        if not ready:
            raise RuntimeError(
                f"Managed file custody guards are unavailable for {table}"
            )

    legacy_guard_installed = connection.scalar(text("""
            SELECT EXISTS (
                SELECT 1 FROM pg_trigger t
                 WHERE t.tgrelid='public.backups'::regclass
                   AND t.tgname='unverified_legacy_s3_custody'
                   AND t.tgenabled IN ('O','A')
                   AND t.tgfoid=to_regprocedure('public.vnbui_unverified_legacy_s3()')
            )
        """))
    if not legacy_guard_installed:
        raise RuntimeError("Legacy S3 catalog quarantine guard is unavailable")

    if not connection.scalar(text("""
        SELECT c.relrowsecurity AND c.relforcerowsecurity
          AND EXISTS (
              SELECT 1 FROM pg_policy p
               WHERE p.polrelid=c.oid AND p.polname='tenant_isolation_recovery_publications'
                 AND p.polqual IS NOT NULL AND p.polwithcheck IS NOT NULL
          )
          AND EXISTS (
              SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid=c.oid AND t.tgname='recovery_publication_custody'
                 AND t.tgenabled IN ('O','A')
                 AND t.tgfoid=to_regprocedure('public.vnbui_recovery_publication_custody()')
          )
          FROM pg_class c WHERE c.oid='public.recovery_publications'::regclass
    """)):
        raise RuntimeError("Signed recovery publication custody guards are unavailable")

    if not connection.scalar(text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_trigger t
            WHERE t.tgrelid='public.settings_v3'::regclass
              AND t.tgname='recovery_signer_marker' AND t.tgenabled IN ('O','A')
              AND t.tgfoid=to_regprocedure('public.vnbui_recovery_signer_marker()')
        )
    """)):
        raise RuntimeError("Recovery signer identity guard is unavailable")


def validated_installation_id(installation_id):
    try:
        identity = UUID(installation_id)
    except (AttributeError, TypeError, ValueError):
        raise RuntimeError(
            "An observed database installation UUID is required"
        ) from None
    if identity.int == 0 or str(identity) != installation_id:
        raise RuntimeError("An observed database installation UUID is required")
    return installation_id


def _assert_expected_installation(connection, installation_id):
    identity = validated_installation_id(installation_id)
    actual_id = connection.scalar(
        text("SELECT installation_id FROM storage_configuration_clock WHERE slot=1")
    )
    if identity != actual_id:
        raise RuntimeError(
            "Database installation differs from the reviewed upgrade plan"
        )


def transition_managed_files(
    connection, *, runtime_role, expected_database, installation_id, rollback=False
):
    """Add the managed-file schema to 6.1.x, with an empty-custody rollback fence."""
    validated_installation_id(installation_id)
    connection.execute(text("SET LOCAL lock_timeout = '30s'"))
    connection.execute(text("SET LOCAL statement_timeout = '5min'"))
    database = _target(connection, runtime_role, expected_database)
    configuration = _configuration(connection)
    _assert_expected_installation(connection, installation_id)
    if (
        ScriptDirectory.from_config(configuration).get_current_head()
        != MANAGED_FILES_HEAD
    ):
        raise RuntimeError("This command supports only the managed file backup release")
    source, target = (
        (MANAGED_FILES_HEAD, MANAGED_FILES_PREDECESSOR)
        if rollback
        else (MANAGED_FILES_PREDECESSOR, MANAGED_FILES_HEAD)
    )
    revisions = list(
        connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
    )
    if revisions != [source] and (rollback or revisions != [target]):
        raise RuntimeError(
            "Schema differs from the reviewed managed file backup transition source"
        )
    if rollback:
        assert_schema_current(connection)
        _assert_managed_file_guards(connection)
        command.downgrade(configuration, target)
    else:
        if revisions == [source]:
            command.upgrade(configuration, target)
        assert_schema_current(connection)
        _assert_managed_file_guards(connection)
        apply_current_runtime_grants(connection, runtime_role)
    return {"database": database, "runtime_role": runtime_role, "revision": target}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fresh", action="store_true")
    mode.add_argument("--check-prerequisites", action="store_true")
    mode.add_argument("--restored", action="store_true")
    mode.add_argument("--upgrade-operation-safety", action="store_true")
    mode.add_argument("--rollback-operation-safety", action="store_true")
    mode.add_argument("--upgrade-managed-files", action="store_true")
    mode.add_argument("--rollback-managed-files", action="store_true")
    parser.add_argument(
        "--rollback-revision",
        choices=(
            "backup_verification",
            "storage_upload_progress",
            "verification_budget",
            "operator_requests",
        ),
        default="verification_budget",
    )
    parser.add_argument(
        "--installation-id", help="database identity observed by the upgrade plan"
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--runtime-role", required=True)
    args = parser.parse_args()
    if args.upgrade_managed_files or args.rollback_managed_files:
        try:
            validated_installation_id(args.installation_id)
        except RuntimeError as error:
            parser.error(str(error))
    url = os.environ.get("DATABASE_URL")
    if not url:
        parser.error("DATABASE_URL must be mounted from the migration-owner Secret")
    engine = None
    try:
        url, connect_args = connection_parameters(url)
        engine = create_engine(url, connect_args=connect_args, hide_parameters=True)
        with engine.begin() as connection:
            options = dict(
                runtime_role=args.runtime_role, expected_database=args.database
            )
            if args.check_prerequisites:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                _target(connection, **options, lock=False)
                if args.installation_id is not None:
                    _assert_expected_installation(connection, args.installation_id)
                print(
                    "Database prerequisites passed; no schema or grant changes performed."
                )
                return
            if args.upgrade_managed_files or args.rollback_managed_files:
                result = transition_managed_files(
                    connection,
                    **options,
                    rollback=args.rollback_managed_files,
                    installation_id=args.installation_id,
                )
            elif args.upgrade_operation_safety or args.rollback_operation_safety:
                result = transition_operation_safety(
                    connection,
                    **options,
                    rollback=args.rollback_operation_safety,
                    rollback_revision=args.rollback_revision,
                )
            else:
                operation = install_empty if args.fresh else grant_restored
                result = operation(connection, **options)
    except Exception as exc:
        # DB driver exceptions may contain connection credentials. Keep them out
        # of Job logs; the operator can inspect the DB server independently.
        reason = (
            f" {exc}." if isinstance(exc, CustomerPostgresPrerequisiteError) else ""
        )
        raise SystemExit(
            f"Installation stage failed ({type(exc).__name__});{reason} "
            "transaction rolled back. Check prerequisites and database identity."
        ) from None
    finally:
        if engine is not None:
            engine.dispose()
    print(
        f"Schema ready: {result['revision']}. Start API with the runtime credential only."
    )


if __name__ == "__main__":
    main()
