"""Explicit operator stages. No API startup, role provisioning or cutover."""

from argparse import Namespace

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from core.postgres_profile import connection_parameters

from core.runtime_grants import (
    apply_current_runtime_grants,
    apply_default_runtime_grants,
)
from core.schema_parity import assert_schema_current, schema_differences
from core.tenant_database import assert_non_bypass_role
from core.table_scope import SCOPES
from core.transition_contract import (
    SEQUENCES,
    default_acl_hazards,
    grant_mismatches,
    object_inventory,
    trigger_functions,
    inspect_attribution,
    _publication_function,
    _owner_review_function,
    _verification_function,
)
from core.transition_preflight import BACKEND, migration_identity

MUTATIONS = {"migration", "current-grants", "default-grants"}


def bind_connection(connection, args, runtime=False):
    actual = connection.execute(
        text(
            "SELECT current_database(),(SELECT oid FROM pg_database WHERE datname=current_database()),"
            "current_user,session_user"
        )
    ).one()
    identity = args.runtime_role if runtime else args.migrator_role
    if tuple(actual) != (args.database, args.database_oid, identity, identity):
        raise RuntimeError("Transition connection identity differs")


def require_current(connection, runtime=False):
    head = migration_identity()[0]
    if list(
        connection.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalars()
    ) != [head]:
        raise RuntimeError("Migration head differs")
    if runtime:
        # No fabricated tenant/platform session for this catalog-only check.
        # Owner parity checks the persisted default; API/RLS behavior is a
        # separate mandatory rehearsal, not inferred from catalog visibility.
        if schema_differences(connection):
            raise RuntimeError("Runtime schema differs")
    else:
        assert_schema_current(connection)
    relations, functions, unknown, missing = object_inventory(connection)
    if unknown or missing:
        raise RuntimeError("Object contract incomplete")
    return relations, functions


def require_runtime_admission(connection, args):
    row = (
        connection.execute(
            text(
                "SELECT oid, NOT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole "
                "OR rolreplication OR rolinherit AS unsafe FROM pg_roles WHERE rolname=:role"
            ),
            {"role": args.runtime_role},
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["unsafe"]:
        raise RuntimeError("Runtime role requires separate operator disposition")
    unsafe = connection.scalar(
        text(
            "SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=:oid) OR "
            "EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=:oid) OR "
            "EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='public' AND nspowner=:oid) OR "
            "has_database_privilege(:role,current_database(),'CREATE')"
        ),
        {"role": args.runtime_role, "oid": row["oid"]},
    )
    relations, functions, _, _ = object_inventory(connection)
    if (
        unsafe
        or any(r["relowner"] == row["oid"] for r in relations)
        or any(p["proowner"] == row["oid"] for p in functions)
    ):
        raise RuntimeError("Runtime membership or ownership requires disposition")


def apply_stage(connection, args):
    """A single caller-owned transaction, locked against other transition stages."""
    # Advisory serialization does not assert quiescence of applications or other
    # admin tools; external maintenance evidence remains mandatory for live use.
    connection.execute(text("SELECT pg_advisory_xact_lock(1447973449,10)"))
    bind_connection(connection, args)
    if args.stage == "migration":
        tables, functions, _, _ = object_inventory(connection)
        expected_triggers = trigger_functions()
        owner = connection.scalar(
            text("SELECT oid FROM pg_roles WHERE rolname=current_user")
        )
        if any(r["relowner"] != owner for r in tables) or any(
            p["proowner"] != owner for p in functions
        ):
            raise RuntimeError("Predecessor object owner differs from executor")
        if any(
            not (
                (
                    row["relkind"] in {"r", "p"}
                    and row["relname"] in set(SCOPES) | {"alembic_version"}
                )
                or (row["relkind"] == "S" and row["relname"] in SEQUENCES)
            )
            for row in tables
        ) or any(
            not _publication_function(p)
            and not _owner_review_function(p)
            and not _verification_function(p)
            and (
                p["proname"] not in expected_triggers
                or p["pronargs"]
                or not p["trigger"]
                or p["prosecdef"]
            )
            for p in functions
        ):
            raise RuntimeError("Unknown predecessor object requires disposition")
        for finding in inspect_attribution(connection):
            if finding["code"] == "FULL_ATTRIBUTION_UNKNOWN_VISIBILITY":
                raise RuntimeError("Complete predecessor visibility required")
            if (
                finding["code"]
                in {
                    "ATTRIBUTION_CONFLICTS",
                    "IDENTITY_CREDENTIAL_COLLISIONS",
                    "SCHEMA_UNIQUENESS_COLLISIONS",
                }
                and finding["count"]
            ):
                raise RuntimeError(
                    "Predecessor attribution/collision requires disposition"
                )
        config = Config(str(BACKEND / "alembic.ini"))
        config.set_main_option("script_location", str(BACKEND / "alembic"))
        config.attributes["connection"] = connection
        config.cmd_opts = Namespace(
            x=(
                []
                if not args.default_organization_id
                else ["default_organization_id=" + args.default_organization_id]
            )
        )
        command.upgrade(config, migration_identity()[0])
        require_current(connection)
        return
    relations, functions = require_current(connection)
    require_runtime_admission(connection, args)
    owner = connection.scalar(
        text("SELECT oid FROM pg_roles WHERE rolname=current_user")
    )
    if any(r["relowner"] != owner for r in relations) or any(
        p["proowner"] != owner for p in functions
    ):
        raise RuntimeError("Migration object owner differs from executor")
    quote = connection.dialect.identifier_preparer.quote
    if args.stage == "current-grants":
        # PUBLIC and membership are additive. Never claim a direct REVOKE alone
        # removed an effective privilege. Scope is the exact classified objects.
        for row in relations:
            kind = "SEQUENCE" if row["relkind"] == "S" else "TABLE"
            connection.execute(
                text(f"REVOKE ALL ON {kind} public.{quote(row['relname'])} FROM PUBLIC")
            )
            if kind == "SEQUENCE":
                connection.execute(
                    text(
                        f"REVOKE ALL ON SEQUENCE public.{quote(row['relname'])} FROM {quote(args.runtime_role)}"
                    )
                )
        from core.transition_contract import function_signature

        for row in functions:
            connection.execute(
                text(
                    f"REVOKE ALL ON FUNCTION public.{quote(row['proname'])}"
                    f"{function_signature(row)} FROM PUBLIC, {quote(args.runtime_role)}"
                )
            )
        apply_current_runtime_grants(connection, args.runtime_role)
        if grant_mismatches(connection, args.runtime_role, relations, functions):
            raise RuntimeError("Effective grants differ after application")
    elif args.stage == "default-grants":
        apply_default_runtime_grants(connection, args.runtime_role)
        if default_acl_hazards(connection, args.migrator_role):
            raise RuntimeError("Other grantees still receive default access")


def run_stage(url, args):
    if args.stage not in MUTATIONS | {
        "parity",
        "runtime-acceptance",
        "security-reference",
        "security-check",
    }:
        raise RuntimeError("Unsupported or held transition stage")
    head, digest, _ = migration_identity()
    if args.expected_head != head or args.expected_migrations_sha256 != digest:
        raise RuntimeError("Reviewed migration identity differs")
    if make_url(url).get_backend_name() != "postgresql":
        raise ValueError("PostgreSQL required")
    security_result = None
    reference = None
    if args.stage == "security-reference" and not getattr(
        args, "disposable_reference", False
    ):
        raise RuntimeError("Disposable reference opt-in required")
    if args.stage == "security-check":
        from core.transition_security import load_reference

        reference = load_reference(
            args.security_reference, args.security_reference_sha256
        )
    url, profile_connect_args = connection_parameters(url)
    engine = create_engine(
        url,
        poolclass=NullPool,
        echo=False,
        hide_parameters=True,
        connect_args={"connect_timeout": 10, **profile_connect_args},
    )
    try:
        # Inspect under READ ONLY first; no grants can repair admission failure.
        with engine.connect().execution_options(
            isolation_level="REPEATABLE READ"
        ) as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SET LOCAL statement_timeout='30s'"))
                bind_connection(connection, args, args.stage == "runtime-acceptance")
                if args.stage != "migration":
                    relations, functions = require_current(
                        connection, runtime=args.stage == "runtime-acceptance"
                    )
                    require_runtime_admission(connection, args)
                    owner = connection.scalar(
                        text("SELECT oid FROM pg_roles WHERE rolname=:role"),
                        {"role": args.migrator_role},
                    )
                    if (
                        owner is None
                        or any(r["relowner"] != owner for r in relations)
                        or any(p["proowner"] != owner for p in functions)
                    ):
                        raise RuntimeError(
                            "Actual object creator differs from selected migrator"
                        )
                if args.stage == "runtime-acceptance":
                    assert_non_bypass_role(connection)
                    relations, functions, _, _ = object_inventory(connection)
                    if grant_mismatches(
                        connection, args.runtime_role, relations, functions
                    ) or default_acl_hazards(connection, args.migrator_role):
                        raise RuntimeError(
                            "Runtime effective/default ACL acceptance failed"
                        )
                if args.stage == "security-reference":
                    from core.transition_security import capture_reference

                    security_result = capture_reference(connection)
                elif args.stage == "security-check":
                    from core.transition_security import compare_installed

                    security_result = compare_installed(connection, reference)
                    if any(row["count"] for row in security_result):
                        raise RuntimeError("Installed security contract differs")
                connection.rollback()
        if args.stage in MUTATIONS:
            if not args.execute:
                raise RuntimeError("Explicit execution required")
            with engine.connect() as connection:
                with connection.begin():
                    connection.execute(text("SET LOCAL lock_timeout='5s'"))
                    connection.execute(text("SET LOCAL statement_timeout='120s'"))
                    apply_stage(connection, args)
                    # The context owns the only commit. An uncertain commit is
                    # reported as UNKNOWN by CLI, never as a durable success.
            # A fresh connection observes postconditions after the commit.
            with engine.connect() as connection:
                with connection.begin():
                    connection.execute(text("SET TRANSACTION READ ONLY"))
                    connection.execute(text("SET LOCAL statement_timeout='30s'"))
                    bind_connection(connection, args)
                    relations, functions = require_current(connection)
                    if args.stage != "migration":
                        require_runtime_admission(connection, args)
                    if args.stage == "current-grants" and grant_mismatches(
                        connection, args.runtime_role, relations, functions
                    ):
                        raise RuntimeError("Committed grant postcondition failed")
                    if args.stage == "default-grants" and default_acl_hazards(
                        connection, args.migrator_role
                    ):
                        raise RuntimeError("Committed default ACL postcondition failed")
                    connection.rollback()
        return {
            "contract": "vnbui-role-transition-stage/1",
            "stage": args.stage,
            "stage_pass": True,
            "ready": False,
            "planned_head": head,
            "migration_files_sha256": digest,
            "security_contract": security_result,
            "unmet": [
                "FINAL_SCHEMA_D08_D09_D11_ACCEPTANCE",
                "POLICY_FUNCTION_BODY_AND_RUNTIME_API_DENIAL_REHEARSAL",
                "EXTERNAL_SCHEMA_SEARCH_PATH_AND_EXTENSION_REVIEW",
                "QUIESCENCE_ROLLBACK_AND_CUTOVER",
            ],
        }
    finally:
        engine.dispose()
