"""D10 inspection and explicit operator stages; not deployment authorization."""

import argparse
import hashlib
import json
import logging
import os
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from pathlib import Path
import re

from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from core.postgres_profile import connection_parameters

from core.table_scope import SCOPES

BACKEND = Path(__file__).resolve().parents[1]
USAGE = (
    "PYTHONPATH=backend python3 -m core.transition_preflight preflight "
    "--dsn-env VNBUI_TRANSITION_OWNER_DSN --runtime-role vnbui_runtime"
)
STAGES = (
    "preflight",
    "migration",
    "parity",
    "current-grants",
    "default-grants",
    "runtime-acceptance",
    "security-reference",
    "security-check",
    "cutover",
)


@contextmanager
def redacted_execution():
    """CLI-only sink: legacy migration diagnostics must not become an artifact.

    Discard rather than buffer unbounded output. The standalone CLI never runs
    inside the API; restoring logging is still required for embedded tests.
    """

    class Sink:
        def write(self, value):
            return len(value)

        def flush(self):
            pass

    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with redirect_stdout(Sink()), redirect_stderr(Sink()):
            yield
    finally:
        logging.disable(previous)


def migration_identity():
    directory = BACKEND / "alembic"
    script = ScriptDirectory(str(directory))
    heads = script.get_heads()
    if len(heads) != 1:
        raise ValueError("Single migration head required")
    digest = hashlib.sha256()
    for path in sorted((directory / "versions").glob("*.py")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return heads[0], digest.hexdigest(), {r.revision for r in script.walk_revisions()}


def inspect_snapshot(connection, runtime_role):
    """Caller supplies a read-only, repeatable-read PostgreSQL transaction.

    Findings contain fixed codes/counts only, never row values, role names, DSNs,
    defaults, SQL errors, password hashes or credential identifiers.
    """
    if connection.dialect.name != "postgresql":
        raise ValueError("PostgreSQL required")
    if connection.scalar(text("SHOW transaction_read_only")) != "on":
        raise ValueError("Read-only transaction required")
    if connection.scalar(text("SHOW transaction_isolation")) != "repeatable read":
        raise ValueError("Repeatable-read snapshot required")
    head, digest, revisions = migration_identity()
    findings = []

    def record(code, count=None):
        row = {"code": code}
        if count is not None:
            row["count"] = int(count)
        findings.append(row)

    inspector = inspect(connection)
    tables = set(inspector.get_table_names(schema="public"))
    expected = set(SCOPES) | {"alembic_version"}
    record("UNKNOWN_PUBLIC_TABLES", len(tables - expected))
    record("MISSING_CURRENT_TABLES", len(expected - tables))
    for code, query in (
        (
            "PUBLIC_SEQUENCES_OBSERVED",
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S'",
        ),
        (
            "PUBLIC_FUNCTIONS_OBSERVED",
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n "
            "ON n.oid=p.pronamespace WHERE n.nspname='public'",
        ),
        (
            "PUBLIC_OTHER_RELATIONS_UNCLASSIFIED",
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind NOT IN ('r','p','S','i','I','t')",
        ),
    ):
        record(code, connection.scalar(text(query)))
    versions = []
    if "alembic_version" in tables:
        versions = list(
            connection.execute(
                text("SELECT version_num FROM public.alembic_version")
            ).scalars()
        )
    if not tables:
        shape = "empty"
    elif len(versions) != 1 or versions[0] not in revisions:
        shape = "unrecognized_or_ambiguous"
    elif versions[0] == head:
        shape = "current_revision_unverified_parity"
    elif versions[0] == "add_demo_rate_buckets":
        shape = "measured_predecessor_revision_unverified_shape"
    else:
        shape = "prior_revision_unverified_shape"

    # Do not confuse a role-filtered/RLS-filtered view with complete attribution.
    observer = connection.execute(
        text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
    ).scalar_one()
    if not observer:
        record("ATTRIBUTION_UNINSPECTED_OBSERVER_VISIBILITY")
    else:
        if "organizations" in tables:
            count = connection.scalar(text("SELECT count(*) FROM public.organizations"))
            record("ORGANIZATION_ROWS", count)
            if count != 1:
                record("EXPLICIT_ATTRIBUTION_DECISION_REQUIRED")
        else:
            record("ORGANIZATION_AUTHORITY_ABSENT")
        # Only aggregate collision counts leave the connection. These are leads,
        # not permission to merge identities or delete credentials.
        for table, column, code in (
            ("agent_api_keys", "key_hash", "AGENT_CREDENTIAL_COLLISION_GROUPS"),
            (
                "orchestrator_api_keys",
                "key_hash",
                "ORCHESTRATOR_CREDENTIAL_COLLISION_GROUPS",
            ),
        ):
            columns = (
                {c["name"] for c in inspector.get_columns(table, schema="public")}
                if table in tables
                else set()
            )
            if column in columns:
                count = connection.scalar(
                    text(
                        f'SELECT count(*) FROM (SELECT "{column}" FROM public."{table}" '
                        f'WHERE "{column}" IS NOT NULL GROUP BY "{column}" HAVING count(*)>1) collisions'
                    )
                )
                record(code, count)
            else:
                record(code + "_UNINSPECTED")

    role = (
        connection.execute(
            text(
                "SELECT oid, rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, "
                "rolreplication, rolinherit FROM pg_roles WHERE rolname=:role"
            ),
            {"role": runtime_role},
        )
        .mappings()
        .one_or_none()
    )
    if role is None:
        record("RUNTIME_ROLE_ABSENT")
    else:
        record("RUNTIME_LOGIN_DISABLED", not role["rolcanlogin"])
        record(
            "RUNTIME_UNSAFE_FLAGS",
            sum(
                bool(role[key])
                for key in (
                    "rolsuper",
                    "rolbypassrls",
                    "rolcreatedb",
                    "rolcreaterole",
                    "rolreplication",
                    "rolinherit",
                )
            ),
        )
        params = {"role": runtime_role, "oid": role["oid"]}
        for code, query in (
            (
                "RUNTIME_MEMBERSHIPS",
                "SELECT count(*) FROM pg_auth_members WHERE member=:oid",
            ),
            (
                "RUNTIME_OWNED_OBJECTS",
                "SELECT count(*) FROM ("
                "SELECT oid FROM pg_database WHERE datname=current_database() AND datdba=:oid UNION ALL "
                "SELECT oid FROM pg_namespace WHERE nspname='public' AND nspowner=:oid UNION ALL "
                "SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public' AND c.relowner=:oid UNION ALL "
                "SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='public' AND p.proowner=:oid) owned",
            ),
            (
                "RUNTIME_SCHEMA_CREATE",
                "SELECT has_schema_privilege(:role,'public','CREATE')::int",
            ),
            (
                "RUNTIME_DATABASE_CREATE",
                "SELECT has_database_privilege(:role,current_database(),'CREATE')::int",
            ),
            (
                "RUNTIME_CONNECT_MISSING",
                "SELECT (NOT has_database_privilege(:role,current_database(),'CONNECT'))::int",
            ),
            (
                "RUNTIME_UNSAFE_TABLE_GRANTS",
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public' AND c.relkind IN ('r','p') AND "
                "has_table_privilege(:role,c.oid,'TRUNCATE,REFERENCES,TRIGGER')",
            ),
            (
                "RUNTIME_EXECUTABLE_PUBLIC_FUNCTIONS_OBSERVED",
                "SELECT count(*) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' "
                "AND has_function_privilege(:role,p.oid,'EXECUTE')",
            ),
        ):
            record(code, connection.scalar(text(query), params))

    # These gates cannot be discharged by this snapshot or by a candidate head.
    # In particular, revision equality is NOT schema parity or final-schema acceptance.
    return {
        "contract": "vnbui-role-transition-preflight/1",
        "ready": False,
        "planned_head": head,
        "migration_files_sha256": digest,
        "observed_shape": shape,
        "findings": findings,
        "unmet": [
            "FINAL_SCHEMA_D08_D09_D11_ACCEPTANCE",
            "RESOLVE_NONZERO_OR_UNKNOWN_INSPECTION_FINDINGS",
            "SCHEMA_PARITY_POLICY_AND_FUNCTION_BODY_ACCEPTANCE",
            "EXTERNAL_SCHEMA_SEARCH_PATH_AND_EXTENSION_REVIEW",
            "EXECUTE_AND_VERIFY_SEPARATE_GRANT_STAGES",
            "RUNTIME_AUTHENTICATED_DENIAL_ACCEPTANCE",
            "QUIESCENCE_AND_ROLLBACK_UNIT_OPERATOR_EVIDENCE",
        ],
    }


def preflight(url, runtime_role, migrator_role=None):
    if make_url(url).get_backend_name() != "postgresql":
        raise ValueError("PostgreSQL required")
    url, profile_connect_args = connection_parameters(url)
    engine = create_engine(
        url,
        poolclass=NullPool,
        echo=False,
        hide_parameters=True,
        connect_args={"connect_timeout": 10, **profile_connect_args},
    )
    try:
        with engine.connect().execution_options(
            isolation_level="REPEATABLE READ"
        ) as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SET LOCAL statement_timeout = '10s'"))
                connection.execute(text("SET LOCAL lock_timeout = '2s'"))
                result = inspect_snapshot(connection, runtime_role)
                from core.transition_contract import (
                    inspect_contract,
                    inspect_attribution,
                )

                result["object_acl_findings"] = inspect_contract(
                    connection, runtime_role, migrator_role
                )
                result["attribution_findings"] = inspect_attribution(connection)
                result["database_oid"] = connection.scalar(
                    text("SELECT oid FROM pg_database WHERE datname=current_database()")
                )
                connection.rollback()
                return result
    finally:
        engine.dispose()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Example: " + USAGE,
    )
    parser.add_argument("stage", choices=STAGES)
    parser.add_argument("--dsn-env", default="VNBUI_TRANSITION_OWNER_DSN")
    parser.add_argument("--runtime-role")
    parser.add_argument("--migrator-role")
    parser.add_argument("--database")
    parser.add_argument("--database-oid", type=int)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-migrations-sha256")
    parser.add_argument("--default-organization-id")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--security-reference")
    parser.add_argument("--security-reference-sha256")
    parser.add_argument("--disposable-reference", action="store_true")
    args = parser.parse_args(argv)
    if (
        args.stage == "cutover"
        or (args.stage == "security-reference" and not args.disposable_reference)
        or (
            args.stage == "security-check"
            and not (args.security_reference and args.security_reference_sha256)
        )
        or (
            args.stage != "preflight"
            and not all(
                (
                    args.runtime_role,
                    args.migrator_role,
                    args.database,
                    args.database_oid,
                    args.expected_head,
                    args.expected_migrations_sha256,
                )
            )
        )
        or (
            args.stage in {"migration", "current-grants", "default-grants"}
            and not args.execute
        )
    ):
        print(
            json.dumps({"code": "STAGE_EXECUTION_HELD", "ready": False, "usage": USAGE})
        )
        return 4
    if (
        not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", args.dsn_env)
        or not args.runtime_role
    ):
        print(
            json.dumps(
                {"code": "INVALID_INPUT_USE_HELP", "ready": False, "usage": USAGE}
            )
        )
        return 2
    url = os.environ.get(args.dsn_env)
    if not url:
        print(
            json.dumps(
                {"code": "MANAGED_DSN_INPUT_ABSENT", "ready": False, "usage": USAGE}
            )
        )
        return 2
    try:
        with redacted_execution():
            if args.stage == "preflight":
                result = (
                    preflight(url, args.runtime_role)
                    if args.migrator_role is None
                    else preflight(url, args.runtime_role, args.migrator_role)
                )
            else:
                from core.transition_stages import run_stage

                result = run_stage(url, args)
    except Exception:
        # DBAPI/SQLAlchemy exceptions can contain credentials, SQL and row values.
        print(
            json.dumps(
                {
                    "code": (
                        "PREFLIGHT_INCOMPLETE_CONNECTION_OR_QUERY"
                        if args.stage == "preflight"
                        else "STAGE_OUTCOME_UNKNOWN_INSPECT_BEFORE_RESTART"
                    ),
                    "ready": False,
                    "usage": USAGE,
                }
            )
        )
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("stage_pass") else 4


if __name__ == "__main__":
    raise SystemExit(main())
