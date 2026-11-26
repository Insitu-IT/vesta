"""Exact installed security comparison against a reviewed disposable reference.

The reference is an operator-reviewed build artifact, never a baseline learned
from the target. SQL bodies are hashed, not returned in findings or exceptions.
"""

import hashlib
import json

from sqlalchemy import text

from core.transition_preflight import migration_identity

LIMIT = 2 * 1024 * 1024
QUERIES = {
    "rls": """SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname""",
    "policies": """SELECT tablename,policyname,permissive,roles::text,cmd,qual,with_check
        FROM pg_policies WHERE schemaname='public' ORDER BY tablename,policyname""",
    "triggers": """SELECT c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,false)
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname""",
    "functions": """SELECT p.proname,pg_get_function_identity_arguments(p.oid),
        pg_get_functiondef(p.oid),p.prosecdef,p.proleakproof,p.provolatile,
        p.proparallel,p.proisstrict,p.proconfig::text
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.prokind IN ('f','p')
        ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)""",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def snapshot(connection):
    # Deparser qualification is search-path dependent. A fixed local path is
    # part of comparison, not a claim about the application's effective path.
    connection.execute(text("SET LOCAL search_path=pg_catalog"))
    result = {}
    for kind, query in QUERIES.items():
        rows = connection.execute(text(query)).fetchmany(4097)
        if len(rows) > 4096:
            raise ValueError("Security inventory exceeds contract bound")
        values = [list(row) for row in rows]
        raw = canonical(values)
        if len(raw) > LIMIT:
            raise ValueError("Security definitions exceed contract bound")
        result[kind] = {"count": len(values), "sha256": hashlib.sha256(raw).hexdigest()}
    return result


def capture_reference(connection):
    """Caller supplies a freshly migrated disposable DB, not the live target.

    Capture itself does not establish provenance: review and digest approval of
    the artifact are required separately. Never called by target acceptance.
    """
    head, digest, _ = migration_identity()
    if list(
        connection.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalars()
    ) != [head]:
        raise ValueError("Reference migration head differs")
    database, oid = connection.execute(
        text(
            "SELECT current_database(),oid FROM pg_database WHERE datname=current_database()"
        )
    ).one()
    return {
        "contract": "vnbui-installed-security/2",
        "head": head,
        "migrations_sha256": digest,
        "postgres_major": int(connection.scalar(text("SHOW server_version_num")))
        // 10000,
        "reference_database": database,
        "reference_database_oid": oid,
        "reference_system_identifier": str(
            connection.scalar(
                text("SELECT system_identifier FROM pg_catalog.pg_control_system()")
            )
        ),
        "objects": snapshot(connection),
    }


def compare_installed(connection, reference):
    head, digest, _ = migration_identity()
    if (
        set(reference)
        != {
            "contract",
            "head",
            "migrations_sha256",
            "postgres_major",
            "reference_database",
            "reference_database_oid",
            "reference_system_identifier",
            "objects",
        }
        or reference["contract"] != "vnbui-installed-security/2"
        or reference["head"] != head
        or reference["migrations_sha256"] != digest
        or reference["postgres_major"]
        != int(connection.scalar(text("SHOW server_version_num"))) // 10000
        or set(reference["objects"]) != set(QUERIES)
        or not isinstance(reference["reference_system_identifier"], str)
        or not reference["reference_system_identifier"].isascii()
        or not reference["reference_system_identifier"].isdigit()
        or not 0 < int(reference["reference_system_identifier"]) < 2**64
        or type(reference["reference_database_oid"]) is not int
        or not 0 < reference["reference_database_oid"] < 2**32
    ):
        raise ValueError("Reviewed security reference differs")
    _, oid = connection.execute(
        text(
            "SELECT current_database(),oid FROM pg_database WHERE datname=current_database()"
        )
    ).one()
    # Names and OIDs are cluster-local. Physical clones intentionally share
    # this identity and cannot serve as independent build provenance.
    system_identifier = str(
        connection.scalar(
            text("SELECT system_identifier FROM pg_catalog.pg_control_system()")
        )
    )
    if (
        not system_identifier.isascii()
        or not system_identifier.isdigit()
        or not 0 < int(system_identifier) < 2**64
    ):
        raise ValueError("Cluster identity unavailable")
    if (system_identifier, oid) == (
        reference["reference_system_identifier"],
        reference["reference_database_oid"],
    ):
        raise ValueError("Target cannot be its own security reference")
    actual = snapshot(connection)
    return [
        {
            "code": "INSTALLED_" + kind.upper() + "_DRIFT",
            "count": int(actual[kind] != reference["objects"][kind]),
        }
        for kind in QUERIES
    ]


def load_reference(path, expected_sha256):
    # Bounded read; no raw JSON/SQL/exception is emitted by the operator CLI.
    with open(path, "rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Reviewed security artifact digest differs")
    return json.loads(raw)
