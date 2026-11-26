"""Blocking PostgreSQL comparison; never create or repair application schema.

The DB-owned access_audit table is checked separately by migration acceptance.
Extra application DDL is not silently ignored.
"""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

from models import Base
from core.postgres_profile import connection_parameters


def _include_object(obj, name, kind, reflected, compare_to):
    return not (kind == "table" and reflected and name == "access_audit")


def _expression(value):
    # Reflection parenthesizes the single-column predicate in this schema.
    return " ".join(
        ("" if value is None else str(value)).strip().strip("()").split()
    ).lower()


def schema_differences(connection):
    if connection.dialect.name != "postgresql":
        raise RuntimeError(
            "Schema acceptance requires PostgreSQL; use DATABASE_URL=postgresql://... python -m core.schema_parity"
        )
    context = MigrationContext.configure(
        connection,
        opts={
            "compare_type": True,
            "compare_server_default": True,
            "include_object": _include_object,
        },
    )
    differences = compare_metadata(context, Base.metadata)
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    for table in Base.metadata.tables.values():
        if table.name not in tables:
            continue
        # Autogenerate does not compare primary keys or index predicates.
        actual_pk = inspector.get_pk_constraint(table.name)["constrained_columns"]
        expected_pk = [c.name for c in table.primary_key.columns]
        if actual_pk != expected_pk:
            differences.append(("primary_key", table.name, actual_pk, expected_pk))
        actual_indexes = {
            index["name"]: index for index in inspector.get_indexes(table.name)
        }
        for index in table.indexes:
            actual = actual_indexes.get(index.name)
            if actual is not None:
                expected_where = index.dialect_options["postgresql"].get("where")
                actual_where = actual.get("dialect_options", {}).get("postgresql_where")
                if _expression(expected_where) != _expression(actual_where):
                    differences.append(("index_predicate", table.name, index.name))
    return differences


def assert_schema_current(connection):
    differences = schema_differences(connection)
    if differences:
        raise RuntimeError(
            "Database schema differs from application metadata; run the reviewed "
            f"Alembic migration before starting the backend. Differences: {differences}"
        )
    count = connection.execute(
        text(
            "SELECT count(*) FROM organization_defaults d JOIN organizations o ON o.id=d.org_id WHERE d.slot='oss'"
        )
    ).scalar_one()
    if count != 1:
        raise RuntimeError(
            "OSS organization assignment is missing; run alembic upgrade head"
        )


if __name__ == "__main__":
    from config import settings
    from sqlalchemy import create_engine

    url, connect_args = connection_parameters(settings.database_url)
    with create_engine(url, connect_args=connect_args).connect() as connection:
        assert_schema_current(connection)
    print("PostgreSQL schema parity: PASS")
