"""One enforcement attachment for synchronous and async SQL engines."""

from sqlalchemy import event
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import RollbackToSavepointClause

from core.tenant_context import install_cursor_context, identity, is_demo


class TenantSession(Session):
    """The ORM identity map must not serve a previous scope without SQL/RLS."""

    def check_identity(self):
        if self.get_bind().dialect.name != "postgresql":
            return
        scope = (identity(), is_demo.get())
        previous = self.info.get("tenant_identity", scope)
        if previous != scope:
            if self.new or self.dirty or self.deleted:
                raise RuntimeError(
                    "Tenant change with pending writes; commit or rollback before changing identity"
                )
            self.expunge_all()
        self.info["tenant_identity"] = scope

    def get(self, *args, **kwargs):
        self.check_identity()
        return super().get(*args, **kwargs)

    def flush(self, *args, **kwargs):
        self.check_identity()
        return super().flush(*args, **kwargs)


@event.listens_for(TenantSession, "do_orm_execute")
def before_orm(execution):
    execution.session.check_identity()


def install_tenant_enforcement(engine):
    if engine.dialect.name != "postgresql":
        return
    if getattr(engine, "_tenant_enforcement", False):
        return
    engine._tenant_enforcement = True

    @event.listens_for(engine, "connect")
    def validate_runtime_role(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:

            def read(sql):
                cursor.execute(sql)
                return cursor.fetchone()[0]

            _validate_runtime_role(read)
        finally:
            cursor.close()
            dbapi_connection.rollback()

    @event.listens_for(engine, "before_cursor_execute")
    def before_sql(connection, cursor, statement, parameters, context, executemany):
        # PostgreSQL rejects set_config while recovering an aborted savepoint.
        # This typed transaction-control statement cannot read or mutate tenant
        # data. The next application statement reinstalls its current identity.
        if context.compiled is not None and isinstance(
            context.compiled.statement, RollbackToSavepointClause
        ):
            return
        install_cursor_context(cursor, engine.dialect.paramstyle)


def assert_non_bypass_role(connection):
    from sqlalchemy import text

    _validate_runtime_role(lambda sql: connection.execute(text(sql)).scalar_one())


def _validate_runtime_role(read):
    """Shared by connect hooks (sync/async) and explicit operator preflight."""
    if read(
        "SELECT rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR "
        "rolreplication OR rolinherit FROM pg_roles WHERE rolname=current_user"
    ):
        raise RuntimeError(
            "Application role must be NOSUPERUSER NOBYPASSRLS NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOINHERIT; see database role transition runbook"
        )
    memberships = read(
        "SELECT EXISTS (SELECT 1 FROM pg_auth_members "
        "WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))"
    )
    if memberships:
        raise RuntimeError(
            "Application role must have no role memberships, including SET ROLE paths"
        )
    owns_tables = read(
        "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)"
    )
    if owns_tables:
        raise RuntimeError(
            "Application role must not own tables; use separate migration owner"
        )
    owns_objects = read("""
        SELECT EXISTS (
            SELECT 1 FROM pg_database WHERE datname=current_database()
              AND datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)
            UNION ALL SELECT 1 FROM pg_namespace WHERE nspname='public'
              AND nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
            UNION ALL SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='public' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
            UNION ALL SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='public' AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
        )
    """)
    if owns_objects:
        raise RuntimeError(
            "Application role must not own database, schema, relations or functions"
        )
    if read("SELECT has_schema_privilege(current_user,'public','CREATE')"):
        raise RuntimeError(
            "Application role must not have CREATE on application schema"
        )
