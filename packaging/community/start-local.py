"""Prepare or start a disposable Community quickstart backend."""

import os
from pathlib import Path
import sys
from urllib.parse import quote

DATABASE = "vesta"
OWNER_ROLE = "vesta_owner"
RUNTIME_ROLE = "vesta_runtime"
SECRETS = Path("/run/secrets")


def secret(name):
    value = (SECRETS / name).read_text(encoding="ascii").rstrip("\r\n")
    if not value:
        raise ValueError("Quickstart secret is empty")
    return value


def database_url(role, password):
    return f"postgresql://{role}:{quote(password, safe='')}@postgres:5432/{DATABASE}"


def prepare_schema(url):
    from alembic.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import create_engine, text

    from core.portable_install import _configuration, _target, install_empty
    from core.schema_parity import assert_schema_current

    engine = create_engine(
        url, connect_args={"connect_timeout": 5}, hide_parameters=True
    )
    try:
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL lock_timeout = '30s'"))
            options = {"runtime_role": RUNTIME_ROLE, "expected_database": DATABASE}
            # Take the same lock and exercise the same database/role checks as
            # the portable installer, before observing schema state.
            _target(connection, **options)
            populated = connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_class "
                    "WHERE relnamespace='public'::regnamespace UNION ALL "
                    "SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace)"
                )
            )
            if not populated:
                install_empty(connection, **options)
                return
            present = MigrationContext.configure(connection).get_current_heads()
            expected = ScriptDirectory.from_config(
                _configuration(connection)
            ).get_heads()
            if tuple(expected) != present:
                raise RuntimeError("Schema revision differs from this checkout")
            assert_schema_current(connection)
    finally:
        engine.dispose()


def main(arguments):
    if arguments == ["migrate"]:
        try:
            prepare_schema(database_url(OWNER_ROLE, secret("owner-password")))
        except Exception as error:
            # Driver errors can contain connection data. Keep Compose logs safe.
            raise SystemExit(
                f"Quickstart schema preparation failed ({type(error).__name__}). "
                "Check database credentials and schema revision. This profile does not "
                "upgrade or erase existing databases."
            ) from None
        print("Quickstart database schema is current.")
        return

    if arguments == ["serve"]:
        try:
            environment = {
                **os.environ,
                "DATABASE_URL": database_url(RUNTIME_ROLE, secret("runtime-password")),
                "JWT_SECRET": secret("jwt-secret"),
                "VESTA_ENCRYPTION_KEY": secret("fernet-key"),
            }
        except (OSError, ValueError):
            raise SystemExit(
                "Quickstart runtime secrets are missing or invalid."
            ) from None
        command = ["opentelemetry-instrument", "python", "server.py"]
        os.execvpe(command[0], command, environment)
    else:
        raise SystemExit("Use start-local.py migrate or start-local.py serve.")


if __name__ == "__main__":
    main(sys.argv[1:])
