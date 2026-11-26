"""Opt-in source smoke against a disposable local PostgreSQL service."""

from contextlib import closing, contextmanager
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.fernet import Fernet
import psycopg2
from psycopg2 import sql
from sqlalchemy.engine import make_url

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1] / "backend"
LOCAL_HTTP = build_opener(ProxyHandler({}))


class SmokeFailure(RuntimeError):
    pass


def failure_summary(stage, error):
    original = getattr(error, "orig", error)
    state = getattr(original, "pgcode", None)
    state = (
        state
        if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state)
        else "unavailable"
    )
    frames = " -> ".join(
        f"{Path(frame.filename).name}:{frame.lineno} ({frame.name})"
        for frame in traceback.extract_tb(error.__traceback__)[-18:]
    )
    return (
        f"Community PostgreSQL smoke failed during {stage} "
        f"({type(error).__name__}, SQLSTATE {state}). Frames {frames or 'unavailable'}."
    )


@contextmanager
def smoke_stage(name):
    try:
        yield
    except SmokeFailure:
        raise
    except Exception as error:
        raise SmokeFailure(failure_summary(name, error)) from None


def dsn(url):
    return url.render_as_string(hide_password=False)


@contextmanager
def disposable_database(admin):
    suffix = secrets.token_hex(8)
    database = f"vesta_smoke_{suffix}"
    owner = f"vesta_owner_{suffix}"
    runtime = f"vesta_runtime_{suffix}"
    owner_password, runtime_password = (secrets.token_urlsafe(32) for _ in range(2))
    owner_url = admin.set(database=database, username=owner, password=owner_password)
    runtime_url = admin.set(
        database=database, username=runtime, password=runtime_password
    )
    created_roles = []
    created_database = False

    with (
        smoke_stage("database fixture provisioning"),
        closing(psycopg2.connect(dsn(admin), connect_timeout=5)) as controller,
    ):
        controller.autocommit = True
        with controller.cursor() as cursor:
            try:
                for role, password in (
                    (owner, owner_password),
                    (runtime, runtime_password),
                ):
                    cursor.execute(
                        sql.SQL(
                            "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB "
                            "NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD %s"
                        ).format(sql.Identifier(role)),
                        (password,),
                    )
                    created_roles.append(role)
                database_id, owner_id, runtime_id = map(
                    sql.Identifier, (database, owner, runtime)
                )
                cursor.execute(
                    sql.SQL("CREATE DATABASE {} OWNER {}").format(database_id, owner_id)
                )
                created_database = True
                cursor.execute(
                    sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database_id)
                )
                cursor.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(
                        database_id, owner_id, runtime_id
                    )
                )
                # Match the PostgreSQL image bootstrap. A NOINHERIT owner
                # needs its own public schema grant on PostgreSQL 15.
                with (
                    smoke_stage("public schema privileges"),
                    closing(
                        psycopg2.connect(
                            dsn(admin.set(database=database)), connect_timeout=5
                        )
                    ) as connection,
                ):
                    connection.autocommit = True
                    with connection.cursor() as schema:
                        schema.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                        schema.execute(
                            sql.SQL(
                                "GRANT USAGE, CREATE ON SCHEMA public TO {}"
                            ).format(owner_id)
                        )
                        schema.execute(
                            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                                runtime_id
                            )
                        )
                yield owner_url, runtime_url
            finally:
                with smoke_stage("database fixture cleanup"):
                    if created_database:
                        cursor.execute(
                            sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                                sql.Identifier(database)
                            )
                        )
                    for role in reversed(created_roles):
                        cursor.execute(
                            sql.SQL("DROP ROLE {}").format(sql.Identifier(role))
                        )


def api_json(base, path, *, data=None, payload=None, token=None, timeout=3):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = Request(base + path, data=data, headers=headers)
    with LOCAL_HTTP.open(request, timeout=timeout) as response:
        return json.load(response)


def serve_backend(listener_fd, diagnostics_fd):
    """Run the real API with a separate channel for redacted startup failures."""
    with os.fdopen(diagnostics_fd, "w", encoding="utf-8") as diagnostics:
        try:
            import uvicorn

            from app import app
            from server import configuration

            options = configuration()
        except Exception as error:
            diagnostics.write(
                failure_summary("backend import and configuration", error)
            )
            raise

        async def application(scope, receive, send):
            try:
                await app(scope, receive, send)
            except Exception as error:
                if scope["type"] == "lifespan":
                    diagnostics.write(failure_summary("backend lifespan", error))
                    diagnostics.flush()
                raise

        with socket.socket(fileno=listener_fd) as listener:
            uvicorn.Server(uvicorn.Config(application, lifespan="on", **options)).run(
                sockets=[listener]
            )


@contextmanager
def running_backend(environment):
    with socket.socket() as listener, tempfile.TemporaryFile() as diagnostics:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        base = f"http://127.0.0.1:{listener.getsockname()[1]}"
        with subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--serve-backend",
                str(listener.fileno()),
                str(diagnostics.fileno()),
            ],
            cwd=BACKEND,
            env=environment,
            pass_fds=(listener.fileno(), diagnostics.fileno()),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        ) as backend:
            listener.close()
            try:
                deadline = time.monotonic() + 45
                while backend.poll() is None and time.monotonic() < deadline:
                    try:
                        ready = api_json(base, "/ready", timeout=1)
                        if ready["checks"]["database"]["status"] == "ok":
                            break
                    except OSError:
                        time.sleep(0.25)
                else:
                    state = backend.poll()
                    outcome = (
                        "readiness timeout" if state is None else f"exit code {state}"
                    )
                    diagnostics.seek(0)
                    failure = diagnostics.read(4096).decode("utf-8", errors="replace")
                    raise SmokeFailure(
                        f"Curated backend did not become ready ({outcome}). {failure}".rstrip()
                    )
                yield base
            finally:
                if backend.poll() is None:
                    backend.terminate()
                    try:
                        backend.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        backend.kill()
                        backend.wait()
                        raise SmokeFailure("Curated backend did not shut down in time.")


def seed_usage_fixture(admin, database, user_id, organization):
    """Seed reader specimens in the disposable database created by this smoke."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from models import Agent, Backup, StorageLineageGeneration, VM

    engine = create_engine(admin.set(database=database), hide_parameters=True)
    try:
        with Session(engine) as db:
            agents = [
                Agent(org_id=organization, hostname=f"fixture-{i}") for i in range(3)
            ]
            db.add_all(agents)
            db.flush()
            vm = VM(org_id=organization, agent_id=agents[0].id, name="usage-fixture")
            db.add(vm)
            db.flush()
            backups = [
                Backup(
                    org_id=organization,
                    vm_id=vm.id,
                    status="completed",
                    authority_kind="human",
                    initiating_user_id=user_id,
                    tags={"imported_from_s3": "historical label"},
                )
                for _ in range(102)
            ]
            db.add_all(backups)
            db.flush()
            for backup in backups[:101]:
                db.add(
                    StorageLineageGeneration(
                        id=str(uuid.uuid4()),
                        org_id=organization,
                        vm_id=vm.id,
                        backup_id=backup.id,
                        root_backup_id=backup.id,
                        state="accepted",
                        receipt_sha256="a" * 64,
                        root_receipt_sha256="a" * 64,
                        manifest_receipt_sha256="b" * 64,
                        tracker_uid="fixture",
                        checkpoint="fixture",
                        accepted_request={},
                    )
                )
            db.commit()
    finally:
        engine.dispose()


def sign_in(base, password, *, seeded=False):
    form = urlencode({"username": "admin", "password": password}).encode()
    login = api_json(base, "/api/v1/auth/login", data=form)
    profile = api_json(base, "/api/v1/auth/me", token=login["access_token"])
    assert profile["username"] == "admin" and profile["role"] == "admin"
    assert profile["is_active"] and profile["can_manage_installation"]
    assert profile["id"] and profile["org_id"]
    status = api_json(base, "/api/v1/licensing/status", token=login["access_token"])
    assert status["status"] == ("required" if seeded else "not_required")
    details = api_json(base, "/api/v1/licensing", token=login["access_token"])
    assert details["status"] == status
    usage = details["community_usage"]
    assert (
        usage["successful_backups"],
        usage["inventoried_vms"],
        usage["registered_agents"],
    ) == ((101, 1, 3) if seeded else (0, 0, 0))
    assert usage["threshold_reached"] is seeded
    if seeded:
        token = login["access_token"]
        route = "/api/v1/licensing/acknowledgement/"
        preview = api_json(
            base, route + "prepare", token=token, payload={"confirm": True}
        )
        api_json(
            base,
            route + "confirm",
            token=token,
            payload={
                "challenge": preview["challenge"],
                "phrase": preview["expected_phrase"],
                "confirm": True,
            },
        )
        assert api_json(base, "/api/v1/licensing/status", token=token)["acknowledged"]
    return profile["id"], profile["org_id"]


def check_runtime_schema(runtime):
    with (
        closing(psycopg2.connect(dsn(runtime), connect_timeout=5)) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT has_schema_privilege(current_user, 'public', 'USAGE'), "
            "has_schema_privilege(current_user, 'public', 'CREATE'), "
            "to_regclass('organization_defaults') IS NOT NULL"
        )
        if cursor.fetchone() != (True, False, True):
            raise SmokeFailure(
                "Runtime requires schema USAGE and lookup without CREATE."
            )


def main():
    raw_url = os.environ.get("SCHEMA_PARITY_TEST_ADMIN_URL")
    if os.getenv("VESTA_DISPOSABLE_POSTGRES", os.getenv("VNBUI_DISPOSABLE_POSTGRES")) != "1" or not raw_url:
        raise SystemExit(
            "Select the disposable PostgreSQL service before running the smoke."
        )
    admin = make_url(raw_url)
    if (
        admin.drivername != "postgresql"
        or admin.database != "postgres"
        or admin.host not in {"127.0.0.1", "localhost", "postgres"}
        or admin.query
    ):
        raise SystemExit(
            "Use the local test service's postgres database without URL options."
        )

    spec = spec_from_file_location("quickstart", HERE / "start-local.py")
    quickstart = module_from_spec(spec)
    spec.loader.exec_module(quickstart)
    with (
        disposable_database(admin) as (owner, runtime),
        tempfile.TemporaryDirectory() as work,
    ):
        quickstart.DATABASE = owner.database
        quickstart.RUNTIME_ROLE = runtime.username
        with smoke_stage("fresh schema installation"):
            quickstart.prepare_schema(dsn(owner))
        with smoke_stage("runtime schema privilege check"):
            check_runtime_schema(runtime)

        password = secrets.token_urlsafe(32) + "Aa1!"
        password_file = Path(work) / "password"
        password_file.write_text(password, encoding="ascii")
        password_file.chmod(0o600)
        legacy_license = Path(work) / "legacy-license.fifo"
        os.mkfifo(legacy_license, 0o600)
        environment = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "LD_LIBRARY_PATH": str(Path(sys.base_prefix) / "lib"),
            "PYTHONPATH": os.pathsep.join(
                str(path)
                for path in (BACKEND.parent, BACKEND, BACKEND.parent / "agent")
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
            "DATABASE_URL": dsn(runtime),
            "JWT_SECRET": secrets.token_urlsafe(32),
            "VNBUI_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            "VNBUI_ARTIFACT_EDITION": "community",
            "INITIAL_ADMIN_USERNAME": "admin",
            "INITIAL_ADMIN_PASSWORD_FILE": str(password_file),
            "LICENSE_FILE": str(legacy_license),
            "LICENSE_REGISTRATION_URL": "",
            "LICENSE_KEYS_FILE": str(Path(work) / "license-keys.json"),
        }
        with (
            smoke_stage("initial runtime startup and login"),
            running_backend(environment) as base,
        ):
            first_identity = sign_in(base, password)

        with smoke_stage("disposable accepted generation reader fixtures"):
            seed_usage_fixture(admin, owner.database, *first_identity)

        with smoke_stage("current schema check"):
            quickstart.prepare_schema(dsn(owner))
        password_file.unlink()
        with (
            smoke_stage("runtime restart and persisted login"),
            running_backend(environment) as base,
        ):
            assert sign_in(base, password, seeded=True) == first_identity

    print("Community PostgreSQL schema, runtime login and restart checks passed.")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--serve-backend":
        serve_backend(int(sys.argv[2]), int(sys.argv[3]))
        raise SystemExit(0)
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit(failure_summary("smoke setup", error)) from None
