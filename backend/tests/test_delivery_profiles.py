"""Offline transport/profile adversarial tests; no database or registry effects."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging/okd"))
sys.path.insert(0, str(ROOT / "backend"))
from backend.tests.test_portable_kit import (  # noqa: E402
    kit,
    config as kit_config,
    oci_fixture,
)
from backend.tests.test_portable_okd import renderer  # noqa: E402


@pytest.fixture
def config():
    return kit_config.__wrapped__()


def image_kit(tmp_path, profile="customer-postgresql"):
    root = tmp_path / "images"
    root.mkdir()
    images = {}
    for component in ["backend", "frontend", "agent"] + (
        ["postgres"] if profile == "full" else []
    ):
        images[component] = oci_fixture(root / component)
        (root / (component + ".digest")).write_text(images[component])
    kit.finish(root, "images", {"images": images, "delivery_profile": profile})
    return root


@pytest.mark.parametrize("profile,count", [("full", 4), ("customer-postgresql", 3)])
def test_profile_inventory(tmp_path, profile, count):
    root = image_kit(tmp_path, profile)
    manifest = kit.verify(root)
    assert len(manifest["metadata"]["images"]) == count
    assert manifest["metadata"]["supply_contract"]["profile"] == profile


@pytest.mark.parametrize(
    "extra", ["postgres/blobs/sha256/" + "e" * 64, "backend/blobs/sha256/" + "e" * 64]
)
def test_retained_database_or_orphan_blob_refused_even_with_rehashed_manifest(
    tmp_path, extra
):
    root = image_kit(tmp_path)
    path = root / extra
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"retained database image layer")
    metadata = json.loads((root / "manifest.json").read_text())["metadata"]
    (root / "manifest.json").unlink()
    kit.finish(root, "images", metadata)
    with pytest.raises(ValueError, match="retained/unreferenced"):
        kit.verify(root)


def test_profile_relabel_rejected(tmp_path):
    root = image_kit(tmp_path, "full")
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["metadata"]["delivery_profile"] = "customer-postgresql"
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="profile contradicts"):
        kit.verify(root)


def test_blob_mutation_rehashed_outer_manifest_still_refused(tmp_path):
    root = image_kit(tmp_path)
    next((root / "backend/blobs/sha256").iterdir()).write_bytes(b"changed")
    metadata = json.loads((root / "manifest.json").read_text())["metadata"]
    (root / "manifest.json").unlink()
    kit.finish(root, "images", metadata)
    with pytest.raises(ValueError, match="descriptor content"):
        kit.verify(root)


def test_customer_export_forbids_pg_config_before_copy(config, tmp_path):
    with patch.object(kit.subprocess, "run") as run:
        with pytest.raises(ValueError, match="forbids"):
            kit.export_images(
                config, tmp_path / "out", {}, profile="customer-postgresql"
            )
        run.assert_not_called()


@pytest.mark.parametrize(
    "stage", ["migrate", "restore-grants", "upgrade", "rollback-schema"]
)
def test_all_schema_stages_forward_customer_profile_and_owner_tls(config, stage):
    config["delivery_profile"] = "customer-postgresql"
    container = renderer.render(config, stage)["items"][0]["spec"]["template"]["spec"][
        "containers"
    ][0]
    env = {item["name"]: item for item in container["env"]}
    assert env["VESTA_DELIVERY_PROFILE"]["value"] == "customer-postgresql"
    assert env["PGSSLMODE"]["value"] == "verify-full"
    assert env["PGSSLROOTCERT"]["value"] == "/trust/ca.crt"
    assert "owner" in env["DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"]


def load_install():
    spec = importlib.util.spec_from_file_location(
        "profile_portable_install", ROOT / "backend/core/portable_install.py"
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            name: SimpleNamespace(**attributes)
            for name, attributes in {
                "core.runtime_grants": {
                    "apply_current_runtime_grants": None,
                    "apply_default_runtime_grants": None,
                },
                "core.schema_parity": {"assert_schema_current": None},
            }.items()
        },
    ):
        spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "version,sslmode,ca,encrypted,extension,standby",
    [
        (160010, "verify-full", "/trust/ca.crt", True, True, False),
        (180001, "verify-full", "/trust/ca.crt", True, True, False),
        (170005, "require", "/trust/ca.crt", True, True, False),
        (170005, "verify-full", "", True, True, False),
        (170005, "verify-full", "/trust/ca.crt", False, True, False),
        (170005, "verify-full", "/trust/ca.crt", True, False, False),
        (170005, "verify-full", "/trust/ca.crt", True, True, True),
    ],
)
def test_customer_prerequisite_refusal(
    monkeypatch, version, sslmode, ca, encrypted, extension, standby
):
    module = load_install()
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    statements = []

    def scalar(sql):
        statements.append(str(sql))
        if "default_transaction_read_only" in str(sql):
            return "off"
        return standby if "pg_is_in_recovery" in str(sql) else extension

    db = SimpleNamespace(
        scalar=scalar,
        connection=SimpleNamespace(
            driver_connection=SimpleNamespace(
                get_dsn_parameters=lambda: {"sslmode": sslmode, "sslrootcert": ca},
                info=SimpleNamespace(ssl_in_use=encrypted),
            )
        ),
    )
    with pytest.raises(RuntimeError):
        module._customer_prerequisites(db, version)
    assert all(sql.startswith("SELECT ") for sql in statements)


def test_customer_prerequisites_accept_verified_connection(monkeypatch):
    module = load_install()
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    db = SimpleNamespace(
        scalar=lambda sql: (
            "off"
            if "default_transaction_read_only" in str(sql)
            else "pg_extension" in str(sql)
        ),
        connection=SimpleNamespace(
            driver_connection=SimpleNamespace(
                get_dsn_parameters=lambda: {
                    "sslmode": "verify-full",
                    "sslrootcert": "/trust/ca.crt",
                },
                info=SimpleNamespace(ssl_in_use=True),
            )
        ),
    )
    module._customer_prerequisites(db, 170005)


@pytest.mark.parametrize("mode", ["require", "disable", "prefer", "verify-ca"])
def test_runtime_and_owner_tls_downgrade_refused(monkeypatch, mode):
    from core.postgres_profile import (
        connection_parameters,
        CustomerPostgresPrerequisiteError,
    )

    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/ca.crt")
    for asynchronous in (False, True):
        with pytest.raises(CustomerPostgresPrerequisiteError, match="verify-full"):
            connection_parameters(
                "postgresql://user:secret@db/vesta?sslmode=" + mode,
                asynchronous=asynchronous,
            )


def test_async_custom_ca_preserves_password_and_unrelated_query(monkeypatch):
    from core import postgres_profile
    from sqlalchemy.engine import make_url

    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    context = SimpleNamespace(verify_mode=2, check_hostname=True)
    with patch.object(
        postgres_profile.ssl, "create_default_context", return_value=context
    ) as create:
        url, args = postgres_profile.connection_parameters(
            "postgresql+asyncpg://user:p%40ss%3Aw%2Ford@db/vesta?sslmode=verify-full"
            "&sslrootcert=%2Ftrust%2Fcustom-ca.crt&application_name=Vesta%20runtime",
            asynchronous=True,
        )
        create.assert_called_once_with(cafile="/trust/custom-ca.crt")
    assert args == {"ssl": context}
    parsed = make_url(url)
    assert parsed.password == "p@ss:w/ord"
    assert parsed.query == {"application_name": "Vesta runtime"}


def test_sync_custom_ca_and_full_profile_compatibility(monkeypatch):
    from core.postgres_profile import connection_parameters

    url = "postgresql://user:secret@db/vesta?sslmode=verify-full&sslrootcert=%2Ftrust%2Fca.crt"
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    assert connection_parameters(url) == (
        url,
        {
            "sslmode": "verify-full",
            "sslrootcert": "/trust/ca.crt",
            "gssencmode": "disable",
        },
    )
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "full")
    old = "postgresql://user:secret@db/vesta?sslmode=require"
    assert connection_parameters(old, asynchronous=True) == (old, {})


def test_customer_profile_disables_dedicated_database_renderer(config):
    import postgres

    config["delivery_profile"] = "customer-postgresql"
    with pytest.raises(ValueError, match="rendering is disabled"):
        postgres.render(config, {})


def test_customer_release_example_and_static_schema_base_keep_guard(tmp_path):
    root = image_kit(tmp_path)
    release = tmp_path / "release"
    kit.assemble_release(root, release, "a" * 40)
    manifest = kit.verify(release)
    assert manifest["metadata"]["delivery_profile"] == "customer-postgresql"
    assert (
        json.loads((release / "install/config.example.json").read_text())[
            "delivery_profile"
        ]
        == "customer-postgresql"
    )
    jobs = list((release / "install/kustomize/base/migrate").glob("*.json"))
    job = json.loads(jobs[0].read_text())
    assert {
        v["name"]: v for v in job["spec"]["template"]["spec"]["containers"][0]["env"]
    }["VESTA_DELIVERY_PROFILE"]["value"] == "customer-postgresql"
    assert (release / "runbooks/supply-support.md").is_file()


def test_readonly_preflight_does_not_acquire_lock_or_change_grants(monkeypatch):
    from unittest.mock import MagicMock

    module = load_install()
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "full")
    db = MagicMock()
    db.dialect.name = "postgresql"
    db.execute.return_value.one.return_value = ("vesta", "schema_owner", 170005)
    db.execute.return_value.mappings.return_value.one_or_none.return_value = {
        "oid": 123,
        "rolcanlogin": True,
        "unsafe": False,
    }
    db.scalar.return_value = False
    assert module._target(db, "runtime", "vesta", lock=False) == "vesta"
    statements = [
        str(call.args[0])
        for call in db.execute.call_args_list + db.scalar.call_args_list
    ]
    assert all(
        sql.startswith("SELECT ") and "advisory" not in sql for sql in statements
    )


def test_release_refuses_extra_database_archive_after_manifest_rehash(tmp_path):
    root = image_kit(tmp_path)
    release = tmp_path / "release"
    kit.assemble_release(root, release, "a" * 40)
    (release / "postgres.oci.tar").write_bytes(b"hidden database payload")
    metadata = json.loads((release / "manifest.json").read_text())["metadata"]
    (release / "manifest.json").unlink()
    kit.finish(release, "release", metadata)
    with pytest.raises(ValueError, match="closed customer inventory"):
        kit.verify(release)


@pytest.mark.parametrize("stage", renderer.STAGES)
def test_customer_profile_survives_real_offline_kustomize(config, stage, tmp_path):
    import shutil
    import subprocess

    import yaml

    oc_binary = shutil.which("oc")
    assert oc_binary, "oc is required for offline Kustomize parity"
    config["delivery_profile"] = "customer-postgresql"
    target = tmp_path / stage
    renderer.write_kustomize(config, stage, target)
    actual = list(
        yaml.safe_load_all(
            subprocess.check_output([oc_binary, "kustomize", str(target)], text=True)
        )
    )
    expected = renderer.render(config, stage)["items"]

    def identity(item):
        return item["kind"], item["metadata"]["name"]

    assert {identity(item): item for item in actual} == {
        identity(item): item for item in expected
    }


@pytest.mark.parametrize(
    "url",
    [
        "postgresql:///vesta",
        "postgresql://user:secret@/vesta",
        "postgresql://user:secret@%2Ftmp/vesta",
        "postgresql://user:secret@db/vesta?host=%2Fvar%2Frun%2Fpostgresql",
        "postgresql://user:secret@db/vesta?host=%40abstract-socket",
        "postgresql://user:secret@db/vesta?host=",
        "postgresql://user:secret@db/vesta?host=db1%2C",
        "postgresql://user:secret@db/vesta?host=db1&host=%2Ftmp",
    ],
)
def test_socket_or_empty_effective_host_refused_before_connection(monkeypatch, url):
    from core.postgres_profile import (
        CustomerPostgresPrerequisiteError,
        connection_parameters,
    )

    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/ca.crt")
    monkeypatch.setenv("PGHOST", "environment-fallback.example")
    for asynchronous in (False, True):
        with pytest.raises(
            CustomerPostgresPrerequisiteError, match="explicit TCP host"
        ):
            connection_parameters(url, asynchronous=asynchronous)
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "full")
    assert connection_parameters(url) == (url, {})


@pytest.mark.parametrize("source", ["query", "environment"])
@pytest.mark.parametrize("mode", ["prefer", "require"])
def test_gss_transport_cannot_replace_customer_tls(monkeypatch, source, mode):
    from core.postgres_profile import (
        CustomerPostgresPrerequisiteError,
        connection_parameters,
    )

    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/ca.crt")
    url = "postgresql://user:secret@db/vesta"
    if source == "query":
        url += "?gssencmode=" + mode
    else:
        monkeypatch.setenv("PGGSSENCMODE", mode)
    for asynchronous in (False, True):
        with pytest.raises(
            CustomerPostgresPrerequisiteError, match="gssencmode=disable"
        ):
            connection_parameters(url, asynchronous=asynchronous)


def test_tcp_query_override_preserves_supported_parameters(monkeypatch):
    from core import postgres_profile
    from sqlalchemy.engine import make_url

    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    monkeypatch.setenv("PGSSLROOTCERT", "/trust/ca.crt")
    url = (
        "postgresql+asyncpg://user:p%40ss%3Aw%2Ford@/vesta"
        "?host=tcp1.example&host=tcp2.example&gssencmode=disable"
        "&application_name=Vesta%20runtime"
    )
    context = SimpleNamespace(verify_mode=2, check_hostname=True)
    with patch.object(
        postgres_profile.ssl, "create_default_context", return_value=context
    ):
        result, args = postgres_profile.connection_parameters(url, asynchronous=True)
    assert args == {"ssl": context}
    parsed = make_url(result)
    assert parsed.password == "p@ss:w/ord"
    assert parsed.query == {
        "host": ("tcp1.example", "tcp2.example"),
        "application_name": "Vesta runtime",
    }


def test_cli_preflight_enforces_readonly_transaction_before_target(monkeypatch, capsys):
    from unittest.mock import MagicMock

    module = load_install()
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "full")
    monkeypatch.setenv("DATABASE_URL", "postgresql://owner:private-password@db/vesta")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "portable_install",
            "--check-prerequisites",
            "--database",
            "vesta",
            "--runtime-role",
            "runtime",
        ],
    )
    engine = MagicMock()
    db = engine.begin.return_value.__enter__.return_value
    events = []
    db.execute.side_effect = lambda sql: events.append(str(sql))
    with patch.object(module, "create_engine", return_value=engine), patch.object(
        module, "_target", side_effect=lambda *args, **kwargs: events.append(kwargs)
    ):
        module.main()
    assert events == [
        "SET TRANSACTION READ ONLY",
        {"runtime_role": "runtime", "expected_database": "vesta", "lock": False},
    ]
    engine.dispose.assert_called_once()
    assert "private-password" not in capsys.readouterr().out


@pytest.mark.parametrize("default_readonly", ["off", "on"])
def test_customer_default_readonly_policy_is_distinct_from_preflight_transaction(
    monkeypatch, default_readonly
):
    module = load_install()
    monkeypatch.setenv("VESTA_DELIVERY_PROFILE", "customer-postgresql")
    statements = []

    def scalar(sql):
        query = str(sql)
        statements.append(query)
        if "current_setting('default_transaction_read_only')" in query:
            return default_readonly
        if "current_setting('transaction_read_only')" in query:
            return "on"  # Intentional read-only preflight transaction is valid.
        return "pg_extension" in query

    db = SimpleNamespace(
        scalar=scalar,
        connection=SimpleNamespace(
            driver_connection=SimpleNamespace(
                get_dsn_parameters=lambda: {
                    "sslmode": "verify-full",
                    "sslrootcert": "/trust/ca.crt",
                },
                info=SimpleNamespace(ssl_in_use=True),
            )
        ),
    )
    if default_readonly == "on":
        with pytest.raises(
            module.CustomerPostgresPrerequisiteError,
            match="requires default_transaction_read_only=off",
        ):
            module._customer_prerequisites(db, 170005)
    else:
        module._customer_prerequisites(db, 170005)
    assert "SELECT current_setting('default_transaction_read_only')" in statements
    assert "SELECT current_setting('transaction_read_only')" not in statements


@pytest.mark.parametrize("explicit", [None, "full"])
def test_extracted_customer_installer_binds_old_site_profile(
    tmp_path, config, explicit
):
    import subprocess

    root = image_kit(tmp_path)
    release = tmp_path / "release"
    kit.assemble_release(root, release, "a" * 40)
    if explicit is not None:
        config["delivery_profile"] = explicit
    site = tmp_path / "site.json"
    site.write_text(json.dumps(config))
    result = subprocess.run(
        [
            sys.executable,
            str(release / "install/render.py"),
            "--config",
            str(site),
            "--stage",
            "migrate",
        ],
        capture_output=True,
        text=True,
    )
    if explicit == "full":
        assert result.returncode != 0
        assert "contradicts the bundled release" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        env = json.loads(result.stdout)["items"][0]["spec"]["template"]["spec"][
            "containers"
        ][0]["env"]
        assert {item["name"]: item.get("value") for item in env}[
            "VESTA_DELIVERY_PROFILE"
        ] == "customer-postgresql"


@pytest.mark.parametrize("tamper", ["installer", "profile-receipt"])
def test_extracted_installer_refuses_mismatched_profile_inputs(
    tmp_path, config, tamper
):
    import subprocess

    root = image_kit(tmp_path)
    release = tmp_path / "release"
    kit.assemble_release(root, release, "a" * 40)
    if tamper == "installer":
        target = release / "install/render.py"
        target.write_text(target.read_text() + "\n# altered installer\n")
    else:
        manifest = json.loads((release / "manifest.json").read_text())
        manifest["metadata"]["supply_contract"]["profile"] = "full"
        (release / "manifest.json").write_text(json.dumps(manifest))
    site = tmp_path / "site.json"
    site.write_text(json.dumps(config))
    result = subprocess.run(
        [
            sys.executable,
            str(release / "install/render.py"),
            "--config",
            str(site),
            "--stage",
            "migrate",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert (
        "checksum mismatch" in result.stderr
        or "profile receipt mismatch" in result.stderr
    )


def test_customer_seal_explicit_tls_overrides_service_and_environment(
    tmp_path, monkeypatch
):
    import io
    from psycopg2.extensions import parse_dsn

    custody = tmp_path / "custody"
    custody.mkdir()
    (custody / "journal").write_text("fixture")
    ca = tmp_path / "ca's\\trusted.pem"
    ca.write_text("fixture CA")
    monkeypatch.setenv("PGSSLMODE", "disable")
    monkeypatch.setenv("PGHOST", "/var/run/postgresql")
    monkeypatch.setenv("PGGSSENCMODE", "require")
    calls = []

    def encrypt(producer, target, recipients):
        producer(io.BytesIO())
        target.write_bytes(b"encrypted-fixture")

    def dump(arguments, **kwargs):
        calls.append(parse_dsn(arguments[-1].removeprefix("--dbname=")))

    monkeypatch.setattr(kit, "encrypt_pipe", encrypt)
    monkeypatch.setattr(kit.subprocess, "run", dump)
    target = tmp_path / "sealed"
    kit.seal_control_plane(
        target,
        custody,
        tmp_path / "recipients",
        "fixture",
        True,
        profile="customer-postgresql",
        pg_host="database.example",
        pg_ca_file=ca,
    )
    assert calls == [
        {
            "service": "fixture",
            "host": "database.example",
            "sslmode": "verify-full",
            "sslrootcert": str(ca.resolve()),
            "gssencmode": "disable",
        }
    ]
    assert kit.verify(target)["metadata"]["delivery_profile"] == "customer-postgresql"
    assert "database.example" not in (target / "manifest.json").read_text()


@pytest.mark.parametrize(
    "host,ca_exists", [(None, True), ("/tmp", True), ("@socket", True), ("db", False)]
)
def test_customer_seal_refuses_missing_tcp_or_ca_before_output(
    tmp_path, host, ca_exists
):
    ca = tmp_path / "ca.pem"
    if ca_exists:
        ca.write_text("fixture")
    with pytest.raises(ValueError):
        kit.seal_control_plane(
            tmp_path / "out",
            tmp_path / "custody",
            tmp_path / "recipients",
            "fixture",
            True,
            config={"delivery_profile": "customer-postgresql"},
            pg_host=host,
            pg_ca_file=ca,
        )
    assert not (tmp_path / "out").exists()


def test_extracted_old_site_kustomize_inherits_customer_api_guard(tmp_path, config):
    import shutil
    import subprocess
    import yaml

    oc = shutil.which("oc")
    assert oc, "oc is required for offline Kustomize parity"
    images = image_kit(tmp_path)
    release = tmp_path / "release"
    kit.assemble_release(images, release, "a" * 40)
    site = tmp_path / "old-site.json"
    site.write_text(json.dumps(config))
    target = tmp_path / "api"
    subprocess.run(
        [
            sys.executable,
            str(release / "install/render.py"),
            "--config",
            str(site),
            "--stage",
            "api",
            "--output-dir",
            str(target),
        ],
        check=True,
        capture_output=True,
    )
    items = list(
        yaml.safe_load_all(
            subprocess.check_output([oc, "kustomize", str(target)], text=True)
        )
    )
    backend = next(
        item
        for item in items
        if item["kind"] == "Deployment" and "backend" in item["metadata"]["name"]
    )
    env = backend["spec"]["template"]["spec"]["containers"][0]["env"]
    assert {item["name"]: item.get("value") for item in env}[
        "VESTA_DELIVERY_PROFILE"
    ] == "customer-postgresql"
