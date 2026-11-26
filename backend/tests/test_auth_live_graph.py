"""Real route registration/lifespan, with external startup work isolated.

Database authorization is tested separately under the restricted PostgreSQL role.
These tests never connect to a database or start backup workers.
"""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


graph = load("live_graph", ROOT / "ci/auth_live_graph.py")
source = load("source_inventory", ROOT / "ci/auth_surface_inventory.py")
FEATURES = ("multi_tenancy", "billing_api", "white_labeling")
MODULE_FEATURE = dict(zip(("multi_tenant", "billing", "white_label"), FEATURES))


@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.asyncio
async def test_post_lifespan_graph_matches_source(monkeypatch, demo):
    await check_post_lifespan_graph(monkeypatch, demo, (False, False, False))


async def check_post_lifespan_graph(monkeypatch, demo, bits):
    from config import settings
    from core import licensing, licensing_advanced, settings_reader
    from core.backup_queue_processor import BackupQueueProcessor
    from core.licensing import FeatureFlags
    from core.installed_profile import InstalledProfile

    enabled = {f for f, bit in zip(FEATURES, bits) if bit}
    license_stub = MagicMock(tier="msp" if enabled else "oss")
    license_stub.has_feature.side_effect = lambda f: f in enabled
    profile = (
        InstalledProfile()
        if demo or not enabled
        else InstalledProfile(
            "commercial",
            (
                "multi_organization"
                if "multi_tenancy" in enabled
                else "single_organization"
            ),
            frozenset(enabled),
        )
    )
    flags = FeatureFlags(license_stub, profile)
    monkeypatch.setattr(licensing, "features", flags)
    monkeypatch.setattr(licensing, "license_manager", license_stub)
    monkeypatch.setattr(
        licensing_advanced.LicenseValidator,
        "validate",
        lambda self: {"tier": license_stub.tier, "features": sorted(enabled)},
    )
    monkeypatch.setattr(settings, "demo_mode", demo)
    monkeypatch.setattr(settings, "demo_max_sessions", 2)
    module = load("d11_profile_app", ROOT / "backend/app.py")
    from core.product_identity import product_name

    assert module.app.title == f"{product_name()} API"
    monkeypatch.setattr(module, "init_database", MagicMock())
    monkeypatch.setattr(module, "SessionLocal", MagicMock())
    monkeypatch.setattr(module.metrics, "collect_gauge_metrics", MagicMock())
    monkeypatch.setattr(module, "scheduler", MagicMock(running=False))
    monkeypatch.setattr(module, "load_schedules", AsyncMock())
    monkeypatch.setattr(module, "_recover_orphaned_uploads", AsyncMock())
    monkeypatch.setattr(settings_reader, "get_setting_with_db", lambda *args: 3)
    monkeypatch.setattr(BackupQueueProcessor, "start", AsyncMock())
    monkeypatch.setattr(BackupQueueProcessor, "stop", AsyncMock())
    from core.backup_executor import backup_executor
    from core.restore_executor import restore_executor
    from core.notifications import notification_service
    from core.realtime import realtime
    from core.websocket import websocket_manager
    from core.task_lifetime import SchedulerWork

    monkeypatch.setattr(module, "scheduler_work", SchedulerWork())
    # These graph-only fixtures replace cleanup, so also isolate admission state.
    from core.verification_executor import verification_executor
    from core.operator_dispatch import operator_dispatcher

    for owner in (
        operator_dispatcher,
        backup_executor,
        restore_executor,
        verification_executor,
        notification_service,
        realtime,
        websocket_manager,
    ):
        monkeypatch.setattr(owner, "start", MagicMock())
        monkeypatch.setattr(owner, "close_admission", MagicMock())
        monkeypatch.setattr(owner, "cleanup", AsyncMock())
    # Run the real lifespan, including its conditional commercial initialization.
    async with module.app.router.lifespan_context(module.app):
        rows = graph.live_graph(module.app)
        graph.require_unique(rows)
        assert not graph.literal_shadows(rows)
        actual = set(graph.operations([r for r in rows if not r["framework"]]))
        expected = set()
        for row in source.inventory():
            if row["kind"] != "route":
                continue
            if row["source"] in source.UNMOUNTED_SOURCES:
                continue
            if row["source"] == "backend/routers/realtime.py" and demo:
                continue
            if row["source"].startswith("commercial/"):
                feature = MODULE_FEATURE[Path(row["source"]).stem]
                if demo or feature not in enabled:
                    continue
            expected.add((row["method"], row["path"]))
        assert actual == expected
        # Includes the accepted restore bundle, backup/restore resume, three
        # scheduler-grant methods and native admission/publication/refusal callbacks.
        # Operator recovery and unreserved closeout add eight mounted routes.
        # They exist in every profile; their
        # presence is topology evidence, not demo/tenant admission qualification.
        assert len(actual) == (
            195
            if demo
            else 199
            + sum(
                count
                for feature, count in zip(FEATURES, (5, 4, 4))
                if feature in enabled
            )
        )
        operator_routes = {
            ("GET", "/api/v1/operator/capabilities"),
            ("GET", "/api/v1/operator/requests/{request_id}"),
            ("GET", "/api/v1/backups/queue/{queue_id}"),
            ("POST", "/api/v1/backups/{backup_id}/close-unreserved"),
            ("GET", "/api/v1/agents/{agent_id}/key-rotations"),
            ("GET", "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}"),
            ("DELETE", "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}"),
            ("POST", "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate"),
        }
        assert operator_routes <= actual
        # Every profile must mount the new read with the same user session
        # and tenant database dependencies as the existing VM detail.
        vm_path = "/api/v1/vms/{vm_id}"
        guidance_path = vm_path + "/backup-guidance"
        assert {("GET", vm_path), ("GET", guidance_path)} <= actual
        detail = next(
            row for row in rows if row["path"] == vm_path and "GET" in row["methods"]
        )
        guidance = next(
            row
            for row in rows
            if row["path"] == guidance_path and "GET" in row["methods"]
        )
        assert guidance["dependencies"] == detail["dependencies"]
        assert "deps:get_current_user" in guidance["dependencies"]
        operator_paths = {path for _, path in operator_routes}
        assert all(r["dependencies"] for r in rows if r["path"] in operator_paths)
        # D04 controls and negative native callback are mounted in every profile; topology does not
        # imply demo admission or replace restricted-PG authority evidence.
        finalize_paths = {
            "/api/v1/agents/backups/{backup_id}/finalize-intent",
            "/api/v1/agents/backups/{backup_id}/checkpoint-proof",
            "/api/v1/agents/backups/{backup_id}/native-no-effect",
            "/api/v1/agents/backups/{backup_id}/native-closed-failure",
            "/api/v1/agents/backups/{backup_id}/native-fenced-failure",
        }
        assert {(verb, path) for verb, path in actual if path in finalize_paths} == {
            ("POST", path) for path in finalize_paths
        }
        assert all(r["dependencies"] for r in rows if r["path"] in finalize_paths)
        generated = set(graph.operations([r for r in rows if r["framework"]]))
        assert generated == {
            (verb, path)
            for verb in ("GET", "HEAD")
            for path in ("/openapi.json", "/docs-assets/{path:path}")
        }
        docs_paths = {"/docs", "/redoc", "/docs/oauth2-redirect"}
        explicit_docs = {
            operation for operation in actual if operation[1] in docs_paths
        }
        assert explicit_docs == {
            (verb, path) for path in docs_paths for verb in ("GET", "HEAD")
        }
        # Ordinary application GET operations still do not acquire HEAD/OPTIONS.
        assert not any(
            verb in {"HEAD", "OPTIONS"}
            for verb, path in actual
            if path not in docs_paths
        )
        openapi = module.app.openapi()
        assert {
            (verb.upper(), path)
            for path, item in openapi["paths"].items()
            for verb in item
        } == {
            (verb, path)
            for verb, path in actual
            if verb != "WEBSOCKET" and path not in docs_paths
        }
        assert all(r["dependencies"] for r in rows if r["path"] == "/api/v1/users")


@pytest.mark.parametrize("profile", ["oss", "demo"])
def test_shipped_http_perimeter(monkeypatch, profile):
    check_shipped_http_perimeter(monkeypatch, profile)


def check_shipped_http_perimeter(monkeypatch, profile):
    """Actual app/middleware; license and DB IO are doubles, never RLS evidence."""
    from config import settings
    from core import licensing, licensing_advanced
    from core.licensing import FeatureFlags
    from core.installed_profile import InstalledProfile
    from database import get_db
    from deps import create_access_token

    demo = profile == "demo"
    enabled = profile == "commercial"
    license_stub = MagicMock(tier="msp" if enabled else "oss")
    license_stub.has_feature.return_value = enabled
    monkeypatch.setattr(
        licensing,
        "features",
        FeatureFlags(
            license_stub,
            (
                InstalledProfile(
                    "commercial", "multi_organization", frozenset(FEATURES)
                )
                if enabled
                else InstalledProfile()
            ),
        ),
    )
    monkeypatch.setattr(licensing, "license_manager", license_stub)
    monkeypatch.setattr(
        licensing_advanced.LicenseValidator,
        "validate",
        lambda self: {
            "tier": license_stub.tier,
            "features": list(FEATURES) if enabled else [],
        },
    )
    monkeypatch.setattr(settings, "demo_mode", demo)
    monkeypatch.setattr("core.tenant_context.commercial_mode", lambda: enabled)
    module = load("d11_perimeter_app", ROOT / "backend/app.py")
    from routers import public

    monkeypatch.setattr(public, "_local_oidc_login_available", lambda _db: False)
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    db.query.return_value.filter.return_value.all.return_value = []
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.filter.return_value.filter.return_value = (
        db.query.return_value.filter.return_value
    )
    module.app.dependency_overrides[get_db] = lambda: db
    # No lifespan here: the separate all-entitlement live-graph test executes it.
    # This control exercises the actual core app and middleware, with no workers.
    client = TestClient(module.app, follow_redirects=False)
    signed = {
        "Authorization": "Bearer "
        + create_access_token(
            {
                "sub": "perimeter-control",
                "user_id": "a875dcf7-5e64-423d-b31a-3373c0a7c9b4",
                "org_id": "89054667-ea2e-4c31-8408-97b76bab3f75",
            }
        )
    }
    try:
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            blocked = demo and path != "/docs/oauth2-redirect"
            for method in ("GET", "HEAD"):
                response = client.request(method, path)
                assert response.status_code == (403 if blocked else 200), (
                    path,
                    response.text,
                )
                if method == "HEAD":
                    assert response.content == b""
            assert client.post(path).status_code == (403 if blocked else 405)
            assert client.get(path, headers=signed).status_code == (
                403 if blocked else 200
            )
        public_paths = (
            "/health",
            "/ready",
            "/metrics",
            "/api/v1/version",
            "/api/v1/bootstrap",
            "/api/v1/features",
            "/api/v1/license/info",
        )
        for path in public_paths:
            blocked = demo and path in (
                "/api/v1/bootstrap",
                "/api/v1/features",
                "/api/v1/license/info",
            )
            for headers in ({}, {"Authorization": "Bearer malformed"}):
                response = client.get(path, headers=headers)
                expected = 401 if headers else 403 if blocked else 200
                assert response.status_code == expected, (path, response.text)
            for method in ("HEAD", "POST", "OPTIONS"):
                expected = 403 if blocked and method != "OPTIONS" else 405
                assert client.request(method, path).status_code == expected
            assert client.get(path, headers=signed).status_code == (
                403 if blocked else 200
            )
        # Every shipped Users operation refuses anonymous admission. Demo also
        # refuses a signed bearer without calling the doubled db.query path.
        # This counter does not observe every possible identity/DB boundary.
        for method, path in (
            ("GET", "/api/v1/users"),
            ("POST", "/api/v1/users"),
            ("GET", "/api/v1/users/target"),
            ("PUT", "/api/v1/users/target"),
            ("DELETE", "/api/v1/users/target"),
        ):
            for headers in ({}, signed):
                before = db.query.call_count
                response = client.request(
                    method,
                    path,
                    headers=headers,
                    json={"username": "new", "password": "Private1!Password"},
                )
                assert response.status_code == (403 if demo else 401)
                if demo:
                    assert db.query.call_count == before
        # Compatibility is tenant inventory, not anonymous process metadata.
        for headers in ({}, signed, {"Authorization": "Bearer malformed"}):
            assert client.get("/api/v1/compatibility", headers=headers).status_code == (
                401
                if headers.get("Authorization") == "Bearer malformed"
                else 403 if demo else 401
            )
        for method in ("HEAD", "POST", "OPTIONS"):
            assert client.request(method, "/api/v1/compatibility").status_code == (
                403 if demo and method != "OPTIONS" else 405
            )
        redirect = client.get("/api/v1/compatibility/")
        assert redirect.status_code == (403 if demo else 307)
        if not demo:
            assert client.get(redirect.headers["location"]).status_code == 401
            # Persisted lookup is doubled here; real writes/RLS are a separate
            # restricted-PostgreSQL test, never inferred from these responses.
            from models import Agent

            actor = SimpleNamespace(
                id="a875dcf7-5e64-423d-b31a-3373c0a7c9b4",
                org_id="89054667-ea2e-4c31-8408-97b76bab3f75",
                is_active=True,
            )
            db.query.return_value.filter.return_value.first.return_value = actor
            db.get.return_value = SimpleNamespace(enabled=True)
            db.query.return_value.filter.return_value.all.return_value = [
                SimpleNamespace(hostname="own-agent", version="5.0.1")
            ]
            own = client.get("/api/v1/compatibility", headers=signed)
            assert own.status_code == 200
            assert [(a["hostname"], a["version"]) for a in own.json()["agents"]] == [
                ("own-agent", "5.0.1")
            ]
            query = db.query.return_value

            def query_failure(model):
                if model is Agent:
                    raise RuntimeError("private-database-credential")
                return query

            db.query.side_effect = query_failure
            failed_inventory = client.get("/api/v1/compatibility", headers=signed)
            assert failed_inventory.status_code == 503
            assert failed_inventory.json() == {
                "detail": "Compatibility inventory unavailable"
            }
            db.query.side_effect = None
            db.query.return_value.filter.return_value.first.return_value = None
        # Dependency failure is a stable, redacted public readiness verdict.
        db.execute.side_effect = RuntimeError("postgres://secret@internal-host/private")
        failed = client.get("/ready")
        assert failed.status_code == 503
        assert failed.json() == {
            "status": "not_ready",
            "checks": {
                "database": {
                    "status": "error",
                    "required": True,
                    "code": "DATABASE_UNAVAILABLE",
                }
            },
        }
        assert "secret" not in failed.text and "internal-host" not in failed.text
        db.execute.side_effect = None
        for method, path in (
            ("GET", "/api/v1/users"),
            ("GET", "/api/v1/settings/v3"),
            ("POST", "/api/v1/auth/oidc/test"),
            ("POST", "/api/v1/backups/target/close-unreserved"),
        ):
            assert client.request(method, path).status_code == (403 if demo else 401)
            slash = client.request(method, path + "/")
            assert slash.status_code == (403 if demo else 307)
            if not demo:
                assert (
                    client.request(method, slash.headers["location"]).status_code == 401
                )
            assert client.head(path).status_code == (403 if demo else 405)
        assert client.put("/api/v1/settings/v3", content="{malformed").status_code == (
            403 if demo else 401
        )
        before = db.query.call_count
        closeout = client.post(
            "/api/v1/backups/target/close-unreserved", headers=signed, json={}
        )
        assert closeout.status_code == (403 if demo else 401)
        if demo:
            assert db.query.call_count == before
        origin = settings.allowed_origins_list[0]
        preflight = {
            "Origin": origin,
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        }
        result = client.options("/api/v1/settings/v3", headers=preflight)
        assert result.status_code == 200
        assert result.headers["access-control-allow-origin"] == origin
        assert result.headers["access-control-allow-credentials"] == "true"
        assert "Origin" in result.headers["vary"]
        for change in (
            {"Origin": "https://untrusted.invalid"},
            {"Access-Control-Request-Method": "TRACE"},
            {"Access-Control-Request-Headers": "X-Platform-Admin"},
        ):
            denied = client.options("/api/v1/settings/v3", headers=preflight | change)
            assert denied.status_code == 400
            if "Origin" in change:
                assert "access-control-allow-origin" not in denied.headers
        response = client.get("/health")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-request-id"]
        # Short-circuit responses bypass inner response decorators. This control
        # records the boundary rather than claiming universal header coverage.
        assert "x-content-type-options" not in result.headers
        # Exposure discriminator, not an accepted telemetry authorization policy.
        # This in-process sample is synthetic and removed after the request.
        gauge = module.metrics.backup_last_success_age_seconds
        labels = ("perimeter-private-vm", "perimeter-private-id")
        gauge.labels(*labels).set(123)
        try:
            telemetry = client.get("/metrics")
            assert telemetry.status_code == 200
            assert all(label in telemetry.text for label in labels)
        finally:
            gauge.remove(*labels)
    finally:
        client.close()


def test_duplicate_and_shadow_controls():
    app = FastAPI()

    @app.get("/things/{identity}")
    def dynamic(identity: str):
        return identity

    @app.get("/things/special")
    def literal():
        return "special"

    assert graph.literal_shadows(graph.live_graph(app)) == [
        ("/things/{identity}", "/things/special", ["GET"])
    ]
    app.add_api_route("/things/special", literal, methods=["GET"])
    with pytest.raises(AssertionError, match="Duplicate"):
        graph.require_unique(graph.live_graph(app))


def test_unknown_mount_fails_closed():
    app = FastAPI()
    app.mount("/child", FastAPI())
    with pytest.raises(AssertionError, match="Unclassified dispatch node"):
        graph.live_graph(app)


def test_framework_head_and_options_are_distinct():
    app = FastAPI()

    @app.get("/item")
    def item():
        return {}

    with TestClient(app) as client:
        assert client.head("/docs").status_code == 200
        assert client.head("/item").status_code == 405
        assert client.options("/item").status_code == 405


def test_real_queue_request_reaches_queue_handler(monkeypatch):
    from app import app
    from database import get_db
    from deps import get_current_user
    from routers import queue

    db = MagicMock()
    db.query.return_value.filter.return_value.count.return_value = 0
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
        []
    )

    def reached_queue(_db):
        assert _db is db
        raise HTTPException(418, "queue-handler-control")

    monkeypatch.setattr(queue, "get_max_concurrent_backups", reached_queue)
    old = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: MagicMock()
    try:
        # Lifespan is covered above; this request isolates dispatch order.
        client = TestClient(app)
        response = client.get("/api/v1/backups/queue")
        assert response.status_code == 418
        assert response.json() == {"detail": "queue-handler-control"}
        client.close()
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(old)


def test_static_docs_mount_is_explicit_in_live_graph(tmp_path):
    from fastapi import FastAPI
    from starlette.staticfiles import StaticFiles

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.mount("/docs-assets", StaticFiles(directory=tmp_path))
    rows = graph.live_graph(app)
    assert len(rows) == 1 and rows[0]["mount"] is True
    assert rows[0]["path"] == "/docs-assets/{path:path}"
    assert rows[0]["methods"] == ["GET", "HEAD"]
    assert rows[0]["dependencies"] == []
    graph.require_unique(rows)


def test_unknown_mounted_app_does_not_disappear_from_live_graph():
    from fastapi import FastAPI

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.mount("/unreviewed", FastAPI())
    with pytest.raises(AssertionError, match="Unclassified dispatch node"):
        graph.live_graph(app)
