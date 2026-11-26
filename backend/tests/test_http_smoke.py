"""HTTP-layer smoke tests via TestClient.

Validates the full fastapi/starlette request→response cycle end-to-end — routing,
request parsing, response serialization, and error semantics — which the
service-layer unit suite (no TestClient) does not exercise. This closes the
no-live-HTTP-cycle portion of the #34 dep-bump blast-radius gap (fastapi 0.139 /
starlette 1.3.1 / pydantic 2.13.4). The live-app + Postgres integration smoke
remains the CI-recovery merge gate.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(db_engine, session_factory):
    # Import the real app and override the DB dependency with the in-memory
    # SQLite session so endpoints that touch the DB (e.g. /ready) work offline.
    from app import app
    import database

    def _override_get_db():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    # No `with` context manager: the app's on_event("startup") handler connects
    # to the real Postgres (absent in-pod). We only need the HTTP request→response
    # cycle here, not the startup sequence — requests still route through the full
    # middleware + router stack with the overridden DB dependency.
    app.dependency_overrides[database.get_db] = _override_get_db
    c = TestClient(app)
    try:
        yield c
    finally:
        app.dependency_overrides.clear()


def test_health_http(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ready_http_db_ok(client):
    # /ready runs SELECT 1 through the overridden SQLite session — exercises the
    # DB-dependency path plus JSON serialization.
    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"]["status"] == "ok"


def test_version_http(client):
    r = client.get("/api/v1/version")
    assert r.status_code == 200
    assert "version" in r.json()


def test_features_http(client):
    r = client.get("/api/v1/features")
    assert r.status_code == 200
    assert "features" in r.json()


def test_unknown_route_404(client):
    # fastapi/starlette 404 error semantics (JSON body).
    r = client.get("/definitely-not-a-route-xyz")
    assert r.status_code == 404
    assert "detail" in r.json()


@pytest.mark.parametrize("body", ["", "username=only", "password=only", "malformed"])
def test_login_validation_error(client, body):
    # Request validation + urlencoded form parsing (starlette 1.x) + error
    # semantics: OAuth2PasswordRequestForm requires username+password.
    r = client.post(
        "/api/v1/auth/login",
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid credentials"}
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_protected_route_without_token(client):
    # Auth dependency + 401/403 error semantics without a bearer token.
    r = client.get("/api/v1/agents")
    assert r.status_code in (401, 403)
