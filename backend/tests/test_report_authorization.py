"""HTTP report role boundaries; DB doubles do not establish tenant/RLS safety."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from database import get_db
from deps import get_current_user
from routers.reports import router


@pytest.fixture
def report_http():
    app = FastAPI()
    app.include_router(router)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield app, client, db


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/reports"),
        ("GET", "/api/v1/reports/probe"),
        ("POST", "/api/v1/reports"),
        ("PUT", "/api/v1/reports/probe"),
        ("DELETE", "/api/v1/reports/probe"),
        ("POST", "/api/v1/reports/probe/generate"),
        ("GET", "/api/v1/reports/probe/executions"),
        ("GET", "/api/v1/report-executions/probe"),
        ("GET", "/api/v1/report-executions/probe/download"),
    ],
)
def test_anonymous_report_requests_never_reach_data(report_http, method, path):
    _, client, db = report_http
    response = client.request(method, path, json={})
    assert response.status_code == 401
    db.query.assert_not_called()
    db.commit.assert_not_called()


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/reports"),
        ("PUT", "/api/v1/reports/probe"),
        ("DELETE", "/api/v1/reports/probe"),
        ("POST", "/api/v1/reports/probe/generate"),
    ],
)
def test_viewer_cannot_mutate_or_generate_reports(report_http, method, path):
    app, client, db = report_http
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role="viewer")
    response = client.request(method, path, json={})
    assert response.status_code == 403
    db.query.assert_not_called()
    db.commit.assert_not_called()


@pytest.mark.parametrize("role", ["operator", "admin"])
@pytest.mark.parametrize(
    "method,path",
    [
        ("PUT", "/api/v1/reports/probe"),
        ("DELETE", "/api/v1/reports/probe"),
        ("POST", "/api/v1/reports/probe/generate"),
    ],
)
def test_authorized_mutations_reach_report_lookup(report_http, role, method, path):
    app, client, db = report_http
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role=role)
    response = client.request(method, path, json={})
    assert response.status_code == 404
    assert response.json()["detail"] == "Report not found"
    db.query.assert_called_once()
    db.commit.assert_not_called()


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
@pytest.mark.parametrize(
    "extension,media_type,content",
    [
        ("pdf", "application/pdf", b"%PDF-fixture"),
        ("csv", "text/csv", "name\nשלום\n".encode()),
        ("html", "text/html", "<p>שלום</p>".encode()),
        ("json", "application/json", b'{"rows":[]}'),
    ],
)
def test_authenticated_download_preserves_persisted_bytes(
    report_http, role, extension, media_type, content
):
    app, client, db = report_http
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role=role)
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(
        status="completed",
        file_content=content,
        file_name="report." + extension,
        content_type=media_type,
    )
    response = client.get("/api/v1/report-executions/probe/download")
    assert response.status_code == 200
    assert response.content == content
    assert response.headers["content-type"].startswith(media_type)
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="report.{extension}"'
    )
    db.commit.assert_not_called()
