"""Oversized legacy page requests clamp; malformed bounds remain HTTP 422."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from database import get_db
from deps import get_current_user
from models import OrganizationDefault
from routers import activity, backups, restores


@pytest.fixture
def client(db_session):
    app = FastAPI()
    for module in (activity, backups, restores):
        app.include_router(module.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        org_id=db_session.get(OrganizationDefault, "oss").org_id, role="admin"
    )
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/activity",
        "/api/v1/activity/unified",
        "/api/v1/backups",
        "/api/v1/restores",
    ],
)
def test_oversized_page_limit_clamps_without_changing_success_contract(client, path):
    response = client.get(path, params={"limit": 1000})
    assert response.status_code == 200, response.text
    assert response.json()["limit"] == 100


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/activity",
        "/api/v1/activity/unified",
        "/api/v1/backups",
        "/api/v1/restores",
    ],
)
@pytest.mark.parametrize(
    "parameter,value",
    [("skip", "-1"), ("limit", "0"), ("limit", "-1"), ("limit", "invalid")],
)
def test_invalid_page_bounds_return_validation_error(client, path, parameter, value):
    response = client.get(path, params={parameter: value})
    assert response.status_code == 422
    assert any(
        error["loc"][:2] == ["query", parameter] for error in response.json()["detail"]
    )
