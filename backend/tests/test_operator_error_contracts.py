"""Exercise handler errors and validate documentation without a real provider."""

import asyncio
from types import SimpleNamespace

from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from jsonschema import Draft202012Validator

from operator_error_contracts import apply_error_contracts
from operator_protocol_contracts import apply_protocol_contracts


def validate(document, path, method, status, value, media="application/json"):
    schema = document["paths"][path][method]["responses"][str(status)]["content"][
        media
    ]["schema"]
    Draft202012Validator(
        {**schema, "components": document.get("components", {})}
    ).validate(value)


def test_callback_decoding_and_stream_size_errors():
    from routers.health import router
    from core.callback_identity import authenticate_callback

    app = FastAPI()
    app.include_router(router)

    async def identity():
        return None

    app.dependency_overrides[authenticate_callback] = identity
    document = apply_error_contracts(
        apply_protocol_contracts(app.openapi()), app.routes
    )
    path = "/api/v1/agents/backups/{backup_id}/native-admission"

    async def exercise():
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            for body, status in ((b"not JSON", 422), (b"x" * 65537, 413)):
                result = await client.post(
                    path.replace("{backup_id}", "backup"), content=body
                )
                assert result.status_code == status
                assert isinstance(result.json()["detail"], str)
                validate(document, path, "post", status, result.json())

    asyncio.run(exercise())


def test_s3_config_absence_and_request_validation_are_distinct(monkeypatch):
    from routers.s3_import import router
    from deps import get_current_user
    from database import get_db

    app = FastAPI()
    app.include_router(router)

    async def user():
        return SimpleNamespace(role="admin")

    async def db():
        return None

    app.dependency_overrides[get_current_user] = user
    app.dependency_overrides[get_db] = db
    monkeypatch.setattr("routers.s3_import.SettingsService", None, raising=False)
    # The client helper imports SettingsService locally, so patch the provider.
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config", lambda _: None
    )
    document = apply_error_contracts(app.openapi(), app.routes)

    async def exercise():
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            missing = await client.get("/api/v1/s3/discover")
            assert missing.status_code == 404
            validate(document, "/api/v1/s3/discover", "get", 404, missing.json())
            invalid = await client.post("/api/v1/s3/import", json={})
            assert invalid.status_code == 422
            assert isinstance(invalid.json()["detail"], list)
            validate(document, "/api/v1/s3/import", "post", 422, invalid.json())

    asyncio.run(exercise())


def test_original_admission_error_variant_is_retained():
    existing = {"$ref": "#/components/schemas/Admission"}
    document = {
        "paths": {
            "/api/v1/backups": {
                "post": {
                    "responses": {
                        "409": {
                            "description": "admission",
                            "content": {"application/json": {"schema": existing}},
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Admission": {
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "object",
                            "properties": {
                                "code": {"const": "request_identity_conflict"}
                            },
                            "required": ["code"],
                        }
                    },
                    "required": ["detail"],
                }
            }
        },
    }
    apply_error_contracts(document)
    merged = document["paths"]["/api/v1/backups"]["post"]["responses"]["409"][
        "content"
    ]["application/json"]["schema"]
    assert existing in merged["anyOf"]
    validate(
        document,
        "/api/v1/backups",
        "post",
        409,
        {"detail": {"code": "request_identity_conflict"}},
    )
    validate(
        document, "/api/v1/backups", "post", 409, {"detail": "Backup already running"}
    )
    validate(
        document, "/api/v1/backups", "post", 500, "Internal Server Error", "text/plain"
    )


def test_minimal_documents_are_not_expanded():
    document = {"paths": {}}
    apply_error_contracts(document)
    assert document["paths"] == {}
