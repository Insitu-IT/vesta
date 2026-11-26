"""Commit ownership controls; doubles are not PostgreSQL rollback evidence."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from cryptography.fernet import Fernet

import deps
from core import settings_service
from models import ActivityLog, SecretV3, SettingV3
from routers import config


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", [None, "construct", "add", "flush", "commit", "encrypt"]
)
async def test_settings_and_audit_have_one_commit(monkeypatch, failure, caplog):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    monkeypatch.setattr(
        settings_service.SettingsService,
        "get",
        lambda self, key: self.DEFINITIONS[key]["default"],
    )
    actor = SimpleNamespace(id="actor-id", username="platform-user")
    pending = []
    fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr(settings_service, "_fernet", fernet)

    def add(row):
        if failure == "add" and isinstance(row, ActivityLog):
            raise RuntimeError("audit add refused")
        pending.append(row)

    def flush():
        if failure == "flush" and any(isinstance(row, ActivityLog) for row in pending):
            raise RuntimeError("audit flush refused")

    db.add.side_effect = add
    db.flush.side_effect = flush
    if failure == "construct":
        monkeypatch.setattr(
            deps,
            "ActivityLog",
            MagicMock(side_effect=RuntimeError("audit construction refused")),
        )
    if failure == "commit":
        db.commit.side_effect = RuntimeError(
            "commit refused secret-control retained-private"
        )
    if failure == "encrypt":
        monkeypatch.setattr(
            fernet,
            "encrypt",
            MagicMock(
                side_effect=RuntimeError(
                    "encryption refused secret-control retained-private"
                )
            ),
        )

    request = {
        "storage.s3.bucket": "test-bucket",
        "storage.s3.secret_key": "secret-control",
    }
    if failure:
        with pytest.raises(HTTPException) as error:
            await config.update_settings_v3(request, actor, db)
        assert error.value.status_code == 500
        assert "secret-control" not in str(error.value) + caplog.text
        import traceback

        assert "secret-control" not in "".join(traceback.format_exception(error.value))
        assert "retained-private" not in str(error.value) + caplog.text + "".join(
            traceback.format_exception(error.value)
        )
        db.rollback.assert_called_once_with()
        assert db.commit.call_count == (1 if failure == "commit" else 0)
    else:
        response = await config.update_settings_v3(request, actor, db)
        assert response["status"] == "ok"
        db.commit.assert_called_once_with()
        db.rollback.assert_not_called()
        assert db.flush.call_count == 3
        setting, secret, audit = pending
        assert isinstance(setting, SettingV3) and setting.value == "test-bucket"
        assert isinstance(secret, SecretV3)
        assert (
            fernet.decrypt(secret.encrypted_value.encode()).decode() == "secret-control"
        )
        assert audit.user_id == actor.id and audit.action == "v3_settings_updated"
        assert audit.details == {
            "settings": ["storage.s3.bucket"],
            "secrets": ["storage.s3.secret_key"],
        }
        assert "secret-control" not in repr(audit.details) + repr(response)


def test_standalone_helpers_retain_commit_ownership(monkeypatch):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    monkeypatch.setattr(settings_service, "_fernet", Fernet(Fernet.generate_key()))
    service = settings_service.SettingsService(db)
    service.set("storage.type", "s3")
    service.set_secret("storage.s3.secret_key", "secret-control")
    deps.log_activity(db, SimpleNamespace(id="actor"), "test")
    assert db.commit.call_count == 3
    db.flush.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        {"unknown": "x"},
        {"oidc.enabled": "true"},
        {"oidc.issuer": []},
        {"oidc.client_secret": {}},
        {"oidc.default_role": "platform_admin"},
        {"oidc.default_role": "admin"},
        {"oidc.scopes": ""},
        {"oidc.scopes": "profile"},
        {"oidc.enabled": True, "oidc.issuer": "http://idp.example"},
        {"oidc.enabled": True, "oidc.client_id": " "},
    ],
)
async def test_invalid_patch_precedes_all_writes(monkeypatch, patch):
    from fastapi import HTTPException

    db = MagicMock()
    monkeypatch.setattr(
        settings_service.SettingsService,
        "get",
        lambda self, key: {
            "oidc.enabled": False,
            "oidc.issuer": "https://idp.example",
            "oidc.client_id": "client",
        }.get(key),
    )
    monkeypatch.setattr(
        settings_service.SettingsService, "get_secret", lambda *args: "retained"
    )
    with pytest.raises(HTTPException) as error:
        await config.update_settings_v3(
            {"storage.s3.bucket": "changed", **patch},
            SimpleNamespace(username="admin"),
            db,
        )
    assert error.value.status_code == 400
    db.add.assert_not_called()
    db.flush.assert_not_called()
    db.commit.assert_not_called()
    db.rollback.assert_called_once()


def test_effective_oidc_and_masked_secret_retention(monkeypatch):
    service = settings_service.SettingsService(MagicMock())
    monkeypatch.setattr(
        service,
        "get",
        lambda key: {
            "oidc.enabled": True,
            "oidc.issuer": "https://idp.example",
            "oidc.client_id": "retained-client",
            "oidc.scopes": "openid profile",
            "oidc.default_role": "viewer",
        }.get(key),
    )
    monkeypatch.setattr(service, "get_secret", lambda key: "retained-secret")
    for secret in ("", "   ", "********", "••••••"):
        assert service.validate_update(
            {"oidc.client_secret": secret, "oidc.scopes": " openid  profile openid "}
        ) == {"oidc.scopes": "openid profile"}
    monkeypatch.setattr(service, "get_secret", lambda key: None)
    with pytest.raises(ValueError):
        service.validate_update({"oidc.enabled": True})
    assert (
        service.validate_update(
            {"oidc.enabled": True, "oidc.client_secret": "new-secret"}
        )["oidc.enabled"]
        is True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["scopes", "role", "secret"])
@pytest.mark.parametrize(
    "patch", [{"oidc.enabled": True}, {"storage.s3.bucket": "changed"}]
)
async def test_enabled_retained_configuration_is_validated(monkeypatch, bad, patch):
    from fastapi import HTTPException

    settings = {
        "oidc.enabled": True,
        "oidc.issuer": "https://idp.example",
        "oidc.client_id": "client",
        "oidc.scopes": "openid profile",
        "oidc.default_role": "viewer",
    }
    if bad == "scopes":
        settings["oidc.scopes"] = "profile"
    if bad == "role":
        settings["oidc.default_role"] = "unsupported"
    monkeypatch.setattr(
        settings_service.SettingsService, "get", lambda self, key: settings.get(key)
    )
    monkeypatch.setattr(
        settings_service.SettingsService,
        "get_secret",
        lambda *args: "   " if bad == "secret" else "retained",
    )
    db = MagicMock()
    with pytest.raises(HTTPException) as error:
        await config.update_settings_v3(patch, SimpleNamespace(username="admin"), db)
    assert error.value.status_code == 400
    db.add.assert_not_called()
    db.flush.assert_not_called()
    db.commit.assert_not_called()
