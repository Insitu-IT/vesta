"""Tests for entry, validation and response handling of recovery exports."""

from types import SimpleNamespace
import unicodedata

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from core.kms.export_passphrase import (
    ExportPassphraseError,
    MIN_EXPORT_PASSPHRASE_LENGTH,
    require_export_passphrase,
)
from routers import encryption

PASSPHRASE = "r5Mq12Jd8B-XwTn6cYaP2_zL97vF"


@pytest.mark.parametrize(
    "value",
    [
        "short-sample",
        "violet fox" + " " * 30,
        "violet fox" + "\u200b\u200d\u3164\u2800" * 8,
        "violet fox" + "\u034f\u0301\u200d" * 10,
        "violet fox" + "\t\u001f\u00a0" * 10,
        "x" * 48,
        "ab 12" * 8 + "a",
        "Lo!\u200d" * 10,
    ],
)
def test_predictable_new_passphrases_are_refused(value):
    with pytest.raises(ExportPassphraseError):
        require_export_passphrase(value)


def test_random_like_or_custom_passphrases_can_be_used():
    require_export_passphrase(PASSPHRASE)
    require_export_passphrase(" rivulet - Moth - 青松 - crypt-77 ")
    require_export_passphrase("%@?#!_[!?.:+}~^|)-)&")
    require_export_passphrase("correct horse battery staple")
    require_export_passphrase("abcdefghijklmnopqrst")
    expanded = "ﬃﬄ①②③㍿ⅫⅦΑΒΓΔ中文"
    assert len(expanded) < 20 <= len(unicodedata.normalize("NFKC", expanded))
    require_export_passphrase(expanded)


def test_new_export_fits_the_standalone_utf8_passphrase_limit():
    value = PASSPHRASE + "水" * 1355
    value += "x" * (4096 - len(value.encode("utf-8")))
    require_export_passphrase(value)
    with pytest.raises(ExportPassphraseError, match="4,096 UTF-8 bytes"):
        require_export_passphrase(value + "水")
    with pytest.raises(ExportPassphraseError, match="valid UTF-8"):
        require_export_passphrase(PASSPHRASE + "\ud800")


class RecoveryProbe:
    supports_export = True

    async def export_keys(self, ids, password):
        assert ids == ["fixture-key"]
        assert password == PASSPHRASE
        return b"encrypted fixture"

    async def import_keys(self, data, password):
        assert password == "legacy80"
        assert data == b"older fixture"
        return ["fixture-key"]

    async def confirm_export_custody(self, data, password, location):
        assert password == "legacy80"
        assert data == b"older fixture"
        assert location == "offline-vault"
        return ["fixture-key"]


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.include_router(encryption.router)
    app.dependency_overrides[encryption.get_current_user] = lambda: SimpleNamespace(
        id="actor", role="admin"
    )
    app.dependency_overrides[encryption.get_db] = lambda: None
    monkeypatch.setattr(encryption, "get_kms_provider", RecoveryProbe)
    monkeypatch.setattr(encryption, "log_activity", lambda *_args, **_kwargs: None)
    with TestClient(app) as transport:
        yield transport


def assert_no_store(response):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_schema_and_good_requests(client):
    schema = client.get("/openapi.json").json()
    password = schema["components"]["schemas"]["ExportKeysRequest"]["properties"][
        "password"
    ]
    assert "minLength" not in password
    assert (
        f"{MIN_EXPORT_PASSPHRASE_LENGTH} significant characters"
        in password["description"]
    )
    assert "Unicode NFKC" in password["description"] and password["writeOnly"] is True
    response = client.post(
        "/api/v1/encryption/keys/export",
        json={"key_ids": ["fixture-key"], "password": PASSPHRASE},
    )
    assert response.status_code == 200 and response.content == b"encrypted fixture"
    assert_no_store(response)
    for action, fields in (
        ("import", {"password": "legacy80"}),
        ("confirm-export", {"password": "legacy80", "location": "offline-vault"}),
    ):
        response = client.post(
            f"/api/v1/encryption/keys/{action}",
            files={"file": ("legacy.bin", b"older fixture")},
            data=fields,
        )
        assert response.status_code == 200
        assert_no_store(response)


def test_invalid_recovery_bodies_do_not_echo_inputs(client, caplog, monkeypatch):
    marker = "sensitive-fixture-echo-321"
    for response in (
        client.post("/api/v1/encryption/keys/export", json={"password": marker}),
        client.post(
            "/api/v1/encryption/keys/export",
            json={"key_ids": [marker], "password": {"unexpected": marker}},
        ),
        client.post(
            "/api/v1/encryption/keys/export",
            content='{"password":"' + marker,
            headers={"Content-Type": "application/json"},
        ),
        client.post("/api/v1/encryption/keys/import", data={"password": marker}),
        client.post(
            "/api/v1/encryption/keys/confirm-export", data={"password": marker}
        ),
    ):
        assert response.status_code == 422
        assert marker not in response.text
        assert_no_store(response)

    class FailingRecovery(RecoveryProbe):
        async def export_keys(self, ids, password):
            raise RuntimeError(password)

    monkeypatch.setattr(encryption, "get_kms_provider", FailingRecovery)
    response = client.post(
        "/api/v1/encryption/keys/export",
        json={"key_ids": ["fixture-key"], "password": marker},
    )
    assert response.status_code == 500
    assert marker not in response.text and marker not in caplog.text
    assert_no_store(response)


def test_weak_choice_and_access_denial_are_private(client):
    for weak in ("violet fox" + "\u200b\u3164" * 20, "z1!7" * 10):
        response = client.post(
            "/api/v1/encryption/keys/export",
            json={"key_ids": ["fixture-key"], "password": weak},
        )
        assert response.status_code == 400
        assert "violet" not in response.text and "z1!7" not in response.text
        assert_no_store(response)
    client.app.dependency_overrides[encryption.get_current_user] = (
        lambda: SimpleNamespace(id="viewer", role="viewer")
    )
    response = client.post(
        "/api/v1/encryption/keys/export",
        json={"key_ids": ["fixture-key"], "password": PASSPHRASE},
    )
    assert response.status_code == 403
    assert_no_store(response)


def test_import_returns_only_authenticated_public_source_trust(client, monkeypatch):
    import json
    from uuid import uuid4

    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from core.kms.local import LocalKMSProvider, _derive_export_key
    from core.recovery_signing import TRUST_SCHEMA, _public_identity

    key_id, public = _public_identity(Ed25519PrivateKey.generate())
    trust = {
        "schema": TRUST_SCHEMA,
        "installation_id": str(uuid4()),
        "org_id": str(uuid4()),
        "key_id": key_id,
        "public_key": public,
    }
    kms = LocalKMSProvider()

    def imported(payload):
        assert payload["keys"][0]["key_material"] == "private-fixture-material"
        return ["historical-key"]

    monkeypatch.setattr(kms, "_import_key_rows", imported)
    monkeypatch.setattr(encryption, "get_kms_provider", lambda: kms)
    salt = b"synthetic-salt!!"
    box = Fernet(_derive_export_key("legacy80", salt))

    for supplied in (trust, {**trust, "key_id": "0" * 64}):
        archive = salt + box.encrypt(
            json.dumps(
                {
                    "format": "vnbui-key-export",
                    "keys": [{"key_material": "private-fixture-material"}],
                    "recovery_trust": supplied,
                }
            ).encode()
        )
        response = client.post(
            "/api/v1/encryption/keys/import",
            files={"file": ("offline.bin", archive)},
            data={"password": "legacy80"},
        )
        assert response.status_code == 200
        assert_no_store(response)
        assert response.json() == {
            "imported_key_ids": ["historical-key"],
            "count": 1,
            **({"recovery_trust": trust} if supplied == trust else {}),
        }
        assert "private-fixture-material" not in response.text
