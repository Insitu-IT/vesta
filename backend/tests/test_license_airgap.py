"""Signed license validation must never need DNS or a license server."""

import base64
import json
import socket

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from core.licensing_advanced import LicenseRevokedError, LicenseValidator


@pytest.fixture
def network_attempts(monkeypatch):
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("License validation attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    return attempts


@pytest.fixture
def signed_license(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    monkeypatch.setattr(
        LicenseValidator, "PUBLIC_KEYS", {"offline-test-key": public_key}
    )
    monkeypatch.setattr(LicenseValidator, "_load_additional_keys", lambda self: None)
    path = tmp_path / "license.jwt"
    monkeypatch.setenv("LICENSE_FILE", str(path))
    audit = []
    monkeypatch.setattr(
        LicenseValidator, "_record_usage", lambda self, data: audit.append(data)
    )

    def install(revocation):
        payload = {
            "license_id": "offline-license",
            "tier": "enterprise",
            "features": ["ldap"],
            "revocation_check": revocation,
        }
        signature = key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        path.write_text(
            json.dumps(
                {
                    "payload": payload,
                    "signature": {
                        "keyid": "offline-test-key",
                        "value": base64.b64encode(signature).decode(),
                    },
                }
            )
        )
        validator = LicenseValidator()
        validator.revocation_cache_path = str(tmp_path / "crl.cache")
        return validator, payload, audit

    return install


@pytest.mark.parametrize(
    "crl_url", ["https://license.example.invalid/crl", "http://127.0.0.1:9/crl"]
)
def test_legacy_online_revocation_fields_never_cause_network(
    signed_license, network_attempts, crl_url
):
    validator, payload, audit = signed_license(
        {"enabled": True, "crl_url": crl_url, "check_interval": 0}
    )
    assert validator.validate() == payload
    assert validator.validate() == payload
    assert len(audit) == 2
    assert network_attempts == []


def test_local_revocation_remains_enforced_without_network(
    signed_license, network_attempts
):
    from pathlib import Path

    validator, payload, audit = signed_license({"enabled": True})
    Path(validator.revocation_cache_path).write_text(
        json.dumps({payload["license_id"]: {"revoked": True}})
    )
    with pytest.raises(LicenseRevokedError, match="revoked"):
        validator.validate()
    assert audit == []
    assert network_attempts == []


def test_unlicensed_startup_is_local(tmp_path, monkeypatch, network_attempts):
    monkeypatch.setenv("LICENSE_FILE", str(tmp_path / "absent-license.jwt"))
    assert LicenseValidator().validate() == {"tier": "oss", "features": []}
    assert network_attempts == []
