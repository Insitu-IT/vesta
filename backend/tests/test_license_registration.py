"""Offline authenticity, atomic administration and persistent advisory notices."""

import base64
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import event

from core import community_usage
from core import license_registration as registration
from core.installed_profile import InstalledProfile
from core.license_registration import (
    LicensingActor,
    LicensingService,
    RegistrationError,
    canonical_signed_bytes,
    verify_certificate,
)
from models import (
    ActivityLog,
    Agent,
    Backup,
    Organization,
    OrganizationDefault,
    SettingV3,
    StorageConfigurationClock,
    StorageLineageGeneration,
    User,
    VM,
)

NOW = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
INSTALLATION = "1a72db23-50a7-4a72-a36e-7c9d73e4aa41"
COMMERCIAL = InstalledProfile(
    "commercial", "multi_organization", frozenset({"multi_tenancy", "billing_api"})
)


@pytest.fixture
def issuer(tmp_path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "keys": {"test-key": base64.b64encode(public).decode()},
            }
        )
    )

    def sign(**overrides):
        payload = {
            "product": "vesta",
            "license_id": "synthetic-license",
            "customer_id": "synthetic-customer",
            "class": "paid",
            "issued_at": (NOW - timedelta(days=1)).isoformat(),
            "coverage": {"modules": sorted(COMMERCIAL.enabled_modules)},
        }
        payload.update(overrides)
        unsigned = {"schema_version": 1, "key_id": "test-key", "payload": payload}
        return json.dumps(
            {
                **unsigned,
                "signature": base64.b64encode(
                    key.sign(canonical_signed_bytes(unsigned))
                ).decode(),
            }
        )

    return SimpleNamespace(sign=sign, key=key, path=str(path))


@pytest.fixture
def admin(db_session):
    org = db_session.get(OrganizationDefault, "oss").org_id
    user = User(
        org_id=org,
        username="license-admin",
        password_hash="unused",
        role="admin",
        is_active=True,
        is_platform_admin=True,
    )
    db_session.add(user)
    db_session.add(
        StorageConfigurationClock(slot=1, installation_id=INSTALLATION, revision=1)
    )
    db_session.commit()
    return user


def service(db, admin, issuer, profile=COMMERCIAL, now=NOW, kind="user"):
    return LicensingService(
        db,
        LicensingActor(
            admin.id,
            "synthetic-operator" if kind == "operator" else admin.username,
            kind,
        ),
        profile,
        now,
        issuer.path,
    )


def seed_observed_usage(db, org_id, backups, vms, agents):
    enrolled = [
        Agent(org_id=org_id, hostname=f"scope-agent-{index}", status="offline")
        for index in range(agents)
    ]
    placeholder = Agent(org_id=org_id, hostname="__s3_import__")
    db.add_all(enrolled + [placeholder])
    db.flush()
    inventory = [
        VM(org_id=org_id, agent_id=enrolled[0].id, name=f"scope-vm-{index}")
        for index in range(vms)
    ]
    db.add_all(
        inventory
        + [
            VM(org_id=org_id, agent_id=placeholder.id, name="legacy import"),
            VM(
                org_id=org_id,
                agent_id=enrolled[0].id,
                name="gone",
                inventory_present=False,
            ),
        ]
    )
    db.flush()

    def row(status, storage_path="s3://test-bucket/backup", tags=None):
        return Backup(
            org_id=org_id,
            vm_id=inventory[0].id,
            status=status,
            storage_path=storage_path,
            completed_at=NOW.replace(tzinfo=None),
            tags=tags or {},
        )

    accepted = [
        row(
            ("completed", "deleting", "deleted")[index % 3],
            tags={"imported_from_s3": "user-supplied label"},
        )
        for index in range(backups)
    ]
    db.add_all(
        accepted
        + [
            row("failed"),
            row("completed", storage_path=None),
            row("completed", tags={"imported_from_s3": True}),
            row("completed"),
        ]
    )
    db.flush()
    # Count one backup identity even if the ledger has another generation.
    for backup in accepted + accepted[:1]:
        db.add(
            StorageLineageGeneration(
                id=str(uuid.uuid4()),
                org_id=org_id,
                vm_id=backup.vm_id,
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


@pytest.mark.parametrize(
    "backups,vms,agents,reached",
    [(100, 21, 3, False), (101, 20, 2, False), (101, 21, 2, True), (101, 20, 3, True)],
)
def test_community_observes_strict_thresholds_and_retained_successes(
    db_session, admin, issuer, backups, vms, agents, reached
):
    seed_observed_usage(db_session, admin.org_id, backups, vms, agents)
    community = service(db_session, admin, issuer, profile=InstalledProfile())
    summary = community.status()
    assert summary["notice_required"] is reached
    assert summary["policy"]["usage_rules_configured"]
    assert "community_usage" not in summary
    detail = community.details()
    assert detail["status"] == summary
    assert detail["community_usage"] == {
        "schedule_version": community_usage.SCHEDULE_VERSION,
        "successful_backups": backups,
        "inventoried_vms": vms,
        "registered_agents": agents,
        "threshold_reached": reached,
    }


def test_community_observation_uses_only_its_installed_organization(
    db_session, admin, issuer
):
    other = Organization(name="Separate organization")
    db_session.add(other)
    db_session.commit()
    seed_observed_usage(db_session, other.id, 101, 21, 3)
    community = service(db_session, admin, issuer, profile=InstalledProfile())
    assert community.details()["community_usage"]["successful_backups"] == 0
    assert not community.status()["notice_required"]


def test_community_notice_changes_scope_with_schedule_and_free_registration_satisfies_it(
    db_session, admin, issuer, monkeypatch
):
    seed_observed_usage(db_session, admin.org_id, 101, 20, 3)
    community = service(db_session, admin, issuer, profile=InstalledProfile())
    status = community.status()
    assert status["reason_code"] == "community_usage_threshold_reached"
    preview = community.prepare_acknowledgement(True)
    community.confirm_acknowledgement(
        preview["challenge"], preview["expected_phrase"], True
    )
    assert community.status()["acknowledged"]

    monkeypatch.setattr(community_usage, "SCHEDULE_VERSION", "next-schedule")
    changed = community.status()
    assert changed["notice_scope"] != status["notice_scope"]
    assert changed["notice_required"] and not changed["acknowledged"]

    registered = community.import_certificate(
        issuer.sign(**{"class": "free", "coverage": {"modules": []}})
    )
    assert registered["status"]["status"] == "valid_free"
    assert not registered["status"]["notice_required"]
    assert registered["community_usage"]["threshold_reached"]
    assert community.profile == InstalledProfile()


def test_two_year_free_license_replaces_the_active_grant_and_expires_at_utc_boundary(
    db_session, admin, issuer
):
    profile = InstalledProfile()
    current = service(db_session, admin, issuer, profile=profile)
    current.import_certificate(issuer.sign(license_id="first"))
    expires = NOW.replace(year=NOW.year + 2)
    certificate = issuer.sign(
        **{
            "class": "free",
            "license_id": "6.1.0/community-usage-v2/fixture",
            "installation_id": INSTALLATION,
            "policy_version": registration.POLICY_VERSION,
            "issued_at": NOW.isoformat(),
            "expires_at": expires.isoformat(),
            "coverage": {"modules": []},
        }
    )
    detail = current.import_certificate(certificate)
    assert detail["installation_id"] == INSTALLATION
    assert detail["certificate"]["license_id"] == "6.1.0/community-usage-v2/fixture"
    assert detail["status"]["status"] == "valid_free"
    assert verify_certificate(
        certificate, issuer.path, INSTALLATION, expires - timedelta(seconds=1)
    )
    assert (
        service(db_session, admin, issuer, profile=profile, now=expires).status()[
            "status"
        ]
        == "expired"
    )


@pytest.mark.parametrize("license_class", ["free", "paid"])
def test_signed_free_paid_and_optional_binding(issuer, license_class):
    payload = verify_certificate(
        issuer.sign(**{"class": license_class, "installation_id": INSTALLATION}),
        issuer.path,
        INSTALLATION,
        NOW,
    )
    assert payload["class"] == license_class
    assert (
        verify_certificate(issuer.sign(), issuer.path, None, NOW)["product"] == "vesta"
    )


@pytest.mark.parametrize(
    "override,code",
    [
        ({"product": "other"}, "wrong_product"),
        ({"unexpected": "value"}, "invalid_payload"),
        ({"class": "enterprise"}, "invalid_class"),
        ({"issued_at": "2026-01-01T00:00:00"}, "invalid_date"),
        ({"issued_at": "2026-01-01T01:00:00+01:00"}, "invalid_date"),
        ({"not_before": (NOW + timedelta(days=1)).isoformat()}, "not_yet_valid"),
        ({"expires_at": NOW.isoformat()}, "expired"),
        ({"expires_at": "2025-01-01T00:00:00Z"}, "invalid_date_range"),
        ({"installation_id": str(uuid.uuid4())}, "wrong_installation"),
        ({"coverage": {"modules": ["unknown"]}}, "invalid_coverage"),
        ({"coverage": {"modules": ["billing_api", "billing_api"]}}, "invalid_coverage"),
    ],
)
def test_payload_rejections(issuer, override, code):
    with pytest.raises(RegistrationError) as error:
        verify_certificate(issuer.sign(**override), issuer.path, INSTALLATION, NOW)
    assert error.value.code == code


@pytest.mark.parametrize(
    "kind",
    [
        "tamper",
        "unknown-key",
        "bool-version",
        "unsigned",
        "duplicate",
        "nested-duplicate",
        "oversized",
        "bad-base64",
        "algorithm",
        "embedded-key",
    ],
)
def test_strict_envelope_and_authenticity(issuer, kind):
    raw = issuer.sign()
    envelope = json.loads(raw)
    if kind == "tamper":
        envelope["payload"]["customer_id"] = "changed"
    elif kind == "unknown-key":
        envelope["key_id"] = "unknown"
    elif kind == "bool-version":
        envelope["schema_version"] = True
    elif kind == "unsigned":
        envelope.pop("signature")
    elif kind == "bad-base64":
        envelope["signature"] = "!"
    elif kind == "algorithm":
        envelope["algorithm"] = "none"
    elif kind == "embedded-key":
        envelope["public_key"] = "attacker"
    elif kind == "duplicate":
        raw = raw.replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
        )
    elif kind == "nested-duplicate":
        raw = raw.replace(
            '"product": "vesta"', '"product": "vesta", "product": "vesta"'
        )
    elif kind == "oversized":
        raw += " " * 65536
    if kind not in {"duplicate", "nested-duplicate", "oversized"}:
        raw = json.dumps(envelope)
    with pytest.raises(RegistrationError):
        verify_certificate(raw, issuer.path, INSTALLATION, NOW)


def test_trust_diagnostics_and_rotation_fail_without_unsigned_fallback(
    tmp_path, issuer
):
    missing = str(tmp_path / "missing.json")
    assert registration.load_trusted_keys(missing)[1]["state"] == "unprovisioned"
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":1,"keys":{"bad":"not-key"}}')
    assert registration.load_trusted_keys(str(bad))[1]["state"] == "invalid"
    with pytest.raises(RegistrationError, match="unknown key"):
        verify_certificate(issuer.sign(), missing, INSTALLATION, NOW)


def test_failed_import_preserves_previous_and_audit(db_session, admin, issuer):
    svc = service(db_session, admin, issuer)
    result = svc.import_certificate(issuer.sign())
    assert result["status"]["status"] == "valid_paid"
    previous = db_session.get(SettingV3, registration.STATE_KEY).value
    with pytest.raises(RegistrationError):
        svc.import_certificate("not-json")
    assert db_session.get(SettingV3, registration.STATE_KEY).value == previous
    assert db_session.query(ActivityLog).count() == 1
    assert svc.details()["installation_id"] == INSTALLATION
    assert svc.details()["trust_store"]["fingerprints"]["test-key"]


def test_audit_failure_rolls_back_import(db_session, admin, issuer):
    svc = service(db_session, admin, issuer)
    svc.import_certificate(issuer.sign(license_id="prior"))

    @event.listens_for(db_session, "before_flush")
    def fail_audit(session, *args):
        if any(isinstance(row, ActivityLog) for row in session.new):
            raise RuntimeError("audit unavailable")

    try:
        with pytest.raises(RuntimeError):
            svc.import_certificate(issuer.sign(license_id="next"))
    finally:
        event.remove(db_session, "before_flush", fail_audit)
    assert svc.details()["certificate"]["license_id"] == "prior"
    assert db_session.query(ActivityLog).count() == 1


def test_summary_has_no_customer_details_and_cannot_promote_features(
    db_session, admin, issuer, monkeypatch
):
    from core import licensing, tenant_context

    flags = licensing.FeatureFlags(profile=InstalledProfile())
    monkeypatch.setattr(licensing, "features", flags)
    svc = service(db_session, admin, issuer, InstalledProfile())
    assert svc.status()["status"] == "not_required"
    svc.import_certificate(issuer.sign())
    status = svc.status()
    assert status["status"] == "valid_paid" and not status["notice_required"]
    assert "customer" not in json.dumps(status) and "certificate" not in status
    assert tenant_context.commercial_mode() is False and flags.multi_tenancy is False
    assert flags.backup_restore and flags.scheduling


def test_insufficient_and_expired_licenses_never_disable_installed_modules(
    db_session, admin, issuer, monkeypatch
):
    from core import licensing, tenant_context

    flags = licensing.FeatureFlags(profile=COMMERCIAL)
    for module in COMMERCIAL.enabled_modules:
        flags.activate(module)
    monkeypatch.setattr(licensing, "features", flags)
    svc = service(db_session, admin, issuer)
    assert svc.status()["status"] == "required"
    svc.import_certificate(issuer.sign(**{"class": "free"}))
    assert svc.status()["status"] == "insufficient_coverage"
    svc.import_certificate(
        issuer.sign(expires_at=(NOW + timedelta(hours=1)).isoformat())
    )
    expired = service(db_session, admin, issuer, now=NOW + timedelta(days=1))
    assert expired.status()["status"] == "expired"
    assert (
        tenant_context.commercial_mode() is True
        and flags.multi_tenancy
        and flags.billing_api
    )
    assert flags.backup_restore and flags.scheduling


@pytest.mark.parametrize("profile", [InstalledProfile(), COMMERCIAL])
@pytest.mark.asyncio
async def test_installed_capabilities_and_local_keys_survive_registration_states(
    db_session, patch_session_local, admin, issuer, monkeypatch, tmp_path, profile
):
    from core.kms.local import LocalKMSProvider
    from core.licensing import FeatureFlags
    from routers import public

    flags = FeatureFlags(profile=profile)
    for module in profile.enabled_modules:
        flags.activate(module)
    monkeypatch.setattr(public, "features", flags)
    provider = LocalKMSProvider()
    key = await provider.create_key("registration-round-trip")
    data_key = bytes(range(32))

    capabilities = await public.get_features()
    legacy = await public.get_license_info()
    assert capabilities["license_enforcement"] == "advisory"
    assert (
        capabilities["configured_modules"]
        == capabilities["loaded_modules"]
        == sorted(profile.enabled_modules)
    )
    assert capabilities["flags"]["billing_api"] == (profile.edition == "commercial")
    assert capabilities["flags"]["client_encryption"] is True
    assert "client_encryption" in capabilities["features"]
    assert legacy["features"]["client_encryption"] is True

    async def assert_capabilities_unchanged():
        assert await public.get_features() == capabilities
        assert await public.get_license_info() == legacy
        wrapped = await provider.wrap_dek(data_key, key.id)
        assert wrapped != data_key
        assert await provider.unwrap_dek(wrapped, key.id) == data_key

    registration_service = service(db_session, admin, issuer, profile=profile)
    absent = "not_required" if profile.edition == "community" else "required"
    assert registration_service.status()["status"] == absent
    await assert_capabilities_unchanged()

    registration_service.import_certificate(
        issuer.sign(expires_at=(NOW + timedelta(hours=1)).isoformat())
    )
    assert registration_service.status()["status"] == "valid_paid"
    await assert_capabilities_unchanged()

    unknown_issuer = SimpleNamespace(path=str(tmp_path / "missing-trust.json"))
    assert (
        service(db_session, admin, unknown_issuer, profile=profile).status()["status"]
        == "invalid"
    )
    await assert_capabilities_unchanged()

    expired = service(
        db_session, admin, issuer, profile=profile, now=NOW + timedelta(days=1)
    )
    assert expired.status()["status"] == "expired"
    await assert_capabilities_unchanged()


def test_acknowledgement_requires_both_confirmations_persists_and_can_clear(
    db_session, admin, issuer
):
    svc = service(db_session, admin, issuer)
    with pytest.raises(RegistrationError):
        svc.prepare_acknowledgement(False)
    preview = svc.prepare_acknowledgement(True)
    assert not svc.status()["acknowledged"]
    with pytest.raises(RegistrationError):
        svc.confirm_acknowledgement(preview["challenge"], "wrong", True)
    with pytest.raises(RegistrationError):
        svc.confirm_acknowledgement(
            preview["challenge"], preview["expected_phrase"], False
        )
    result = svc.confirm_acknowledgement(
        preview["challenge"], preview["expected_phrase"], True
    )
    assert result["acknowledged"] and result["status"] == "required"
    assert service(db_session, admin, issuer, now=NOW + timedelta(days=365)).status()[
        "acknowledged"
    ]
    with pytest.raises(RegistrationError):
        svc.confirm_acknowledgement(
            preview["challenge"], preview["expected_phrase"], True
        )
    assert svc.clear_acknowledgement()["acknowledged"] is False


def test_challenge_bound_to_actor_scope_and_time(
    db_session, admin, issuer, monkeypatch
):
    svc = service(db_session, admin, issuer)
    preview = svc.prepare_acknowledgement(True)
    expired = service(db_session, admin, issuer, now=NOW + timedelta(minutes=11))
    with pytest.raises(RegistrationError, match="challenge expired"):
        expired.confirm_acknowledgement(
            preview["challenge"], preview["expected_phrase"], True
        )
    operator = service(db_session, admin, issuer, kind="operator")
    with pytest.raises(RegistrationError):
        operator.confirm_acknowledgement(
            preview["challenge"], preview["expected_phrase"], True
        )
    monkeypatch.setattr(registration, "POLICY_VERSION", "next-policy")
    with pytest.raises(RegistrationError):
        svc.confirm_acknowledgement(
            preview["challenge"], preview["expected_phrase"], True
        )
    assert not svc.status()["acknowledged"]


def test_authority_is_persisted_and_operator_identity_is_distinct(
    db_session, admin, issuer
):
    svc = service(db_session, admin, issuer, kind="operator")
    svc.set_registration_url("")
    svc.record_operator_access("details")
    record = (
        db_session.query(ActivityLog)
        .filter(ActivityLog.action == "licensing_operator_details")
        .one()
    )
    assert record.user_id == admin.id and record.details["actor"]["kind"] == "operator"
    admin.is_platform_admin = False
    db_session.commit()
    with pytest.raises(RegistrationError) as error:
        svc.set_registration_url("https://example.org")
    assert error.value.status_code == 403
    assert (
        db_session.get(SettingV3, registration.STATE_KEY).value.find(
            '"registration_url":""'
        )
        >= 0
    )


@pytest.mark.parametrize(
    "value",
    [
        "http://example.org",
        "javascript:alert(1)",
        "https://user:secret@example.org",
        "https://[broken",
        "https://example.org/\n",
    ],
)
def test_registration_url_is_display_only_bounded_https(
    db_session, admin, issuer, value
):
    with pytest.raises(RegistrationError):
        service(db_session, admin, issuer).set_registration_url(value)
    assert db_session.get(SettingV3, registration.STATE_KEY) is None


def test_reserved_settings_not_exposed_or_writable_through_generic_settings(
    db_session, admin, issuer
):
    from core.settings_service import SettingsService

    svc = service(db_session, admin, issuer)
    svc.prepare_acknowledgement(True)
    settings = SettingsService(db_session)
    assert registration.STATE_KEY not in settings.get_all()
    with pytest.raises(ValueError):
        settings.validate_update({registration.STATE_KEY: {"acknowledgement": True}})


def test_routes_require_auth_and_installation_authority_before_decode(monkeypatch):
    from database import get_db
    from deps import get_current_user, get_installation_admin, get_installation_db
    from fastapi import HTTPException
    from routers import licensing as routes

    app = FastAPI()
    app.include_router(routes.router)

    def deny():
        raise HTTPException(403, "installation authority required")

    app.dependency_overrides[get_installation_admin] = deny
    app.dependency_overrides[get_installation_db] = lambda: None
    app.dependency_overrides[get_db] = lambda: None
    app.dependency_overrides[get_current_user] = lambda: (_ for _ in ()).throw(
        HTTPException(401, "authentication required")
    )
    with TestClient(app) as client:
        assert client.get("/api/v1/licensing/status").status_code == 401
        for method, path in [
            ("post", "import"),
            ("put", "registration-url"),
            ("post", "acknowledgement/prepare"),
            ("post", "acknowledgement/confirm"),
            ("delete", "acknowledgement"),
        ]:
            assert (
                client.request(
                    method, "/api/v1/licensing/" + path, content=b"broken" * 65536
                ).status_code
                == 403
            )
        assert client.get("/api/v1/licensing").status_code == 403


def test_all_registration_transitions_are_local(db_session, admin, issuer, monkeypatch):
    import socket
    import urllib.request

    def no_network(*args, **kwargs):
        raise AssertionError("registration attempted network IO")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    svc = service(db_session, admin, issuer)
    svc.status()
    svc.details()
    svc.set_registration_url("https://registration.invalid/vesta")
    svc.import_certificate(issuer.sign(**{"class": "free"}))
    preview = svc.prepare_acknowledgement(True)
    svc.confirm_acknowledgement(preview["challenge"], preview["expected_phrase"], True)
    assert svc.details()["status"]["acknowledged"]
    svc.clear_acknowledgement()


def test_acknowledgement_audit_failure_is_atomic_and_challenge_remains(
    db_session, admin, issuer
):
    svc = service(db_session, admin, issuer)
    preview = svc.prepare_acknowledgement(True)

    @event.listens_for(db_session, "before_flush")
    def fail_ack(session, *args):
        if any(
            isinstance(row, ActivityLog)
            and row.action == "licensing_notice_acknowledged"
            for row in session.new
        ):
            raise RuntimeError("audit unavailable")

    try:
        with pytest.raises(RuntimeError):
            svc.confirm_acknowledgement(
                preview["challenge"], preview["expected_phrase"], True
            )
    finally:
        event.remove(db_session, "before_flush", fail_ack)
    assert not svc.status()["acknowledged"]
    assert svc.confirm_acknowledgement(
        preview["challenge"], preview["expected_phrase"], True
    )["acknowledged"]


def test_missing_invalid_and_rotated_trust_are_diagnostic_only(
    db_session, admin, issuer, tmp_path
):
    svc = service(db_session, admin, issuer)
    svc.import_certificate(issuer.sign())
    for path, trust_state in [
        (str(tmp_path / "missing"), "unprovisioned"),
        (str(tmp_path / "bad"), "invalid"),
    ]:
        if trust_state == "invalid":
            (tmp_path / "bad").write_text("invalid")
        diagnostic = LicensingService(db_session, svc.actor, COMMERCIAL, NOW, path)
        details = diagnostic.details()
        assert details["status"]["status"] == "invalid"
        assert details["status"]["reason_code"] == "unknown_key"
        assert details["trust_store"]["state"] == trust_state
        assert diagnostic.profile == COMMERCIAL
        assert details["certificate"]["license_id"] == "synthetic-license"


def test_acknowledgement_survives_certificate_changes_same_policy(
    db_session, admin, issuer
):
    svc = service(db_session, admin, issuer)
    preview = svc.prepare_acknowledgement(True)
    svc.confirm_acknowledgement(preview["challenge"], preview["expected_phrase"], True)
    svc.import_certificate(
        issuer.sign(expires_at=(NOW + timedelta(hours=1)).isoformat())
    )
    assert svc.status()["acknowledged"] and not svc.status()["notice_required"]
    expired = service(db_session, admin, issuer, now=NOW + timedelta(days=1))
    assert expired.status()["acknowledged"] and expired.status()["status"] == "expired"


def test_admin_http_import_bounded_body_and_strict_confirm(
    db_session, admin, issuer, monkeypatch
):
    from deps import get_installation_admin, get_installation_db
    from routers import licensing as routes

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_installation_admin] = lambda: admin
    app.dependency_overrides[get_installation_db] = lambda: db_session
    monkeypatch.setattr(routes, "_service", lambda db, user: service(db, user, issuer))
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/v1/licensing/import", json={"envelope": issuer.sign()}
            ).status_code
            == 200
        )
        assert (
            client.post("/api/v1/licensing/import", content=b"x" * 135169).status_code
            == 413
        )
        response = client.post(
            "/api/v1/licensing/acknowledgement/prepare", json={"confirm": 1}
        )
        assert (
            response.status_code == 422
            and response.json()["detail"]["code"] == "invalid_request"
        )
        malformed = client.put(
            "/api/v1/licensing/registration-url", json={"url": "https://[broken"}
        )
        assert (
            malformed.status_code == 422
            and malformed.json()["detail"]["code"] == "invalid_registration_url"
        )
        assert db_session.query(ActivityLog).count() == 1


def test_demo_denies_registration_routes_before_service(monkeypatch):
    from config import settings
    from middleware import DemoPolicyMiddleware
    from routers import licensing as routes

    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(
        routes,
        "_service",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("demo reached registration service")
        ),
    )
    app = FastAPI()
    app.include_router(routes.router)
    app.add_middleware(DemoPolicyMiddleware)
    with TestClient(app) as client:
        for method, path in [
            ("get", "status"),
            ("get", ""),
            ("post", "import"),
            ("put", "registration-url"),
            ("post", "acknowledgement/prepare"),
            ("post", "acknowledgement/confirm"),
            ("delete", "acknowledgement"),
        ]:
            assert (
                client.request(
                    method, "/api/v1/licensing" + ("/" + path if path else "")
                ).status_code
                == 403
            )


def test_signed_unknown_policy_is_rejected_and_current_policy_supported(issuer):
    assert (
        verify_certificate(
            issuer.sign(policy_version="registration-v1"),
            issuer.path,
            INSTALLATION,
            NOW,
        )["policy_version"]
        == "registration-v1"
    )
    with pytest.raises(RegistrationError) as error:
        verify_certificate(
            issuer.sign(policy_version="unapproved-future-policy"),
            issuer.path,
            INSTALLATION,
            NOW,
        )
    assert error.value.code == "unsupported_policy"


def test_trust_store_is_regular_local_file_and_projection_symlink_works(
    issuer, tmp_path
):
    link = tmp_path / "projection.json"
    link.symlink_to(issuer.path)
    assert registration.load_trusted_keys(str(link))[1]["state"] == "configured"
    assert registration.load_trusted_keys(str(tmp_path))[1]["state"] == "invalid"


def test_admin_http_complete_advisory_flow(db_session, admin, issuer, monkeypatch):
    from database import get_db
    from deps import get_current_user, get_installation_admin, get_installation_db
    from routers import licensing as routes

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_installation_admin] = lambda: admin
    app.dependency_overrides[get_installation_db] = lambda: db_session
    monkeypatch.setattr(routes, "_service", lambda db, user: service(db, user, issuer))
    with TestClient(app) as client:
        assert client.get("/api/v1/licensing").json()["certificate"] is None
        assert client.get("/api/v1/licensing/status").json()["status"] == "required"
        assert (
            client.put("/api/v1/licensing/registration-url", json={"url": ""}).json()[
                "status"
            ]["registration_url"]
            == ""
        )
        assert (
            client.post(
                "/api/v1/licensing/import",
                json={"envelope": issuer.sign(**{"class": "free"})},
            ).json()["status"]["status"]
            == "insufficient_coverage"
        )
        preview = client.post(
            "/api/v1/licensing/acknowledgement/prepare", json={"confirm": True}
        ).json()
        confirmed = client.post(
            "/api/v1/licensing/acknowledgement/confirm",
            json={
                "confirm": True,
                "challenge": preview["challenge"],
                "phrase": preview["expected_phrase"],
            },
        )
        assert confirmed.status_code == 200 and confirmed.json()["acknowledged"]
        assert (
            client.delete("/api/v1/licensing/acknowledgement").json()["acknowledged"]
            is False
        )
        details = client.get("/api/v1/licensing").json()
        assert details["certificate"]["customer_id"] == "synthetic-customer"
        assert "synthetic-customer" not in client.get("/api/v1/licensing/status").text


@pytest.mark.parametrize("field", ["license_id", "customer_id", "policy_version"])
def test_signed_lone_surrogate_is_refused_before_replacement(
    db_session, admin, issuer, field
):
    svc = service(db_session, admin, issuer)
    svc.import_certificate(issuer.sign(customer_id="לקוח סינתטי"))
    previous = db_session.get(SettingV3, registration.STATE_KEY).value
    with pytest.raises(RegistrationError):
        svc.import_certificate(issuer.sign(**{field: "\ud800"}))
    assert db_session.get(SettingV3, registration.STATE_KEY).value == previous
    assert svc.details()["certificate"]["customer_id"] == "לקוח סינתטי"
    with pytest.raises(RegistrationError):
        svc.set_registration_url("https://example.org/\ud800")


def test_trust_fifo_is_rejected_without_blocking(issuer, tmp_path):
    import os
    import time

    fifo = tmp_path / "keys.fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    assert registration.load_trusted_keys(str(fifo))[1]["state"] == "invalid"
    assert time.monotonic() - started < 1


def test_offline_openapi_exposes_bounded_registration_request_bodies():
    from routers import licensing as routes

    app = FastAPI()
    app.include_router(routes.router)
    paths = app.openapi()["paths"]
    for path, method, fields in [
        ("/import", "post", {"envelope"}),
        ("/registration-url", "put", {"url"}),
        ("/acknowledgement/prepare", "post", {"confirm"}),
        ("/acknowledgement/confirm", "post", {"confirm", "challenge", "phrase"}),
    ]:
        body = paths["/api/v1/licensing" + path][method]["requestBody"]
        assert body["required"] is True
        schema = body["content"]["application/json"]["schema"]
        assert set(schema["required"]) == fields
        assert schema["additionalProperties"] is False
    envelope = paths["/api/v1/licensing/import"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["properties"]["envelope"]
    assert envelope["type"] == "string" and envelope["maxLength"] == 65536


def test_missing_storage_identity_stays_unbound_without_creating_one(
    db_session, admin, issuer
):
    db_session.query(StorageConfigurationClock).delete()
    db_session.commit()
    svc = service(db_session, admin, issuer)
    svc.import_certificate(issuer.sign())
    assert svc.details()["installation_id"] is None
    with pytest.raises(RegistrationError, match="wrong installation"):
        svc.import_certificate(issuer.sign(installation_id=INSTALLATION))
    assert db_session.query(StorageConfigurationClock).count() == 0
    assert svc.details()["certificate"].get("installation_id") is None
