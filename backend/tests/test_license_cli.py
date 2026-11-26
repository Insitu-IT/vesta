"""Offline issuer files and actual audited two-step operator acknowledgements."""

import json
from datetime import datetime, timedelta, timezone
import socket

import pytest

from core import license_cli
from core.license_registration import RegistrationError, verify_certificate


@pytest.fixture
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline license operation attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def arguments(*values):
    return license_cli.build_parser().parse_args(values)


@pytest.fixture
def issuer(tmp_path, no_network):
    private, public = tmp_path / "issuer.pem", tmp_path / "public.json"
    args = arguments(
        "keygen",
        "--key-id",
        "operator-2026-v1",
        "--private-key",
        str(private),
        "--public-keys",
        str(public),
    )
    license_cli.keygen(args)
    return private, public


@pytest.mark.parametrize("license_class", ["free", "paid"])
def test_issue_exact_runtime_verified_certificate_without_network(
    tmp_path, issuer, no_network, license_class
):
    private, public = issuer
    assert private.stat().st_mode & 0o777 == 0o600
    payload = {
        "product": "vesta",
        "license_id": "fixture-license",
        "customer_id": "fixture-customer",
        "class": license_class,
        "issued_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "coverage": {"modules": ["billing_api"] if license_class == "paid" else []},
        "policy_version": "registration-v1",
    }
    source, target = tmp_path / "payload.json", tmp_path / "license.json"
    source.write_text(json.dumps(payload))
    args = arguments(
        "issue",
        "--key-id",
        "operator-2026-v1",
        "--private-key",
        str(private),
        "--payload-file",
        str(source),
        "--output",
        str(target),
    )
    license_cli.issue(args)
    assert verify_certificate(target.read_text(), keys_path=public) == payload
    envelope = json.loads(target.read_text())
    assert set(envelope) == {"schema_version", "key_id", "payload", "signature"}
    assert target.stat().st_mode & 0o777 == 0o600
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        license_cli.issue(args)
    assert target.read_bytes() == before


def test_keygen_never_overwrites_or_exposes_existing_issuer_key(
    tmp_path, issuer, no_network
):
    private, public = issuer
    before = private.read_bytes()
    with pytest.raises(ValueError, match="new local files"):
        license_cli.keygen(
            arguments(
                "keygen",
                "--key-id",
                "operator-2026-v1",
                "--private-key",
                str(private),
                "--public-keys",
                str(public),
            )
        )
    assert private.read_bytes() == before
    private.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        license_cli.read_file(private, private=True)
    alias = tmp_path / "alias"
    alias.symlink_to(private)
    with pytest.raises(OSError):
        license_cli.read_file(alias)


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"product": "different"}, "wrong product"),
        ({"policy_version": "future-policy"}, "unsupported policy"),
    ],
)
def test_incompatible_product_or_policy_cannot_be_issued(
    tmp_path, issuer, no_network, overrides, reason
):
    private, _ = issuer
    source, target = tmp_path / "payload.json", tmp_path / "license.json"
    source.write_text(
        json.dumps(
            {
                "product": "vesta",
                "license_id": "id",
                "customer_id": "id",
                "class": "free",
                "issued_at": "2026-01-01T00:00:00Z",
                "coverage": {"modules": []},
                **overrides,
            }
        )
    )
    with pytest.raises(RegistrationError, match=reason):
        license_cli.issue(
            arguments(
                "issue",
                "--key-id",
                "operator-2026-v1",
                "--private-key",
                str(private),
                "--payload-file",
                str(source),
                "--output",
                str(target),
            )
        )
    assert not target.exists()


def test_issuer_can_prepare_future_renewal_but_runtime_import_rejects_early_activation(
    tmp_path, issuer, no_network
):
    private, public = issuer
    beginning = datetime.now(timezone.utc) + timedelta(days=31)
    payload = {
        "product": "vesta",
        "license_id": "future-renewal",
        "customer_id": "customer",
        "class": "paid",
        "issued_at": (beginning - timedelta(days=1)).isoformat(),
        "not_before": beginning.isoformat(),
        "expires_at": (beginning + timedelta(days=365)).isoformat(),
        "coverage": {"modules": ["billing_api"]},
    }
    source, target = tmp_path / "future.json", tmp_path / "renewal.json"
    source.write_text(json.dumps(payload))
    license_cli.issue(
        arguments(
            "issue",
            "--key-id",
            "operator-2026-v1",
            "--private-key",
            str(private),
            "--payload-file",
            str(source),
            "--output",
            str(target),
        )
    )
    assert (
        verify_certificate(target.read_text(), keys_path=public, now=beginning)
        == payload
    )
    with pytest.raises(RegistrationError, match="not yet valid"):
        verify_certificate(target.read_text(), keys_path=public)


def test_operator_acknowledgement_requires_two_commands_and_audits_actual_actor(
    tmp_path, db_session, session_factory, monkeypatch, no_network
):
    from core.installed_profile import InstalledProfile
    from core.licensing import features
    from models import ActivityLog, OrganizationDefault, User

    monkeypatch.setattr(
        features,
        "profile",
        InstalledProfile(
            "commercial", "multi_organization", frozenset({"multi_tenancy"})
        ),
    )
    organization = db_session.get(OrganizationDefault, "oss").org_id
    actor = User(
        username="issuer-operator-test",
        password_hash="unusable-fixture",
        org_id=organization,
        role="admin",
        is_active=True,
        is_platform_admin=True,
    )
    db_session.add(actor)
    db_session.commit()
    actor_id = actor.id
    challenge, phrase = tmp_path / "challenge.json", tmp_path / "phrase.txt"
    common = ["--actor-user-id", actor_id, "--reason", "offline operator acceptance"]
    prepare = arguments("ack-prepare", *common, "--challenge-file", str(challenge))
    with pytest.raises(ValueError, match="First review"):
        license_cli.run_operator(prepare, session_factory)
    assert db_session.query(ActivityLog).count() == 0
    prepare.confirm_review = True
    result = license_cli.run_operator(prepare, session_factory)
    assert result["challenge_file_created"]
    assert challenge.stat().st_mode & 0o777 == 0o600
    phrase.write_text("HIDE LICENSING NOTICE\n")
    confirm = arguments(
        "ack-confirm",
        *common,
        "--challenge-file",
        str(challenge),
        "--phrase-file",
        str(phrase)
    )
    with pytest.raises(ValueError, match="Second confirmation"):
        license_cli.run_operator(confirm, session_factory)
    confirm.confirm_hide = True
    assert license_cli.run_operator(confirm, session_factory)["acknowledged"]
    with pytest.raises(RegistrationError):
        license_cli.run_operator(confirm, session_factory)
    status = license_cli.run_operator(arguments("status", *common), session_factory)
    assert status["acknowledged"]
    db_session.expire_all()
    events = db_session.query(ActivityLog).order_by(ActivityLog.created_at).all()
    assert [event.action for event in events[:2]] == [
        "licensing_acknowledgement_prepared",
        "licensing_notice_acknowledged",
    ]
    assert len(events) == 3  # Third event is the separately audited operator read.
    for event in events:
        assert event.details["actor"]["kind"] == "operator"
        assert event.details["actor"]["user_id"] == actor_id
        assert "uid:" in event.details["actor"]["label"]
        assert json.loads(challenge.read_text())["challenge"] not in json.dumps(
            event.details
        )
