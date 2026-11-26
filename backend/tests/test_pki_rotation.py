"""Certificate replacement retires prior credentials before the response."""

import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException, Request
from core.pki import retire_agent_certificates
from core.s3_ownership import StorageOwnershipError
from core.storage_attempt_key import _credential
from deps import _verify_agent_cert, hash_api_key
from models import Agent, AgentCertificate, AgentRegistrationKey, User
from routers import agents as agents_router
from routers import pki as pki_router


def _agent_with_certificate(db):
    agent = Agent(
        id=str(uuid.uuid4()),
        hostname="rotation-agent",
        status="online",
        cert_fingerprint="old-fingerprint",
        mtls_enabled=True,
    )
    old = AgentCertificate(
        id=str(uuid.uuid4()),
        agent_id=agent.id,
        serial_number=uuid.uuid4().hex,
        fingerprint="old-fingerprint",
        common_name=agent.hostname,
        expires_at=datetime.utcnow() + timedelta(days=1),
        status="active",
    )
    db.add_all([agent, old])
    db.commit()
    return agent, old


def test_current_certificate_only_after_atomic_replacement(db_session):
    agent, old = _agent_with_certificate(db_session)
    assert _verify_agent_cert(old.fingerprint, db_session).id == agent.id

    retire_agent_certificates(db_session, agent.id)
    agent.cert_fingerprint = "new-fingerprint"
    new = AgentCertificate(
        id=str(uuid.uuid4()),
        agent_id=agent.id,
        serial_number=uuid.uuid4().hex,
        fingerprint="new-fingerprint",
        common_name=agent.hostname,
        expires_at=datetime.utcnow() + timedelta(days=365),
        status="active",
    )
    db_session.add(new)
    db_session.commit()
    db_session.expire_all()

    assert old.status == "revoked" and old.revoked_at is not None
    assert _verify_agent_cert(old.fingerprint, db_session) is None
    assert _verify_agent_cert(new.fingerprint, db_session).id == agent.id
    with pytest.raises(StorageOwnershipError, match="Credential unavailable"):
        _credential(db_session, agent.id, ("certificate", old.fingerprint))
    _credential(db_session, agent.id, ("certificate", new.fingerprint))


def test_superseded_active_row_cannot_reenter_storage_effect(db_session):
    agent, old = _agent_with_certificate(db_session)
    agent.cert_fingerprint = "new-fingerprint"
    db_session.commit()

    assert old.status == "active"
    assert _verify_agent_cert(old.fingerprint, db_session) is None
    with pytest.raises(StorageOwnershipError, match="Credential unavailable"):
        _credential(db_session, agent.id, ("certificate", old.fingerprint))


@pytest.mark.asyncio
async def test_renewal_retires_old_certificate(db_session, monkeypatch):
    agent, old = _agent_with_certificate(db_session)
    expires = datetime.utcnow() + timedelta(days=365)

    class Signer:
        def sign_csr(self, csr, hostname):
            assert csr == b"test-csr"
            assert hostname == agent.hostname
            return {
                "cert_pem": "new-certificate",
                "serial": uuid.uuid4().hex,
                "fingerprint": "new-fingerprint",
                "expires_at": expires,
            }

    monkeypatch.setattr(pki_router, "get_pki_manager", lambda db: Signer())
    result = await pki_router.renew_certificate(
        {"csr": "test-csr"}, agent=agent, db=db_session
    )
    db_session.expire_all()

    assert result["fingerprint"] == "new-fingerprint"
    assert old.status == "revoked" and old.revoked_at is not None
    assert agent.cert_fingerprint == "new-fingerprint"
    assert _verify_agent_cert(old.fingerprint, db_session) is None
    assert _verify_agent_cert("new-fingerprint", db_session).id == agent.id


def _registration_key(db, hostname):
    issuer = User(
        id=str(uuid.uuid4()),
        username="rotation-admin",
        password_hash="unused",
        role="admin",
    )
    secret = uuid.uuid4().hex
    key = AgentRegistrationKey(
        id=str(uuid.uuid4()),
        name="rotation-key",
        agent_hostname=hostname,
        key_hash=hash_api_key(secret),
        key_prefix=secret[:8],
        max_uses=1,
        use_count=0,
        created_by=issuer.id,
    )
    db.add_all([issuer, key])
    db.commit()
    return key, secret


def _registration_request():
    return Request(
        {
            "type": "http",
            "scheme": "https",
            "server": ("example.test", 443),
            "path": "/api/v1/agents/register",
            "headers": [],
        }
    )


@pytest.mark.asyncio
async def test_failed_certificate_issue_does_not_spend_key_or_rotate_agent(
    db_session, monkeypatch
):
    agent, old = _agent_with_certificate(db_session)
    agent.api_key_hash = "original-key-hash"
    key, secret = _registration_key(db_session, agent.hostname)
    db_session.commit()
    monkeypatch.setattr(agents_router, "is_ca_initialized", lambda db: True)

    class FailedSigner:
        def issue_agent_cert(self, hostname):
            raise RuntimeError("CA unavailable")

    monkeypatch.setattr(agents_router, "get_pki_manager", lambda db: FailedSigner())
    with pytest.raises(HTTPException) as error:
        await agents_router.register_agent(
            {"hostname": agent.hostname},
            _registration_request(),
            api_key=secret,
            db=db_session,
        )
    db_session.expire_all()

    assert error.value.status_code == 503
    assert key.use_count == 0
    assert agent.api_key_hash == "original-key-hash"
    assert agent.cert_fingerprint == old.fingerprint
    assert old.status == "active"


@pytest.mark.asyncio
async def test_registration_replaces_key_and_certificate_atomically(
    db_session, monkeypatch
):
    agent, old = _agent_with_certificate(db_session)
    key, secret = _registration_key(db_session, agent.hostname)
    expires = datetime.utcnow() + timedelta(days=365)
    monkeypatch.setattr(agents_router, "is_ca_initialized", lambda db: True)

    class Signer:
        def issue_agent_cert(self, hostname):
            assert hostname == agent.hostname
            return {
                "cert_pem": "new-certificate",
                "key_pem": "new-private-key",
                "serial": uuid.uuid4().hex,
                "fingerprint": "new-fingerprint",
                "expires_at": expires,
            }

        def get_ca_cert_pem(self):
            return "ca-certificate"

    monkeypatch.setattr(agents_router, "get_pki_manager", lambda db: Signer())
    result = await agents_router.register_agent(
        {"hostname": agent.hostname},
        _registration_request(),
        api_key=secret,
        db=db_session,
    )
    db_session.expire_all()

    assert key.use_count == 1
    assert agent.api_key_hash == hash_api_key(result["api_key"])
    assert agent.cert_fingerprint == "new-fingerprint"
    assert old.status == "revoked"
    assert _verify_agent_cert(old.fingerprint, db_session) is None
    assert _verify_agent_cert("new-fingerprint", db_session).id == agent.id


@pytest.mark.asyncio
async def test_registration_without_ca_keeps_api_key_mode(db_session, monkeypatch):
    key, secret = _registration_key(db_session, "key-only-agent")
    monkeypatch.setattr(agents_router, "is_ca_initialized", lambda db: False)
    monkeypatch.setattr(agents_router, "REQUIRE_MTLS", False)

    result = await agents_router.register_agent(
        {"hostname": "key-only-agent"},
        _registration_request(),
        api_key=secret,
        db=db_session,
    )
    db_session.expire_all()

    agent = db_session.get(Agent, result["agent_id"])
    assert key.use_count == 1
    assert agent.api_key_hash == hash_api_key(result["api_key"])
    assert agent.cert_fingerprint is None
    assert result["tls"] is None


@pytest.mark.asyncio
async def test_strict_registration_without_ca_does_not_spend_key_or_create_agent(
    db_session, monkeypatch
):
    key, secret = _registration_key(db_session, "strict-agent")
    monkeypatch.setattr(agents_router, "is_ca_initialized", lambda db: False)
    monkeypatch.setattr(agents_router, "REQUIRE_MTLS", True)

    with pytest.raises(HTTPException) as error:
        await agents_router.register_agent(
            {"hostname": "strict-agent"},
            _registration_request(),
            api_key=secret,
            db=db_session,
        )
    db_session.expire_all()

    assert error.value.status_code == 503
    assert key.use_count == 0
    assert db_session.query(Agent).filter_by(hostname="strict-agent").count() == 0
