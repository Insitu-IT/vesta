"""Real TLS transport produces identity; certificate-like headers cannot."""

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
import socket
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import uvicorn

from core.callback_identity import authenticate_callback
from core.verified_tls import verified_peer
from database import get_db
from deps import hash_api_key, verify_agent_api_key
from models import AgentCertificate, Organization
from server import configuration
from .conftest import make_agent


def certificates(tmp_path, rotated=False):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test callback CA")])

    def builder(name, key):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
        )

    ca = (
        builder(issuer, ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(name, usage):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            builder(subject, key)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_path, key_path = tmp_path / (name + ".pem"), tmp_path / (name + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return (
            str(cert_path),
            str(key_path),
            hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        )

    result = (
        str(ca_path),
        leaf("server", ExtendedKeyUsageOID.SERVER_AUTH),
        leaf("agent", ExtendedKeyUsageOID.CLIENT_AUTH),
    )
    if rotated:
        return (*result, leaf("agent-rotated", ExtendedKeyUsageOID.CLIENT_AUTH))
    return result


@pytest.mark.parametrize(
    "env",
    [
        {"REQUIRE_MTLS": "true"},
        {"BACKEND_TLS_CERT_FILE": "cert"},
        {"BACKEND_TLS_CLIENT_CA_FILE": "ca"},
        {
            "REQUIRE_MTLS": "true",
            "BACKEND_TLS_CERT_FILE": "cert",
            "BACKEND_TLS_KEY_FILE": "key",
        },
    ],
)
def test_required_mtls_configuration_cannot_start_without_tls(env):
    with pytest.raises(RuntimeError):
        configuration(env)


def test_verified_tls_uses_real_peer_and_rejects_header_impersonation(
    tmp_path, monkeypatch
):
    ca, server_pair, agent_pair = certificates(tmp_path)

    async def app(scope, receive, send):
        body = json.dumps(dict(fingerprint=verified_peer(scope))).encode()
        await send(
            dict(
                type="http.response.start",
                status=200,
                headers=[(b"content-type", b"application/json")],
            )
        )
        await send(dict(type="http.response.body", body=body))

    opts = configuration(
        dict(
            REQUIRE_MTLS="true",
            BACKEND_TLS_CERT_FILE=server_pair[0],
            BACKEND_TLS_KEY_FILE=server_pair[1],
            BACKEND_TLS_CLIENT_CA_FILE=ca,
        )
    )
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_level="error", **opts)
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    listener.setblocking(False)
    url = f"https://127.0.0.1:{listener.getsockname()[1]}"
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [listener]}, daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        with httpx.Client(verify=ca, cert=agent_pair[:2], trust_env=False) as client:
            response = client.get(url, headers={"X-Client-Cert-Fingerprint": "f" * 64})
            assert response.json() == dict(fingerprint=agent_pair[2])
        with httpx.Client(verify=ca, trust_env=False) as client:
            response = client.get(
                url,
                headers={
                    "X-Client-Cert-Fingerprint": agent_pair[2],
                    "X-Forwarded-Proto": "https",
                },
            )
            assert response.json() == dict(fingerprint=None)
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        _, _, untrusted_agent = certificates(foreign)
        with httpx.Client(
            verify=ca, cert=untrusted_agent[:2], trust_env=False
        ) as client:
            with pytest.raises(httpx.TransportError):
                client.get(url, headers={"X-Client-Cert-Fingerprint": agent_pair[2]})
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
    assert not thread.is_alive()
    monkeypatch.setattr("deps.REQUIRE_MTLS", True)
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-client-cert-fingerprint", agent_pair[2].encode())],
            "vnbui.verified_tls_peer": {"fingerprint": agent_pair[2]},
        }
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(authenticate_callback("valid-looking-api-key", request))
    assert error.value.status_code == 401

    async def ordinary_agent_auth():
        async for _ in verify_agent_api_key("valid-looking-api-key", request, None):
            raise AssertionError("caller header became TLS identity")

    with pytest.raises(HTTPException) as error:
        asyncio.run(ordinary_agent_auth())
    assert error.value.status_code == 401


@pytest.mark.parametrize("require_mtls", [False, True])
@pytest.mark.parametrize("duplicate_header", [False, True])
def test_active_certificate_header_cannot_authenticate_any_agent_route(
    tmp_path,
    monkeypatch,
    db_session,
    patch_session_local,
    require_mtls,
    duplicate_header,
):
    """An enrolled fingerprint is not authority without a verified TLS peer.

    Discover mounted consumers so a new route using either agent dependency is
    included automatically. The separate socket test above covers the real
    TLS adapter; TestClient deliberately supplies no TLS peer here.
    """
    from routers import agents, health, pki

    _, _, agent_pair = certificates(tmp_path)
    key = "fixture-agent-api-key"
    agent = make_agent(db_session, api_key_hash=hash_api_key(key))
    db_session.add(
        AgentCertificate(
            agent_id=agent.id,
            serial_number="fixture-serial",
            fingerprint=agent_pair[2],
            common_name=agent.hostname,
            expires_at=datetime.utcnow() + timedelta(days=1),
            status="active",
        )
    )
    db_session.commit()
    assert (
        db_session.query(AgentCertificate)
        .filter_by(fingerprint=agent_pair[2], status="active")
        .count()
        == 1
    )

    monkeypatch.setattr("deps.REQUIRE_MTLS", require_mtls)
    app = FastAPI()
    for router in (agents.router, health.router, pki.router):
        app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db_session
    # FastAPI 0.139 exposes included routers as wrappers in app.routes;
    # inspect the source routers for the actual APIRoutes.
    protected = [
        route
        for router in (agents.router, health.router, pki.router)
        for route in router.routes
        if isinstance(route, APIRoute)
        and any(
            dependency.call in (authenticate_callback, verify_agent_api_key)
            for dependency in route.dependant.dependencies
        )
    ]
    assert len(protected) == 17
    assert any(
        route.path == "/api/v1/agents/backups/{backup_id}/native-fenced-failure"
        and route.methods == {"POST"}
        for route in protected
    )
    assert any(
        route.path == "/api/v1/agents/backups/{backup_id}/native-no-effect"
        and route.methods == {"POST"}
        for route in protected
    )

    headers = [("X-Client-Cert-Fingerprint", agent_pair[2])]
    if duplicate_header:
        headers *= 2
    headers.append(("X-Forwarded-Proto", "https"))
    with TestClient(app) as client:
        for route in protected:
            method = next(iter(route.methods))
            path = re.sub(r"\{[^/]+\}", agent.id, route.path)
            kwargs = {"json": {}} if method == "POST" else {}
            response = client.request(method, path, headers=headers, **kwargs)
            assert response.status_code == 401, (method, route.path, response.text)

        # API-key mode remains key-authenticated; a header cannot take priority.
        response = client.get(
            f"/api/v1/agents/{agent.id}/pending-jobs",
            headers={"X-Agent-Key": key},
        )
        assert response.status_code == (401 if require_mtls else 200)


def test_real_tls_agent_route_enforces_certificate_lifecycle(
    tmp_path, monkeypatch, db_session, patch_session_local
):
    """Exercise the actual TLS peer, not a fabricated request scope or header.

    Database expiry/revocation and agent ownership are tested after the socket
    has verified each client certificate. This is still a unit DB, not the
    deployed PostgreSQL/route acceptance required to close issue #81.
    """
    from routers import agents, health, pki

    ca, server_pair, agent_pair, rotated_pair = certificates(tmp_path, rotated=True)
    agent = make_agent(db_session, cert_fingerprint=agent_pair[2], mtls_enabled=True)
    cert = AgentCertificate(
        agent_id=agent.id,
        serial_number="initial-serial",
        fingerprint=agent_pair[2],
        common_name=agent.hostname,
        expires_at=datetime.utcnow() + timedelta(days=1),
        status="active",
    )
    other_org = Organization(name="other certificate-test tenant")
    db_session.add_all([cert, other_org])
    db_session.flush()
    other_agent = make_agent(db_session, org_id=other_org.id)
    db_session.commit()

    monkeypatch.setattr("deps.REQUIRE_MTLS", True)
    app = FastAPI()
    for router in (agents.router, health.router, pki.router):
        app.include_router(router)
    protected = [
        route
        for router in (agents.router, health.router, pki.router)
        for route in router.routes
        if isinstance(route, APIRoute)
        and any(
            dependency.call in (authenticate_callback, verify_agent_api_key)
            for dependency in route.dependant.dependencies
        )
    ]
    assert len(protected) == 17
    assert any(
        route.path == "/api/v1/agents/backups/{backup_id}/native-fenced-failure"
        and route.methods == {"POST"}
        for route in protected
    )
    assert any(
        route.path == "/api/v1/agents/backups/{backup_id}/native-no-effect"
        and route.methods == {"POST"}
        for route in protected
    )

    def assert_all_routes_reject(client, base_url):
        for route in protected:
            method = next(iter(route.methods))
            route_path = re.sub(r"\{[^/]+\}", agent.id, route.path)
            kwargs = {"json": {}} if method == "POST" else {}
            response = client.request(method, base_url + route_path, **kwargs)
            assert response.status_code == 401, (method, route.path, response.text)

    opts = configuration(
        dict(
            REQUIRE_MTLS="true",
            BACKEND_TLS_CERT_FILE=server_pair[0],
            BACKEND_TLS_KEY_FILE=server_pair[1],
            BACKEND_TLS_CLIENT_CA_FILE=ca,
        )
    )
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_level="error", **opts)
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    listener.setblocking(False)
    url = f"https://127.0.0.1:{listener.getsockname()[1]}"
    path = f"/api/v1/agents/{agent.id}/pending-jobs"
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [listener]}, daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        with httpx.Client(verify=ca, cert=agent_pair[:2], trust_env=False) as client:
            assert client.get(url + path).json() == {"backups": []}
            assert (
                client.get(
                    url + f"/api/v1/agents/{other_agent.id}/pending-jobs"
                ).status_code
                == 403
            )
            cert.status = "revoked"
            db_session.commit()
            assert_all_routes_reject(client, url)

            cert.status = "active"
            cert.expires_at = datetime.utcnow() - timedelta(seconds=1)
            db_session.commit()
            assert_all_routes_reject(client, url)

            cert.expires_at = datetime.utcnow() + timedelta(days=1)
            agent.cert_fingerprint = rotated_pair[2]
            db_session.add(
                AgentCertificate(
                    agent_id=agent.id,
                    serial_number="rotated-serial",
                    fingerprint=rotated_pair[2],
                    common_name=agent.hostname,
                    expires_at=datetime.utcnow() + timedelta(days=1),
                    status="active",
                )
            )
            db_session.commit()
            assert_all_routes_reject(client, url)
        with httpx.Client(verify=ca, cert=rotated_pair[:2], trust_env=False) as client:
            assert client.get(url + path).json() == {"backups": []}
        with httpx.Client(verify=ca, trust_env=False) as client:
            assert (
                client.get(
                    url + path,
                    headers={"X-Client-Cert-Fingerprint": rotated_pair[2]},
                ).status_code
                == 401
            )
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
    assert not thread.is_alive()
