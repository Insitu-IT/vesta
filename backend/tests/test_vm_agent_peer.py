"""Defensive checks of enrollment, operator-supplied overrides and raw TLS pinning."""

from dataclasses import replace
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import json
import ssl
from types import SimpleNamespace

import httpx
import pytest

from core.file_agent_http import FileAgentHTTP
from core.pki import PKIManager
from core.verified_tls import PEER_SCOPE, VerifiedPeer
from core.vm_agent_peer import AgentPeerUnavailable, vm_agent_peer
from models import AgentCertificate
from routers.health import agent_heartbeat
from version import __version__

from .conftest import make_agent


def enroll(db, *, fingerprint="a" * 64, hostname="enrolled.test"):
    agent = make_agent(
        db,
        hostname=hostname,
        cert_fingerprint=fingerprint,
        mtls_enabled=True,
        ip_address="127.0.0.1",
    )
    cert = AgentCertificate(
        agent_id=agent.id,
        serial_number=fingerprint[:10],
        fingerprint=fingerprint,
        common_name=hostname,
        expires_at=datetime.utcnow() + timedelta(days=1),
    )
    db.add(cert)
    db.commit()
    return agent, cert


def installed_binding(path, monkeypatch, agent, fingerprint="b" * 64):
    monkeypatch.setenv("VESTA_AGENT_SERVING_TRUST_FILE", str(path))
    doc = {
        "schema": "vesta-agent-serving-trust/1",
        "agents": [
            {
                "organization_id": agent.org_id,
                "agent_id": agent.id,
                "dns_name": "serving.test",
                "sha256": fingerprint,
            }
        ],
    }
    path.write_text(json.dumps(doc))
    path.chmod(0o644)
    return doc


@pytest.mark.parametrize("mutation", ["revoked", "inactive", "expired", "not-current"])
def test_expired_or_revoked_enrollment_refuses_even_installed_alternate(
    db_session, tmp_path, monkeypatch, mutation
):
    agent, cert = enroll(db_session)
    installed_binding(tmp_path / "approved.json", monkeypatch, agent)
    peer = vm_agent_peer(db_session, agent)
    assert peer.hostname == "serving.test" and peer.fingerprint == "b" * 64
    assert peer.enrollment_fingerprint == agent.cert_fingerprint
    if mutation == "revoked":
        cert.revoked_at = datetime.utcnow()
    elif mutation == "inactive":
        cert.status = "revoked"
    elif mutation == "expired":
        cert.expires_at = datetime.utcnow() - timedelta(seconds=1)
    else:
        agent.cert_fingerprint = "c" * 64
    db_session.commit()
    with pytest.raises(AgentPeerUnavailable, match="enrolled"):
        vm_agent_peer(db_session, agent)


def test_installed_binding_is_tenant_specific_and_invalid_file_never_falls_back(
    db_session, tmp_path, monkeypatch
):
    agent, _ = enroll(db_session)
    other, _ = enroll(db_session, fingerprint="c" * 64, hostname="other.test")
    default = vm_agent_peer(db_session, agent)
    assert (
        default.fingerprint == agent.cert_fingerprint
        and default.hostname == agent.hostname
    )
    path = tmp_path / "agent-serving-trust.json"
    doc = installed_binding(path, monkeypatch, other)
    assert vm_agent_peer(db_session, agent) == default
    doc["agents"].append(dict(doc["agents"][0]))
    path.write_text(json.dumps(doc))
    with pytest.raises(AgentPeerUnavailable, match="trust"):
        vm_agent_peer(db_session, agent)


@pytest.mark.parametrize("address", ["ctrl01", "agent.ns.svc", "2001:db8::1"])
def test_vm_peer_keeps_literal_addresses_with_independent_dns_identity(
    db_session, address
):
    agent, _ = enroll(db_session)
    agent.ip_address = address
    peer = vm_agent_peer(db_session, agent)
    assert peer.address == address
    assert peer.hostname == agent.hostname and peer.port == 8090


@pytest.mark.parametrize(
    "address",
    [
        "user@other",
        "https://other",
        "host/path",
        "host:443",
        "host\nother",
        "-bad",
        "bad.",
    ],
)
def test_vm_peer_refuses_paths_and_url_authority_in_reported_address(
    db_session, address
):
    agent, _ = enroll(db_session)
    agent.ip_address = address
    with pytest.raises(AgentPeerUnavailable, match="address"):
        vm_agent_peer(db_session, agent)


@pytest.mark.asyncio
async def test_distinct_serving_leaf_is_verified_before_version_and_mutation(
    db_session, tmp_path, monkeypatch
):
    ca, key = PKIManager.initialize_ca()
    pki = PKIManager(ca, key)
    enrolled = pki.issue_agent_cert("enrolled.test")
    approved = pki.issue_agent_cert("serving.test")
    different = pki.issue_agent_cert("serving.test")
    controller = pki.issue_backend_cert()
    agent, cert = enroll(db_session, fingerprint=enrolled["fingerprint"])
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca)

    def save(name, pair):
        cert_path, key_path = tmp_path / f"{name}.pem", tmp_path / f"{name}.key"
        cert_path.write_text(pair["cert_pem"])
        key_path.write_text(pair["key_pem"])
        return str(cert_path), str(key_path)

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.command, self.path, self.headers["X-Vesta-Agent-ID"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"version": __version__}).encode())

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            seen.append((self.command, self.path, self.headers["X-Vesta-Agent-ID"]))
            self.send_response(202)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"{}")

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        agent.port = server.server_port
        db_session.commit()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*save("serving", approved))
        context.load_verify_locations(cafile=ca_path)
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = FileAgentHTTP(
                ca=str(ca_path), certificate=save("controller", controller)
            )
            headers = {"X-Orchestrator-Key": "synthetic", "X-Vesta-Agent-ID": agent.id}
            default = vm_agent_peer(db_session, agent)
            with pytest.raises(httpx.TransportError):
                await client.post(default, "/api/restores", headers=headers, json={})
            path = tmp_path / "approved.json"
            installed_binding(path, monkeypatch, agent, different["fingerprint"])
            with pytest.raises(httpx.TransportError):
                await client.post(
                    vm_agent_peer(db_session, agent),
                    "/api/restores",
                    headers=headers,
                    json={},
                )
            assert seen == []
            installed_binding(path, monkeypatch, agent, approved["fingerprint"])
            peer = vm_agent_peer(db_session, agent)
            response = await client.post(
                peer,
                "/api/restores",
                headers=headers,
                json={},
                params={"scope": "fixture"},
            )
            assert (
                response.status_code == 202
                and response.headers["cache-control"] == "no-store"
            )
            assert [(m, p) for m, p, _ in seen] == [
                ("GET", "/api/version"),
                ("POST", "/api/restores?scope=fixture"),
            ]
            assert all(actor == agent.id for _, _, actor in seen)
            seen.clear()

            async def revoke_after_probe():
                if seen:
                    cert.revoked_at = datetime.utcnow()
                    db_session.commit()
                if vm_agent_peer(db_session, agent) != peer:
                    raise AgentPeerUnavailable("Peer changed")

            with pytest.raises(AgentPeerUnavailable, match="enrolled"):
                await client.post(
                    peer,
                    "/api/verifications",
                    headers=headers,
                    json={"fixture": True},
                    recheck=revoke_after_probe,
                )
            assert [(m, p) for m, p, _ in seen] == [("GET", "/api/version")]
            with pytest.raises(httpx.TransportError):
                await client.post(
                    replace(peer, hostname="wrong.test"),
                    "/api/restores",
                    headers=headers,
                )
        finally:
            server.shutdown()
            thread.join()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["libvirt", "kubevirt", "none"])
@pytest.mark.parametrize("verified", [False, True])
async def test_heartbeat_never_reads_standing_s3_settings(
    db_session, monkeypatch, provider, verified
):
    agent, _ = enroll(db_session)
    agent.config = {"vm_controller_sha256": "agent-settings-value"}
    db_session.commit()

    def forbid(*args):
        pytest.fail("heartbeat reached standing storage credentials")

    monkeypatch.setattr("routers.health.SettingsService.get_s3_config", forbid)
    monkeypatch.setattr(
        "core.file_controller_identity.current_file_controller_fingerprint",
        lambda service: "f" * 64,
    )

    async def payload():
        return {"capabilities": {"provider": provider}}

    request = SimpleNamespace(
        json=payload,
        scope={PEER_SCOPE: VerifiedPeer(agent.cert_fingerprint)} if verified else {},
    )
    result = await agent_heartbeat(agent.id, request, agent, db_session)
    assert result["s3_config"] is None
    if provider in {"libvirt", "kubevirt"} and verified:
        assert result["config"]["vm_controller_sha256"] == "f" * 64
    else:
        assert "vm_controller_sha256" not in result["config"]
