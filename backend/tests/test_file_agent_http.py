"""Enrolled TLS binding protects preflight and file request bytes."""

from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import ssl

import httpx
import pytest

from core.file_agent_http import AgentPeer, FileAgentHTTP
from core.pki import PKIManager
from version import __version__


@pytest.mark.asyncio
async def test_enrolled_dns_and_leaf_before_preflight_or_request(tmp_path):
    hostname = "file-agent.test.invalid"
    ca, ca_key = PKIManager.initialize_ca()
    pki = PKIManager(ca, ca_key)
    expected = pki.issue_agent_cert(hostname)
    other = pki.issue_agent_cert(hostname)
    backend = pki.issue_backend_cert()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca)

    def save(label, pair):
        cert, key = (tmp_path / f"{label}.pem", tmp_path / f"{label}.key")
        cert.write_text(pair["cert_pem"])
        key.write_text(pair["key_pem"])
        return str(cert), str(key)

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, data):
            seen.append(
                (self.command, self.path, self.headers.get("X-Orchestrator-Key"))
            )
            self.send_response(status)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.reply(200, ('{"version":"' + __version__ + '"}').encode())

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.reply(202, b"{}")

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(*save("server", expected))
        server_context.load_verify_locations(cafile=ca_file)
        server_context.verify_mode = ssl.CERT_REQUIRED
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        serving = Thread(target=server.serve_forever, daemon=True)
        serving.start()
        try:
            transport = FileAgentHTTP(
                ca=str(ca_file), certificate=save("client", backend)
            )
            peer = AgentPeer(
                "127.0.0.1", server.server_port, hostname, expected["fingerprint"]
            )
            headers = {"X-Orchestrator-Key": "synthetic-key"}
            path = "/api/file-backups"
            for wrong in (
                replace(peer, fingerprint=other["fingerprint"]),
                replace(peer, hostname="different-agent.test.invalid"),
            ):
                with pytest.raises(httpx.TransportError):
                    await transport.post(wrong, path, headers=headers, json={})
            assert not seen
            assert (
                await transport.post(peer, path, headers=headers, json={})
            ).status_code == 202
            assert seen == [
                ("GET", "/api/version", "synthetic-key"),
                ("POST", path, "synthetic-key"),
            ]
        finally:
            server.shutdown()
            serving.join()
