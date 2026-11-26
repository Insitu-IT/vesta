"""A real HTTP server exercises shared executor configuration across closed loops."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import ssl

import httpx
import pytest

from core.agent_http import AgentHTTP


@pytest.fixture
def agent_server():
    connections = []
    started, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            connections.append(self.connection)

        def do_GET(self):
            if self.path == "/disconnect":
                self.close_connection = True
                return
            if self.path == "/slow":
                started.set()
                release.wait(5)
                self.close_connection = True
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", connections, started, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()


def test_transport_lifetime_across_repeated_and_concurrent_loops(agent_server):
    url, connections, _, _ = agent_server
    # Created outside any loop, as at module import/startup. The same facade is
    # used first by an API-shaped loop and then repeated scheduler invocations.
    transport = AgentHTTP(timeout=2, trust_env=False)

    async def invoke():
        response = await transport.get(url)
        assert response.text == "ok"
        assert response.is_closed

    for _ in range(3):
        asyncio.run(invoke())
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(asyncio.run, invoke()) for _ in range(2)]
        for future in futures:
            future.result()
    assert len(connections) == 5  # No pooled connection escaped its owning loop.
    asyncio.run(transport.aclose())


def test_transport_error_does_not_poison_next_loop(agent_server):
    url, _, _, _ = agent_server
    transport = AgentHTTP(timeout=2, trust_env=False)
    with pytest.raises(httpx.RemoteProtocolError):
        asyncio.run(transport.get(url + "/disconnect"))
    assert asyncio.run(transport.get(url)).text == "ok"


def test_cancellation_does_not_leave_a_transport_on_the_closed_loop(agent_server):
    url, _, started, release = agent_server
    transport = AgentHTTP(timeout=2, trust_env=False)

    async def cancel_request():
        task = asyncio.create_task(transport.get(url + "/slow"))
        try:
            assert await asyncio.to_thread(started.wait, 2)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            release.set()

    asyncio.run(cancel_request())
    assert asyncio.run(transport.get(url)).text == "ok"


def test_both_global_executors_use_loop_neutral_transport():
    from core.backup_executor import backup_executor
    from core.restore_executor import restore_executor

    assert isinstance(backup_executor.http_client, AgentHTTP)
    assert isinstance(restore_executor.http_client, AgentHTTP)


@pytest.mark.parametrize("executor_name", ["backup", "restore"])
def test_executors_verify_site_server_ca_separately_from_client_ca(
    tmp_path, monkeypatch, executor_name
):
    """Exercise real mTLS with different serving and client-identity issuers."""
    from .test_verified_callback_tls import certificates
    from core.backup_executor import BackupExecutor
    from core.restore_executor import RestoreExecutor

    serving, enrolled = tmp_path / "serving", tmp_path / "enrolled"
    serving.mkdir()
    enrolled.mkdir()
    server_ca, server_pair, _ = certificates(serving)
    client_ca, _, client_pair = certificates(enrolled)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*server_pair[:2])
    context.load_verify_locations(cafile=client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("AGENT_CA_CERT", server_ca)
    monkeypatch.setenv("BACKEND_TLS_CLIENT_CA_FILE", client_ca)
    monkeypatch.setenv("ORCHESTRATOR_CLIENT_CERT", client_pair[0])
    monkeypatch.setenv("ORCHESTRATOR_CLIENT_KEY", client_pair[1])
    monkeypatch.setenv("AGENT_TLS_ENABLED", "true")
    factory = BackupExecutor if executor_name == "backup" else RestoreExecutor
    executor = factory()
    transport = executor.http_client
    assert executor.agent_tls_enabled
    assert transport._configuration["verify"] == server_ca
    try:
        assert asyncio.run(transport.get(url)).text == "ok"
        # Reproduces the manual lab override: enrolled client CA cannot verify
        # the independently site-issued agent serving certificate.
        wrong_trust = AgentHTTP(verify=client_ca, cert=client_pair[:2], timeout=2)
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            asyncio.run(wrong_trust.get(url))
        # A trusted issuer alone must not bypass the advertised-name check.
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            asyncio.run(transport.get(url.replace("127.0.0.1", "localhost")))
        assert asyncio.run(transport.get(url)).text == "ok"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()
