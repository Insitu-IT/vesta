"""Directly address an enrolled agent and bind each TLS handshake to it."""

from dataclasses import dataclass
import hashlib
import hmac
from http.client import HTTPSConnection, HTTPException
import json
import socket
import ssl

import httpx

from core.agent_http import require_compatible_agent_version
from core.task_lifetime import run_owned_worker


@dataclass(frozen=True)
class AgentPeer:
    address: str
    port: int
    hostname: str
    fingerprint: str
    agent_id: str | None = None
    enrollment_fingerprint: str | None = None


class EnrolledConnection(HTTPSConnection):
    def __init__(self, peer, context):
        super().__init__(peer.hostname, peer.port, context=context, timeout=8)
        self.peer = peer
        self.context = context

    def connect(self):
        # Resolve/dial the authenticated heartbeat's address. TLS still uses
        # the enrollment hostname for SNI and verified certificate identity.
        network = socket.create_connection(
            (self.peer.address, self.peer.port), timeout=self.timeout
        )
        try:
            verified = self.context.wrap_socket(
                network, server_hostname=self.peer.hostname
            )
        except BaseException:
            network.close()
            raise
        certificate = verified.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(certificate or b"").hexdigest()
        if not certificate or not hmac.compare_digest(
            fingerprint, self.peer.fingerprint
        ):
            verified.close()
            raise ssl.SSLError("TLS peer is not the approved enrolled agent")
        # HTTPConnection sends nothing until connect returns with this socket.
        self.sock = verified


class FileAgentHTTP:
    MAX_RESPONSE_BYTES = 32768

    def __init__(self, *, ca, certificate, max_response_bytes=None):
        self.ca, self.certificate = ca, certificate
        self.max_response_bytes = max_response_bytes or self.MAX_RESPONSE_BYTES

    def _request(self, peer, method, path, headers, payload=None, params=None):
        request = httpx.Request(
            method,
            httpx.URL(scheme="https", host=peer.hostname, port=peer.port, path=path),
            params=params,
        )
        context = ssl.create_default_context(cafile=self.ca)
        context.load_cert_chain(*self.certificate)
        connection = EnrolledConnection(peer, context)
        body = json.dumps(payload).encode() if payload is not None else None
        if body is not None:
            headers = {**headers, "Content-Type": "application/json"}
        try:
            connection.request(
                method, request.url.raw_path.decode("ascii"), body=body, headers=headers
            )
            response = connection.getresponse()
            content = response.read(self.max_response_bytes + 1)
            if len(content) > self.max_response_bytes:
                raise RuntimeError("Enrolled agent response exceeded its size limit")
            return httpx.Response(
                response.status,
                headers=response.headers.items(),
                content=content,
                request=request,
            )
        except (OSError, HTTPException) as exc:
            raise httpx.TransportError(
                "Verified agent request failed", request=request
            ) from exc
        finally:
            connection.close()

    async def get(self, peer, path, *, headers, params=None):
        return await run_owned_worker(
            self._request, peer, "GET", path, headers, None, params
        )

    async def post(self, peer, path, *, headers, json=None, params=None, recheck=None):
        if recheck is not None:
            await recheck()
        probe = await self.get(peer, "/api/version", headers=headers)
        probe.raise_for_status()
        report = probe.json()
        require_compatible_agent_version(
            report.get("version") if isinstance(report, dict) else None
        )
        if recheck is not None:
            await recheck()
        return await run_owned_worker(
            self._request, peer, "POST", path, headers, json, params
        )

    async def aclose(self):
        """Each request owns and closes its connection."""
