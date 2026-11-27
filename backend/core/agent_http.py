"""Loop-neutral agent transport configuration with request-owned connections.

Executors are process singletons used by the API loop and scheduler threads.
They may retain this configuration, never an AsyncClient or its connection pool.
Each eager request creates and closes its transport on the calling loop, including
on cancellation/error. Responses have been fully read before the client closes.
"""

import re

import httpx
from version import check_compatibility


def require_compatible_agent_version(version):
    if (
        not isinstance(version, str)
        or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
        is None
        or not check_compatibility(version)["compatible"]
    ):
        raise RuntimeError("Agent major version mismatch; coordinated upgrade required")


class AgentHTTP:
    def __init__(self, **configuration):
        self._configuration = dict(configuration)

    async def request(self, method, url, **kwargs):
        async with httpx.AsyncClient(**self._configuration) as client:
            if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                # Probe the selected agent, not cached heartbeat configuration.
                # No mutation is sent if version evidence is absent or incompatible.
                # Ordinary callers can probe the public version without sending
                # a bearer key. Certified dispatch has its own peer-bound probe.
                probe = await client.get(
                    str(httpx.URL(url).copy_with(path="/health", query=None)),
                )
                probe.raise_for_status()
                version = probe.json().get("version")
                require_compatible_agent_version(version)
            return await client.request(method, url, **kwargs)

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def delete(self, url, **kwargs):
        return await self.request("DELETE", url, **kwargs)

    async def aclose(self):
        """No shared pool exists; each request owns and closes its transport."""
