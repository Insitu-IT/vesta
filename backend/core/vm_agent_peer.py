"""Resolve the explicitly authorized serving TLS identity for VM work."""

from datetime import datetime, timezone
import ipaddress
import json
import os
import re
import stat
from uuid import UUID

from core.file_agent_http import AgentPeer

TRUST_SCHEMA = "vesta-agent-serving-trust/1"
MAX_TRUST_BYTES = 64 * 1024
_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class AgentPeerUnavailable(RuntimeError):
    """No authorized agent transport can be selected."""


def valid_dns(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 253
        and all(_DNS_LABEL.fullmatch(label) for label in value.split("."))
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate trust field")
        result[key] = value
    return result


def _binding(path, org_id, agent_id):
    if path is None:
        return None
    try:
        # Projected ConfigMap volumes use symlinks for atomic replacement.
        # Open nonblocking and require a regular, bounded, operator-owned file.
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
                raise ValueError("Unsafe trust file")
            raw = stream.read(MAX_TRUST_BYTES + 1)
        if len(raw) > MAX_TRUST_BYTES:
            raise ValueError("Trust file too large")
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            type(manifest) is not dict
            or set(manifest) != {"schema", "agents"}
            or manifest["schema"] != TRUST_SCHEMA
            or type(manifest["agents"]) is not list
        ):
            raise ValueError("Invalid trust document")
        seen = set()
        match = None
        for row in manifest["agents"]:
            if type(row) is not dict or set(row) != {
                "organization_id",
                "agent_id",
                "dns_name",
                "sha256",
            }:
                raise ValueError("Invalid serving identity")
            for field in ("organization_id", "agent_id"):
                if str(UUID(row[field])) != row[field]:
                    raise ValueError("Noncanonical binding identity")
            key = row["organization_id"], row["agent_id"]
            if (
                key in seen
                or not valid_dns(row["dns_name"])
                or not isinstance(row["sha256"], str)
                or _SHA256.fullmatch(row["sha256"]) is None
            ):
                raise ValueError("Invalid or repeated serving identity")
            seen.add(key)
            if key == (org_id, agent_id):
                match = row["dns_name"], row["sha256"]
        return match
    except (AttributeError, OSError, TypeError, ValueError):
        raise AgentPeerUnavailable(
            "Installed agent serving trust is unavailable"
        ) from None


def vm_agent_peer(db, agent, *, now=None):
    from core.file_backups import certified_file_fingerprint

    fingerprint = certified_file_fingerprint(
        db, agent, now or datetime.now(timezone.utc)
    )
    port = agent.port if agent.port is not None else 8090
    if fingerprint is None or type(port) is not int or not 1 <= port <= 65535:
        raise AgentPeerUnavailable("Current enrolled agent transport is unavailable")
    if not valid_dns(agent.hostname):
        raise AgentPeerUnavailable("Enrolled agent DNS identity is unavailable")
    address = agent.ip_address or agent.hostname
    if not isinstance(address, str):
        raise AgentPeerUnavailable("Enrolled agent address is unavailable")
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        if not valid_dns(address):
            raise AgentPeerUnavailable(
                "Enrolled agent address is unavailable"
            ) from None
    dns_name, serving_fingerprint = _binding(
        os.environ.get("VESTA_AGENT_SERVING_TRUST_FILE"), agent.org_id, agent.id
    ) or (agent.hostname, fingerprint)
    return AgentPeer(
        address, port, dns_name, serving_fingerprint, agent.id, fingerprint
    )
