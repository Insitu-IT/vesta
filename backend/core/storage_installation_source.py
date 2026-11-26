"""Unmounted named-Secret resolver. No installer, enrollment or provider activation.

The protected boot interface supplies API trust and source identity. Every request
reads the projected token anew. Kubernetes deletion is not a database fence.
"""

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
from threading import Lock
from urllib.parse import urlsplit
import uuid

from core.s3_ownership import StorageOwnershipError

MAX_RESPONSE = 1024 * 1024
TIMEOUT = 10
SOURCE_FIELDS = frozenset(
    {
        "kind",
        "api_origin",
        "api_ca_sha256",
        "namespace",
        "name",
        "uid",
        "immutable",
        "access_key",
        "secret_key",
        "trust_key",
    }
)
_boot = ContextVar("storage_installation_boot", default=None)
_process_pid = os.getpid()
_process_binding = None
_process_binding_lock = Lock()


def refuse():
    raise StorageOwnershipError("Installation source unavailable") from None


def validate_source(source):
    if type(source) is not dict or set(source) != SOURCE_FIELDS:
        refuse()
    if (
        source["kind"] != "kubernetes_immutable_secret"
        or source["immutable"] is not True
    ):
        refuse()
    for key in SOURCE_FIELDS - {"immutable"}:
        if type(source[key]) is not str or not source[key] or len(source[key]) > 2048:
            refuse()
    if not re.fullmatch(r"[0-9a-f]{64}", source["api_ca_sha256"]):
        refuse()
    for key in ("namespace", "name"):
        if len(source[key]) > (63 if key == "namespace" else 253) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", source[key]
        ):
            refuse()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", source["uid"]):
        refuse()
    names = [source[k] for k in ("access_key", "secret_key", "trust_key")]
    if len(set(names)) != 3 or any(
        not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", n) for n in names
    ):
        refuse()
    if not re.fullmatch(
        r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", source["api_origin"]
    ):
        refuse()
    try:
        url = urlsplit(source["api_origin"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
            or not 0 < (url.port or 443) < 65536
        ):
            refuse()
    except ValueError:
        refuse()
    return source


@dataclass(frozen=True, repr=False)
class BootBinding:
    installation_id: str
    generation_id: str
    source_json: str
    token_path: str
    api_ca_path: str
    boot_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def source(self):
        try:
            return validate_source(json.loads(self.source_json))
        except (ValueError, TypeError):
            refuse()


@contextmanager
def bound_process(boot):
    """Internal boot-scoped entrypoint; never supplied from an HTTP request."""
    global _process_binding
    if (
        os.getpid() != _process_pid
        or type(boot) is not BootBinding
        or _boot.get() is not None
    ):
        refuse()
    boot.source()
    with _process_binding_lock:
        if _process_binding is None:
            _process_binding = boot
        elif _process_binding != boot:
            refuse()
    token = _boot.set(boot)
    try:
        yield
    finally:
        _boot.reset(token)


def require_boot(descriptor):
    boot = _boot.get()
    if (
        type(boot) is not BootBinding
        or os.getpid() != _process_pid
        or boot != _process_binding
        or boot.installation_id != descriptor["installation_id"]
        or boot.generation_id != descriptor["id"]
        or boot.source() != descriptor["source"]
    ):
        refuse()
    return boot


@dataclass(frozen=True, repr=False)
class SourceMaterial:
    boot_id: str
    generation_id: str
    uid: str
    resource_version: str
    key_names: tuple[str, str, str]
    access: str
    secret: str
    trust_pem: str

    def receipt(self):
        return dict(
            boot_id=self.boot_id,
            generation_id=self.generation_id,
            uid=self.uid,
            resource_version=self.resource_version,
            source_kind="kubernetes_immutable_secret",
            key_names=dict(
                zip(("access_key", "secret_key", "trust_key"), self.key_names)
            ),
        )


def _read(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        refuse()
    return raw


def _object(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            refuse()
        value[k] = v
    return value


def resolve(descriptor):
    """No DB access. One authenticated GET binds UID and all material atomically.

    No redirects, retries, ambient proxy/trust, or credential fallback. Errors
    deliberately omit server bodies, request URLs and bootstrap/secret material.
    """
    boot = require_boot(descriptor)
    source = boot.source()
    conn = None
    try:
        ca = _read(boot.api_ca_path, MAX_RESPONSE)
        if hashlib.sha256(ca).hexdigest() != source["api_ca_sha256"]:
            refuse()
        token = _read(boot.token_path, 16384).decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
            refuse()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ca.decode("ascii"))
        url = urlsplit(source["api_origin"])
        conn = http.client.HTTPSConnection(
            url.hostname, url.port or 443, timeout=TIMEOUT, context=context
        )
        path = (
            "/api/v1/namespaces/" + source["namespace"] + "/secrets/" + source["name"]
        )
        conn.request(
            "GET",
            path,
            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        )
        response = conn.getresponse()
        if response.status != 200:
            refuse()
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            refuse()
        obj = json.loads(raw, object_pairs_hook=_object)
        meta = obj["metadata"]
        if (
            obj.get("kind") != "Secret"
            or obj.get("apiVersion") != "v1"
            or obj.get("immutable") is not True
            or meta["name"] != source["name"]
            or meta["namespace"] != source["namespace"]
            or meta["uid"] != source["uid"]
            or meta.get("deletionTimestamp") is not None
            or type(meta["resourceVersion"]) is not str
            or not 0 < len(meta["resourceVersion"]) <= 256
        ):
            refuse()
        data = obj["data"]
        values = []
        for name in ("access_key", "secret_key", "trust_key"):
            value = base64.b64decode(data[source[name]], validate=True).decode("utf-8")
            if not value or "\x00" in value:
                refuse()
            values.append(value)
        access, secret, pem = values
        if len(access) > 4096 or len(secret) > 16384:
            refuse()
        if hashlib.sha256(pem.encode()).hexdigest() != descriptor["trust_sha256"]:
            refuse()
        provider_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        provider_context.load_verify_locations(cadata=pem)
        return SourceMaterial(
            boot.boot_id,
            boot.generation_id,
            meta["uid"],
            meta["resourceVersion"],
            tuple(source[k] for k in ("access_key", "secret_key", "trust_key")),
            access,
            secret,
            pem,
        )
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        refuse()
    finally:
        if conn is not None:
            conn.close()


def admit_resolved(db, request, key, identity, operation):
    """Fresh original authority after source IO, before using the material."""
    from core.callback_provider_create import _admit
    from core.storage_capability_evidence import require_evidence

    if identity is None or operation not in {
        "create",
        "part_sign",
        "complete",
        "head",
        "list_parts",
    }:
        refuse()
    binding = dict(
        reservation_id=request["reservation_id"],
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        key_ref=request["plan"]["encryption"]["key_ref"],
    )
    try:
        _, current, _, _ = _admit(db, identity, request["backup_id"], binding, key)
        if current != request:
            refuse()
        require_evidence(db, current, operation)
        db.commit()
    except Exception:
        db.rollback()
        raise
