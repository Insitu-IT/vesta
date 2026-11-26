"""Finite SigV4 primitives; no SDK credential discovery, redirects or retries.

Signed request material is memory-only. SigV4 necessarily exposes the public
access-key identifier in Credential, never the reusable signing secret.
"""

import hashlib
import hmac
import http.client
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlsplit, parse_qsl
from xml.etree import ElementTree

from core.s3_ownership import StorageOwnershipError

TTL = 60
MAX_RESPONSE = 1024 * 1024


@dataclass(frozen=True)
class SigningWindow:
    """Detached R1 DB clock and immutable evidence bound; never serialized.

    The monotonic sample precedes the DB clock query, conservatively charging
    query/commit/configuration latency against this one creator's interval.
    Expiry bounds request admission, not the last mutation of an admitted PUT.
    """

    evidence_id: str
    evidence_sha256: str
    admitted_at: datetime
    not_after: int
    monotonic_start: float

    def interval(self):
        start = int(self.admitted_at.timestamp())
        end = min(start + TTL, self.not_after)
        elapsed = time.monotonic() - self.monotonic_start
        if elapsed < 0 or self.admitted_at.timestamp() + elapsed >= end:
            raise StorageOwnershipError("Part signing window expired")
        return self.admitted_at.astimezone(timezone.utc), end - start


def sign(
    target,
    key,
    method,
    query,
    headers,
    access,
    secret,
    *,
    now=None,
    signing_window=None,
):
    duration = TTL
    if signing_window is not None:
        if now is not None or type(signing_window) is not SigningWindow:
            raise StorageOwnershipError("Part signing window invalid")
        now, duration = signing_window.interval()
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    date = stamp[:8]
    scope = f"{date}/{target['region']}/s3/aws4_request"
    origin = urlsplit(target["endpoint"])
    path = "/" + quote(target["bucket"], safe="") + "/" + quote(key, safe="/~")
    values = {k.lower(): str(v) for k, v in headers.items()}
    values["host"] = origin.netloc
    signed = ";".join(sorted(values))
    params = dict(
        query,
        **{
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": access + "/" + scope,
            "X-Amz-Date": stamp,
            "X-Amz-Expires": str(duration),
            "X-Amz-SignedHeaders": signed,
        },
    )
    canonical_query = urlencode(sorted(params.items()), quote_via=quote, safe="~")
    canonical_headers = "".join(
        k + ":" + " ".join(values[k].split()) + "\n" for k in sorted(values)
    )
    canonical = "\n".join(
        (
            method,
            path,
            canonical_query,
            canonical_headers,
            signed,
            values.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        )
    )
    string = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            stamp,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        )
    )
    signing = ("AWS4" + secret).encode()
    for item in (date, target["region"], "s3", "aws4_request"):
        signing = hmac.new(signing, item.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing, string.encode(), hashlib.sha256).hexdigest()
    return dict(
        method=method,
        url=target["endpoint"]
        + path
        + "?"
        + canonical_query
        + "&X-Amz-Signature="
        + signature,
        headers={k: v for k, v in values.items() if k != "host"},
        expires_at=int(now.timestamp()) + duration,
    )


def _call(authority, body, limit, observation=False):
    """One bounded HTTPS request. Never log URL/headers/body or SDK errors."""
    u = urlsplit(authority["url"])
    if u.scheme != "https" or u.username or u.fragment:
        raise StorageOwnershipError("Provider control unavailable")
    connection = http.client.HTTPSConnection(
        u.hostname,
        u.port,
        timeout=30,
        context=authority.get("_tls_context") or ssl.create_default_context(),
    )
    try:
        connection.request(
            authority["method"],
            u.path + "?" + u.query,
            body=body,
            headers={**authority["headers"], "Host": u.netloc},
        )
        response = connection.getresponse()
        data = response.read(limit + 1)
        if len(data) > limit or (not observation and response.status not in (200, 201)):
            raise StorageOwnershipError("Provider control unavailable")
        headers = {k.lower(): v for k, v in response.getheaders()}
        if sum(len(k) + len(v) for k, v in headers.items()) > 16384:
            raise StorageOwnershipError("Provider control unavailable")
        return (response.status, headers, data) if observation else (headers, data)
    finally:
        connection.close()


def control_call(authority, body=b""):
    return _call(authority, body, MAX_RESPONSE)


def observation_call(authority):
    """ListParts-only bounded GET; preserve status, never redirect or retry."""
    if authority["method"] != "GET":
        raise StorageOwnershipError("Observation requires GET")
    return _call(authority, b"", 2 * 1024 * 1024, observation=True)


def xml_fields(data, root):
    if b"<!" in data or len(data) > MAX_RESPONSE:
        raise StorageOwnershipError("Invalid provider response")
    element = ElementTree.fromstring(data)
    if element.tag.split("}")[-1] != root:
        raise StorageOwnershipError("Invalid provider response")
    result = {}
    for child in element:
        name = child.tag.split("}")[-1]
        if name in result or len(child):
            raise StorageOwnershipError("Invalid provider response")
        result[name] = child.text or ""
    return result


def signed_query(authority):
    """Non-secret operation view for deterministic tests, not persistence."""
    return {
        k: v
        for k, v in parse_qsl(urlsplit(authority["url"]).query)
        if not k.startswith("X-Amz-")
    }
