"""Independent SigV4 oracle and bounded response controls; no provider access."""

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from botocore.auth import S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import pytest

from core.storage_signing import sign, xml_fields, TTL


@pytest.mark.parametrize(
    "method,query,headers",
    [
        (
            "POST",
            {"uploads": ""},
            {"x-amz-meta-vnbui-org-id": "org", "x-amz-checksum-algorithm": "SHA256"},
        ),
        (
            "PUT",
            {"uploadId": "opaque+/=", "partNumber": "1"},
            {
                "content-length": "0",
                "x-amz-content-sha256": "a" * 64,
                "x-amz-checksum-sha256": "fixture",
            },
        ),
        (
            "POST",
            {"uploadId": "opaque"},
            {
                "if-none-match": "*",
                "content-length": "128",
                "x-amz-content-sha256": "b" * 64,
            },
        ),
        (
            "HEAD",
            {"versionId": "opaque+/="},
            {"if-match": '"opaque"', "x-amz-checksum-mode": "ENABLED"},
        ),
    ],
)
def test_finite_signatures_equal_independent_botocore(
    method, query, headers, monkeypatch, caplog
):
    now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
    target = dict(
        endpoint="https://storage.example", bucket="fixture", region="eu-central"
    )
    # Non-production published-style example credentials; never a live principal.
    ours = sign(
        target,
        "owned/attempt/artifact",
        method,
        query,
        headers,
        "EXAMPLE",
        "example-signing-material",
        now=now,
    )
    reference = AWSRequest(
        method=method,
        url="https://storage.example/fixture/owned/attempt/artifact",
        params=query,
        headers=headers,
    )
    oracle = S3SigV4QueryAuth(
        Credentials("EXAMPLE", "example-signing-material"),
        "s3",
        "eu-central",
        expires=TTL,
    )
    reference.context["timestamp"] = now.strftime("%Y%m%dT%H%M%SZ")
    oracle._modify_request_before_signing(reference)
    canonical = oracle.canonical_request(reference)
    signature = oracle.signature(oracle.string_to_sign(reference, canonical), reference)
    oracle._inject_signature_to_request(reference, signature)
    assert parse_qs(urlsplit(ours["url"]).query) == parse_qs(
        urlsplit(reference.url).query
    )
    assert ours["expires_at"] == int(now.timestamp()) + 60
    assert "example-signing-material" not in str(ours) + caplog.text


@pytest.mark.parametrize(
    "data",
    [
        b"<Error><Code>PRIVATE</Code></Error>",
        b"<!DOCTYPE x><Result/>",
        b"<Result><Id>a</Id><Id>b</Id></Result>",
        b"<Result><Nested><Id>a</Id></Nested></Result>",
        b"x" * (1024 * 1024 + 1),
    ],
)
def test_control_xml_refuses_ambiguous_or_unbounded_response(data):
    with pytest.raises(Exception):
        xml_fields(data, "Result")


@pytest.mark.parametrize("remaining", [1, 7, 60, 600])
def test_evidence_bounded_signature_matches_independent_oracle(remaining, monkeypatch):
    from core.storage_signing import SigningWindow

    now = datetime(2026, 9, 28, 12, 0, 0, 123456, tzinfo=timezone.utc)
    monkeypatch.setattr("core.storage_signing.time.monotonic", lambda: 100.25)
    window = SigningWindow(
        "owned-evidence", "a" * 64, now, int(now.timestamp()) + remaining, 100
    )
    ours = sign(
        dict(endpoint="https://storage.example", bucket="fixture", region="eu-central"),
        "owned/part",
        "PUT",
        {"uploadId": "exact", "partNumber": "1"},
        {"x-amz-content-sha256": "a" * 64},
        "EXAMPLE",
        "example-signing-material",
        signing_window=window,
    )
    reference = AWSRequest(
        method="PUT",
        url="https://storage.example/fixture/owned/part",
        params={"uploadId": "exact", "partNumber": "1"},
        headers={"x-amz-content-sha256": "a" * 64},
    )
    oracle = S3SigV4QueryAuth(
        Credentials("EXAMPLE", "example-signing-material"),
        "s3",
        "eu-central",
        expires=min(TTL, remaining),
    )
    reference.context["timestamp"] = now.strftime("%Y%m%dT%H%M%SZ")
    oracle._modify_request_before_signing(reference)
    canonical = oracle.canonical_request(reference)
    oracle._inject_signature_to_request(
        reference,
        oracle.signature(oracle.string_to_sign(reference, canonical), reference),
    )
    assert parse_qs(urlsplit(ours["url"]).query) == parse_qs(
        urlsplit(reference.url).query
    )
    assert ours["expires_at"] == int(now.timestamp()) + min(TTL, remaining)
    assert ours["expires_at"] <= window.not_after


@pytest.mark.parametrize(
    "remaining,elapsed",
    [(0, 0), (-1, 0), (1, 0.5), (10, 9.5), (600, 59.5), (10, -0.01)],
)
def test_elapsed_creator_cannot_mint_expired_signature(remaining, elapsed, monkeypatch):
    from core.storage_signing import SigningWindow
    from core.s3_ownership import StorageOwnershipError

    now = datetime(2026, 9, 28, 12, 0, 0, 500000, tzinfo=timezone.utc)
    monkeypatch.setattr("core.storage_signing.time.monotonic", lambda: 100 + elapsed)
    window = SigningWindow(
        "owned-evidence", "a" * 64, now, int(now.timestamp()) + remaining, 100
    )
    with pytest.raises(StorageOwnershipError, match="window expired"):
        window.interval()


def test_database_session_timezone_is_normalized_to_sigv4_utc(monkeypatch):
    from datetime import timedelta
    from core.storage_signing import SigningWindow

    local = datetime(2026, 9, 28, 15, 0, tzinfo=timezone(timedelta(hours=3)))
    monkeypatch.setattr("core.storage_signing.time.monotonic", lambda: 100)
    window = SigningWindow(
        "evidence", "a" * 64, local, int(local.timestamp()) + 30, 100
    )
    result = sign(
        dict(endpoint="https://storage.example", bucket="fixture", region="r"),
        "part",
        "PUT",
        {},
        {},
        "EXAMPLE",
        "example-secret",
        signing_window=window,
    )
    query = parse_qs(urlsplit(result["url"]).query)
    assert query["X-Amz-Date"] == ["20260928T120000Z"]
    assert query["X-Amz-Expires"] == ["30"]
    assert result["expires_at"] == int(local.timestamp()) + 30
