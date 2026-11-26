"""Strict wire parsing and observation-only tuple classifications."""

import base64
from copy import deepcopy
from xml.etree import ElementTree as ET
import pytest
from core.storage_listparts import parse_page, classify, MAX_RESPONSE
from core.s3_ownership import StorageOwnershipError


def page(numbers=(), marker=0, truncated=False, namespace=False):
    root = ET.Element("ListPartsResult")
    fields = dict(
        Bucket="b",
        Key="k",
        UploadId="u",
        PartNumberMarker=str(marker),
        MaxParts="1000",
        IsTruncated=str(truncated).lower(),
        ChecksumAlgorithm="SHA256",
        ChecksumType="COMPOSITE",
    )
    if truncated:
        fields["NextPartNumberMarker"] = str(numbers[-1])
    for key, value in fields.items():
        ET.SubElement(root, key).text = value
    for n in numbers:
        part = ET.SubElement(root, "Part")
        for key, value in dict(
            PartNumber=str(n),
            Size="100",
            ETag='"e"',
            ChecksumSHA256=base64.b64encode(b"a" * 32).decode(),
        ).items():
            ET.SubElement(part, key).text = value
    if namespace:
        for node in root.iter():
            node.tag = "{http://s3.amazonaws.com/doc/2006-03-01/}" + node.tag
    return ET.tostring(root)


@pytest.mark.parametrize("count", [0, 1, 1000, 1001, 10000])
@pytest.mark.parametrize("namespace", [False, True])
def test_complete_supported_pagination_range(count, namespace):
    seen = []
    marker = 0
    batches = [
        list(range(i, min(i + 1000, count + 1))) for i in range(1, count + 1, 1000)
    ] or [[]]
    for i, batch in enumerate(batches):
        parsed = parse_page(
            page(batch, marker, i < len(batches) - 1, namespace), "b", "k", "u", marker
        )
        seen.extend(p["number"] for p in parsed["parts"])
        if parsed["truncated"]:
            marker = parsed["next_marker"]
    assert seen == list(range(1, count + 1))
    assert not parsed["truncated"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.append(deepcopy(r.find("Bucket"))),
        lambda r: r.find("Bucket").__setattr__("text", "foreign"),
        lambda r: r.find("MaxParts").__setattr__("text", "999"),
        lambda r: r.find("PartNumberMarker").__setattr__("text", "1"),
        lambda r: r.find("IsTruncated").__setattr__("text", "TRUE"),
        lambda r: r.find("ChecksumType").__setattr__("text", "FULL_OBJECT"),
        lambda r: r.find("Part/PartNumber").__setattr__("text", "01"),
        lambda r: r.find("Part/Size").__setattr__("text", "-1"),
        lambda r: r.find("Part/ETag").__setattr__("text", "unquoted"),
        lambda r: r.find("Part/ChecksumSHA256").__setattr__("text", "YWJj"),
        lambda r: r.find("Part/ChecksumSHA256").__setattr__(
            "text", base64.b64encode(b"a" * 32).decode() + "\n"
        ),
        lambda r: r.append(deepcopy(r.find("Part"))),
        lambda r: r.find("Part").set("unexpected", "x"),
        lambda r: r.find("Key").set("unexpected", "x"),
        lambda r: r.remove(r.find("ChecksumAlgorithm")),
    ],
)
def test_one_invalid_field_with_valid_control(mutation):
    raw = page([1])
    assert parse_page(raw, "b", "k", "u", 0)["parts"][0]["number"] == 1
    root = ET.fromstring(raw)
    mutation(root)
    with pytest.raises(StorageOwnershipError, match="Invalid ListParts evidence"):
        parse_page(ET.tostring(root), "b", "k", "u", 0)


@pytest.mark.parametrize(
    "raw",
    [
        b"<!DOCTYPE x><ListPartsResult/>",
        b"x" * (MAX_RESPONSE + 1),
        b"<ListPartsResult>",
        b"\xff",
    ],
    ids=["dtd", "oversized", "truncated", "non-utf8"],
)
def test_malformed_or_oversized_refused(raw):
    with pytest.raises(StorageOwnershipError, match="Invalid ListParts evidence"):
        parse_page(raw, "b", "k", "u", 0)


def test_empty_truncated_and_repeated_marker_refused():
    root = ET.fromstring(page([1], truncated=True))
    root.remove(root.find("Part"))
    with pytest.raises(StorageOwnershipError):
        parse_page(ET.tostring(root), "b", "k", "u", 0)
    root = ET.fromstring(page([1], truncated=True))
    root.find("NextPartNumberMarker").text = "0"
    with pytest.raises(StorageOwnershipError):
        parse_page(ET.tostring(root), "b", "k", "u", 0)


def test_actual_reorder_and_overlapping_page_refused():
    root = ET.fromstring(page([1, 2]))
    parts = root.findall("Part")
    for p in parts:
        root.remove(p)
    for p in reversed(parts):
        root.append(p)
    with pytest.raises(StorageOwnershipError):
        parse_page(ET.tostring(root), "b", "k", "u", 0)
    with pytest.raises(StorageOwnershipError):
        parse_page(page([1], marker=1), "b", "k", "u", 1)


def test_1001_entries_in_one_page_refused():
    with pytest.raises(StorageOwnershipError):
        parse_page(page(range(1, 1002)), "b", "k", "u", 0)


def test_classifications_do_not_create_acknowledgments():
    observed = [
        dict(number=n, bytes=100, sha256="a" * 64, etag='"e"') for n in range(1, 5)
    ]
    local = {
        1: dict(bytes=100, sha256="a" * 64, acknowledgment=dict(etag="e")),
        2: dict(bytes=100, sha256="a" * 64, acknowledgment=None),
        3: dict(bytes=100, sha256="a" * 64, acknowledgment=dict(etag="other")),
    }
    before = deepcopy(local)
    assert [v["classification"] for v in classify(observed, local)] == [
        "committed_ack_match",
        "unacknowledged_intent_match",
        "conflict",
        "conflict",
    ]
    assert local == before


def test_utf16_declaration_cannot_bypass_entity_refusal():
    raw = '<?xml version="1.0" encoding="utf-16"?><!DOCTYPE x [<!ENTITY x "expanded">]><ListPartsResult/>'.encode(
        "utf-16"
    )
    with pytest.raises(StorageOwnershipError):
        parse_page(raw, "b", "k", "u", 0)


def test_listparts_transport_preserves_404_and_closes_without_retry(monkeypatch):
    from core import storage_signing

    calls = []

    class Response:
        status = 404

        def read(self, n):
            assert n == MAX_RESPONSE + 1
            return b"<Error><Code>NoSuchUpload</Code></Error>"

        def getheaders(self):
            return [("x-amz-request-id", "request")]

    class Connection:
        def __init__(self, *a, **kw):
            calls.append("connect")
            assert kw["timeout"] == 30

        def request(self, *a, **kw):
            calls.append("request")

        def getresponse(self):
            return Response()

        def close(self):
            calls.append("close")

    monkeypatch.setattr(storage_signing.http.client, "HTTPSConnection", Connection)
    response = storage_signing.observation_call(
        dict(method="GET", url="https://example.test/b/k?uploadId=u", headers={})
    )
    assert response[0] == 404 and response[1]["x-amz-request-id"] == "request"
    assert calls == ["connect", "request", "close"]


@pytest.mark.parametrize("status,length", [(302, 0), (200, MAX_RESPONSE + 1), (403, 0)])
def test_existing_control_transport_still_refuses_status_and_oversize(
    monkeypatch, status, length
):
    from core import storage_signing

    closed = []

    class Response:
        def read(self, n):
            return b"x" * min(n, length)

        def getheaders(self):
            return []

    Response.status = status

    class Connection:
        def __init__(self, *a, **kw):
            pass

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            closed.append(True)

    monkeypatch.setattr(storage_signing.http.client, "HTTPSConnection", Connection)
    with pytest.raises(StorageOwnershipError):
        storage_signing.control_call(
            dict(method="POST", url="https://example.test/b/k?uploadId=u", headers={})
        )
    assert closed == [True]
