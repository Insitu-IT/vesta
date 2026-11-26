"""Bounded ListParts wire evidence. A listing is never a recovery decision."""

import base64
import re
from xml.etree import ElementTree as ET

from core.s3_ownership import StorageOwnershipError

MAX_RESPONSE = 2 * 1024 * 1024
MAX_PARTS = 10000


def refuse():
    raise StorageOwnershipError("Invalid ListParts evidence")


def integer(value, minimum, maximum):
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        refuse()
    number = int(value)
    if not minimum <= number <= maximum:
        refuse()
    return number


def fields(element, repeated=()):
    result = {}
    for child in element:
        name = child.tag.rsplit("}", 1)[-1]
        if name in repeated:
            result.setdefault(name, []).append(child)
        elif name in result:
            refuse()
        else:
            result[name] = child
    return result


def scalar(values, name):
    node = values.get(name)
    if node is None or len(node) or node.attrib:
        refuse()
    return node.text or ""


def parse_page(data, bucket, key, upload_id, marker):
    if type(data) is not bytes or len(data) > MAX_RESPONSE or b"<!" in data:
        refuse()
    try:
        decoded = data.decode("utf-8")
        if "\x00" in decoded or "<!" in decoded:
            refuse()
        root = ET.fromstring(decoded)
    except (ET.ParseError, ValueError, UnicodeDecodeError):
        refuse()
    if (
        root.tag
        not in (
            "ListPartsResult",
            "{http://s3.amazonaws.com/doc/2006-03-01/}ListPartsResult",
        )
        or root.attrib
    ):
        refuse()
    namespace = root.tag[: -len("ListPartsResult")]
    if any(
        not isinstance(e.tag, str) or e.tag != namespace + e.tag.rsplit("}", 1)[-1]
        for e in root.iter()
    ):
        refuse()
    values = fields(root, ("Part",))
    required = {
        "Bucket",
        "Key",
        "UploadId",
        "PartNumberMarker",
        "MaxParts",
        "IsTruncated",
        "ChecksumAlgorithm",
        "ChecksumType",
    }
    allowed = required | {
        "NextPartNumberMarker",
        "Part",
        "Initiator",
        "Owner",
        "StorageClass",
    }
    if not required <= values.keys() or values.keys() - allowed:
        refuse()
    if (
        scalar(values, "Bucket"),
        scalar(values, "Key"),
        scalar(values, "UploadId"),
    ) != (bucket, key, upload_id):
        refuse()
    if (
        integer(scalar(values, "PartNumberMarker"), 0, MAX_PARTS) != marker
        or integer(scalar(values, "MaxParts"), 1, 1000) != 1000
    ):
        refuse()
    if (
        scalar(values, "ChecksumAlgorithm") != "SHA256"
        or scalar(values, "ChecksumType") != "COMPOSITE"
    ):
        refuse()
    truncated = scalar(values, "IsTruncated")
    if truncated not in ("true", "false"):
        refuse()
    parts = []
    last = marker
    for element in values.get("Part", []):
        row = fields(element)
        if (
            element.attrib
            or not {"PartNumber", "Size", "ETag", "ChecksumSHA256"} <= row.keys()
            or row.keys()
            - {"PartNumber", "Size", "ETag", "ChecksumSHA256", "LastModified"}
        ):
            refuse()
        number = integer(scalar(row, "PartNumber"), last + 1, MAX_PARTS)
        size = integer(scalar(row, "Size"), 0, 5368709120)
        etag = scalar(row, "ETag")
        if (
            not re.fullmatch(r'"[^"\x00-\x1f\x7f]{1,1022}"', etag)
            or len(etag.encode()) > 1024
        ):
            refuse()
        encoded = scalar(row, "ChecksumSHA256")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            refuse()
        if len(digest) != 32 or base64.b64encode(digest).decode() != encoded:
            refuse()
        parts.append(dict(number=number, bytes=size, etag=etag, sha256=digest.hex()))
        last = number
        if len(parts) > 1000:
            refuse()
    next_marker = (
        integer(scalar(values, "NextPartNumberMarker"), 0, MAX_PARTS)
        if "NextPartNumberMarker" in values
        else None
    )
    if truncated == "true" and (
        not parts or next_marker != last or next_marker <= marker
    ):
        refuse()
    if truncated == "false" and next_marker not in (None, 0, last):
        refuse()
    return dict(
        marker=marker,
        truncated=truncated == "true",
        next_marker=next_marker if truncated == "true" else None,
        parts=parts,
    )


def classify(observed, local):
    """Pure comparison. An observed ETag never creates an acknowledgment."""
    result = []
    for item in observed:
        known = local.get(item["number"])
        kind = "conflict"
        if known and (item["bytes"], item["sha256"]) == (
            known["bytes"],
            known["sha256"],
        ):
            if known["acknowledgment"] is None:
                kind = "unacknowledged_intent_match"
            elif item["etag"] == '"' + known["acknowledgment"]["etag"] + '"':
                kind = "committed_ack_match"
        result.append(dict(item, classification=kind))
    return result
