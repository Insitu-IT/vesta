"""Provider response parsing never substitutes another multipart identity."""

import hashlib
from xml.sax.saxutils import escape

import pytest

from core.callback_provider_create import _response
from core.s3_ownership import StorageOwnershipError

REQUEST = {"plan": {"target": {"bucket": "bound-bucket"}}}
KEY = "bound/object"


def xml(bucket="bound-bucket", key=KEY, upload="opaque-provider-id"):
    return (
        "<InitiateMultipartUploadResult><Bucket>"
        + escape(bucket)
        + "</Bucket><Key>"
        + escape(key)
        + "</Key><UploadId>"
        + escape(upload)
        + "</UploadId></InitiateMultipartUploadResult>"
    ).encode()


def test_exact_identity_and_raw_response_digest():
    data = xml()
    result = _response(REQUEST, KEY, {"x-amz-request-id": "request-1"}, data)
    assert result == dict(
        schema=1,
        bucket="bound-bucket",
        key=KEY,
        upload_id="opaque-provider-id",
        request_id="request-1",
        host_id=None,
        body_sha256=hashlib.sha256(data).hexdigest(),
    )


@pytest.mark.parametrize(
    "data,headers",
    [
        (xml(bucket="foreign"), {}),
        (xml(key="foreign"), {}),
        (xml(upload=""), {}),
        (xml(upload="é" * 513), {}),
        (xml(upload="opaque\ncontrol"), {}),
        (xml(), {"x-amz-request-id": "bad\rheader"}),
        (xml(), {"x-amz-id-2": "é" * 513}),
        (xml().replace(b"</UploadId>", b"</UploadId><UploadId>second</UploadId>"), {}),
        (b"<!DOCTYPE x>" + xml(), {}),
        (b"x" * (1024 * 1024 + 1), {}),
    ],
)
def test_foreign_ambiguous_or_unbounded_response_refused(data, headers):
    with pytest.raises(StorageOwnershipError):
        _response(REQUEST, KEY, headers, data)
