"""Independent published vector for the unmounted Complete/HEAD cut."""

import base64

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_composite import verify_sha256_composite

# AWS multipart additional-checksum tutorial, steps 6 and 9; OPS note 63527.
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/tutorial-s3-mpu-additional-checksums.html
PARTS = tuple(
    base64.b64decode(value, validate=True).hex()
    for value in (
        "QLl8R4i4+SaJlrl8ZIcutc5TbZtwt2NwB8lTXkd3GH0=",
        "xCdgs1K5Bm4jWETYw/CmGYr+m6O2DcGfpckx5NVokvE=",
        "f5wsfsa5bB+yXuwzqG1Bst91uYneqGD3CCidpb54mAo=",
    )
)
COMPOSITE = "aI8EoktCdotjU8Bq46DrPCxQCGuGcPIhJ51noWs6hvk=-3"


def test_published_three_part_composite():
    assert verify_sha256_composite(PARTS, COMPOSITE, "COMPOSITE") == {
        "algorithm": "SHA256",
        "type": "COMPOSITE",
        "value": COMPOSITE,
        "part_count": 3,
    }


def test_swapped_part_order_refused():
    swapped = (PARTS[1], PARTS[0], PARTS[2])
    with pytest.raises(StorageOwnershipError, match="differs from committed parts"):
        verify_sha256_composite(swapped, COMPOSITE, "COMPOSITE")


@pytest.mark.parametrize("suffix", ["-2", "-4", "-03", "", "-3\n"])
def test_wrong_or_noncanonical_count_refused(suffix):
    with pytest.raises(StorageOwnershipError, match="differs from committed parts"):
        verify_sha256_composite(PARTS, COMPOSITE[:-2] + suffix, "COMPOSITE")


@pytest.mark.parametrize("kind", ["FULL_OBJECT", "", None, "SHA256"])
def test_composite_cannot_be_full_object_evidence(kind):
    with pytest.raises(StorageOwnershipError, match="Invalid composite checksum"):
        verify_sha256_composite(PARTS, COMPOSITE, kind)


@pytest.mark.parametrize("checksum", [None, "", '"etag"', 15728640])
def test_absent_checksum_or_identity_only_refused(checksum):
    with pytest.raises(StorageOwnershipError):
        verify_sha256_composite(PARTS, checksum, "COMPOSITE")


@pytest.mark.parametrize("parts", [(), PARTS * 3334, ("00",), ("g" * 64,)])
def test_invalid_part_evidence_refused(parts):
    with pytest.raises(StorageOwnershipError, match="Invalid composite"):
        verify_sha256_composite(parts, COMPOSITE, "COMPOSITE")
