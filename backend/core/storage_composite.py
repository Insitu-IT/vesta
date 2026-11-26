"""SHA256 multipart evidence, distinct from a full-object ciphertext digest.

Callers must supply the frozen, ordered committed part digests. This pure
comparison establishes no provider authentication, object identity or custody.
"""

import base64
import hashlib
import re

from core.s3_ownership import StorageOwnershipError


def verify_sha256_composite(part_digests, checksum, checksum_type):
    """Validate the declared SHA256 COMPOSITE wire representation exactly."""
    if (
        type(part_digests) not in (list, tuple)
        or not 1 <= len(part_digests) <= 10000
        or type(checksum) is not str
        or checksum_type != "COMPOSITE"
    ):
        raise StorageOwnershipError("Invalid composite checksum evidence")
    digest = hashlib.sha256()
    for value in part_digests:
        if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise StorageOwnershipError("Invalid composite part digest")
        digest.update(bytes.fromhex(value))
    expected = (
        base64.b64encode(digest.digest()).decode("ascii") + "-" + str(len(part_digests))
    )
    if checksum != expected:
        raise StorageOwnershipError("Composite checksum differs from committed parts")
    return dict(
        algorithm="SHA256",
        type="COMPOSITE",
        value=checksum,
        part_count=len(part_digests),
    )
