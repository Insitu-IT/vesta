"""Strict wire validation for an owned upload's object inventory.

Validation is not a storage HEAD, checkpoint commit, or publication transition.
Callers must persist the validated inventory and establish those independently.
ETags are opaque object identities, never plaintext or ciphertext checksums.
"""

import re
import base64

from core.s3_ownership import StorageOwnershipError, storage_identity
from core.storage_plan import validate_plan


def validate_receipt(claim, receipt):
    """Return a detached canonical inventory bound to the exact reservation.

    A prefix is authority only for literal child keys. Neither URL decoding nor
    path normalization may widen it. Unknown fields fail closed to prevent a
    newer producer's lifecycle semantics being silently discarded.
    """

    def refuse():
        raise StorageOwnershipError("Invalid or mismatched storage receipt")

    fields = {"schema", "reservation_id", "backup_id", "endpoint", "bucket", "objects"}
    if type(receipt) is not dict or set(receipt) != fields:
        refuse()
    if (
        type(receipt["schema"]) is not int
        or receipt["schema"] != 1
        or receipt["reservation_id"] != claim.id
        or receipt["backup_id"] != claim.backup_id
        or receipt["endpoint"] != claim.endpoint
        or receipt["bucket"] != claim.bucket
        or claim.state not in {"reserved", "published"}
    ):
        refuse()
    objects = receipt["objects"]
    plan = validate_plan(claim, getattr(claim, "expected_plan", None))
    planned = {item["key"]: item for item in plan["artifacts"]}
    if type(objects) is not list or len(objects) != len(planned):
        refuse()
    expected = {
        "key",
        "version_id",
        "etag",
        "plaintext_bytes",
        "ciphertext_bytes",
        "plaintext_sha256",
        "ciphertext_sha256",
        "volume_id",
        "role",
    }
    seen, result = set(), []
    for obj in objects:
        if type(obj) is not dict or set(obj) != expected:
            refuse()
        key = obj["key"]
        if not isinstance(key, str) or key in seen:
            refuse()
        item = planned.get(key)
        if item is None or any(
            obj[field] != item[field] for field in ("volume_id", "role")
        ):
            refuse()
        if claim.kind == "payload":
            if not claim.object_key.endswith("/") or not key.startswith(
                claim.object_key
            ):
                refuse()
            relative = key[len(claim.object_key) :]
            if any(part in {"", ".", ".."} for part in relative.split("/")) or any(
                char in relative for char in ("\\", "%", "\x00")
            ):
                refuse()
        elif claim.kind != "chain_manifest" or key != claim.object_key:
            refuse()
        version = obj["version_id"]
        if version is not None and (not isinstance(version, str) or not version):
            refuse()
        if not isinstance(obj["etag"], str) or not obj["etag"].strip():
            refuse()
        for field in ("plaintext_bytes", "ciphertext_bytes"):
            if type(obj[field]) is not int or obj[field] < 0:
                refuse()
            prefix = field.removesuffix("_bytes")
            if not item[prefix + "_min"] <= obj[field] <= item[prefix + "_max"]:
                refuse()
        for field in ("plaintext_sha256", "ciphertext_sha256"):
            if not isinstance(obj[field], str) or not re.fullmatch(
                "[0-9a-f]{64}", obj[field]
            ):
                refuse()
        seen.add(key)
        result.append(dict(obj))
    if seen != set(planned):
        refuse()
    return {**receipt, "objects": sorted(result, key=lambda obj: obj["key"])}


def verify_stored_receipt(claim, receipt, client):
    """Verify identity with HEAD only and expose checksum assurance separately.

    The synchronous S3 client must target the recorded origin. Metadata binds
    producer plaintext claims; plaintext correctness still requires the trusted
    encryption producer. Only a provider FULL_OBJECT SHA256 is comparable to the
    receipt's ciphertext SHA256. Multipart COMPOSITE hashes are not that digest.
    No body read, listing, publication transition or automatic scrub occurs.
    """
    validated = validate_receipt(claim, receipt)
    if storage_identity(
        {"endpoint": client.meta.endpoint_url, "bucket": claim.bucket}
    ) != (claim.endpoint, claim.bucket):
        raise StorageOwnershipError("Verification client differs from reserved target")
    verification = []
    for obj in validated["objects"]:
        request = dict(
            Bucket=claim.bucket,
            Key=obj["key"],
            IfMatch=obj["etag"],
            ChecksumMode="ENABLED",
        )
        if obj["version_id"] is not None:
            request["VersionId"] = obj["version_id"]
        response = client.head_object(**request)
        metadata = response.get("Metadata", {})
        expected = {
            "vnbui-reservation-id": claim.id,
            "vnbui-backup-id": claim.backup_id,
            "vnbui-plaintext-sha256": obj["plaintext_sha256"],
            "vnbui-ciphertext-sha256": obj["ciphertext_sha256"],
            "vnbui-plaintext-bytes": str(obj["plaintext_bytes"]),
            "vnbui-ciphertext-bytes": str(obj["ciphertext_bytes"]),
        }
        if (
            response.get("ContentLength") != obj["ciphertext_bytes"]
            or response.get("ETag") != obj["etag"]
            or response.get("VersionId") != obj["version_id"]
            or any(metadata.get(key) != value for key, value in expected.items())
        ):
            raise StorageOwnershipError(
                "Stored object identity or metadata differs from receipt"
            )
        checksum = response.get("ChecksumSHA256")
        checksum_type = response.get("ChecksumType")
        assurance = "identity_metadata_only"
        reason = "provider_full_object_sha256_unavailable"
        if checksum is not None and checksum_type == "FULL_OBJECT":
            expected_checksum = base64.b64encode(
                bytes.fromhex(obj["ciphertext_sha256"])
            ).decode("ascii")
            if checksum != expected_checksum:
                raise StorageOwnershipError(
                    "Provider ciphertext checksum differs from receipt"
                )
            assurance, reason = "provider_checksum_verified", None
        verification.append(
            dict(
                key=obj["key"],
                version_id=obj["version_id"],
                assurance=assurance,
                reason=reason,
                checksum_type=checksum_type,
                checksum_sha256=checksum,
            )
        )
    # The envelope cannot be mistaken for an ordinary validated receipt. A
    # publication caller must persist and expose per-object assurance explicitly.
    return {
        "receipt": validated,
        "verification": verification,
        "scrub_required": any(
            v["assurance"] != "provider_checksum_verified" for v in verification
        ),
    }
