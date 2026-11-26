"""Transaction/1 receipt verification; acceptance is not publication authority."""

import base64
from copy import deepcopy
import hashlib
import json
import re

from core.s3_ownership import StorageOwnershipError
from core.storage_wire import PROTOCOL, validate_transaction


def decode(body):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate receipt field")
            result[key] = value
        return result

    try:
        return json.loads(body, object_pairs_hook=unique_pairs)
    except RecursionError:
        raise ValueError("Receipt nesting exceeds supported bounds") from None


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def validate(claim, receipt):
    def refuse():
        raise StorageOwnershipError("Transaction receipt does not match committed plan")

    try:
        saved = claim.expected_plan
        if (
            type(saved) is not dict
            or set(saved) != {"schema", "transaction"}
            or saved["schema"] != 3
        ):
            refuse()
        request = validate_transaction(saved["transaction"])
        if (
            request["reservation_id"] != claim.id
            or request["backup_id"] != claim.backup_id
            or request["org_id"] != claim.org_id
            or request["plan"]["target"]["endpoint"] != claim.endpoint
            or request["plan"]["target"]["bucket"] != claim.bucket
            or claim.state != "reserved"
            or not claim.dispatch_token
        ):
            refuse()
        if request["plan"]["provider"] == "libvirt":
            from core.native_storage import validate_receipt

            plan = request["plan"]
            _, receipt_hash = validate_receipt(
                receipt,
                plan["artifacts"],
                claim.backup_id,
                claim.id,
                plan["target"],
                plan["encryption"],
            )
            return request, deepcopy(receipt), receipt_hash
        fields = {
            "protocol",
            "schema",
            "reservation_id",
            "backup_id",
            "endpoint",
            "bucket",
            "objects",
        }
        if (
            type(receipt) is not dict
            or set(receipt) != fields
            or len(canonical(receipt)) > 4 * 1024 * 1024
        ):
            refuse()
        if (
            receipt["protocol"] != PROTOCOL
            or type(receipt["schema"]) is not int
            or receipt["schema"] != 2
            or any(
                receipt[k] != getattr(claim, k if k != "reservation_id" else "id")
                for k in ("reservation_id", "backup_id", "endpoint", "bucket")
            )
        ):
            refuse()
        objects = receipt["objects"]
        planned = {a["key"]: a for a in request["plan"]["artifacts"]}
        if type(objects) is not list or len(objects) != len(planned):
            refuse()
        seen = set()
        for obj in objects:
            if type(obj) is not dict or set(obj) != {
                "key",
                "version_id",
                "etag",
                "plaintext_bytes",
                "ciphertext_bytes",
                "plaintext_sha256",
                "ciphertext_sha256",
                "volume_id",
                "role",
            }:
                refuse()
            key = obj["key"]
            if type(key) is not str or key in seen or key not in planned:
                refuse()
            seen.add(key)
            artifact = planned[key]
            if any(obj[k] != artifact[k] for k in ("role", "volume_id")):
                refuse()
            for name in ("etag", "version_id"):
                value = obj[name]
                if name == "version_id" and value is None:
                    continue
                if type(value) is not str or not value or len(value.encode()) > 1024:
                    refuse()
            for domain in ("plaintext", "ciphertext"):
                count, digest = obj[domain + "_bytes"], obj[domain + "_sha256"]
                if (
                    type(count) is not int
                    or not artifact[domain + "_min"]
                    <= count
                    <= artifact[domain + "_max"]
                ):
                    refuse()
                if (
                    type(digest) is not str
                    or re.fullmatch("[0-9a-f]{64}", digest) is None
                ):
                    refuse()
            n = obj["plaintext_bytes"]
            if (
                obj["role"] != "volume_payload"
                or request["plan"]["encryption"]["format"] == "none"
            ):
                if (
                    n != obj["ciphertext_bytes"]
                    or obj["plaintext_sha256"] != obj["ciphertext_sha256"]
                ):
                    refuse()
            elif obj["ciphertext_bytes"] != 5 + n + 32 * ((n + 5242879) // 5242880):
                refuse()
        # Array order is part of the C01 digest, never sorted during validation.
        result = deepcopy(receipt)
        return request, result, hashlib.sha256(canonical(result)).hexdigest()
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        refuse()


def verify(claim, request, receipt, client):
    if client.meta.endpoint_url != claim.endpoint:
        raise StorageOwnershipError(
            "Verification target differs from committed authority"
        )
    verification = []
    for obj in receipt["objects"]:
        args = dict(
            Bucket=claim.bucket,
            Key=obj["key"],
            IfMatch=obj["etag"],
            ChecksumMode="ENABLED",
        )
        if obj["version_id"] is not None:
            args["VersionId"] = obj["version_id"]
        response = client.head_object(**args)
        metadata = {
            "vnbui-protocol": "1",
            "vnbui-org-id": claim.org_id,
            "vnbui-backup-id": claim.backup_id,
            "vnbui-reservation-id": claim.id,
            "vnbui-plan-sha256": request["plan_sha256"],
            "vnbui-artifact-id": (
                obj["artifact_id"]
                if request["plan"]["provider"] == "libvirt"
                else hashlib.sha256(
                    (obj["volume_id"] + ":" + obj["role"]).encode()
                ).hexdigest()
            ),
        }
        if (
            type(response.get("ContentLength")) is not int
            or response["ContentLength"] != obj["ciphertext_bytes"]
            or response.get("ETag") != obj["etag"]
            or response.get("VersionId") != obj["version_id"]
            or response.get("Metadata") != metadata
        ):
            raise StorageOwnershipError(
                "Stored identity differs from committed receipt"
            )
        checksum, kind = response.get("ChecksumSHA256"), response.get("ChecksumType")
        if kind not in (None, "", "FULL_OBJECT", "COMPOSITE"):
            raise StorageOwnershipError("Unknown provider checksum representation")
        comparable = checksum is not None and kind == "FULL_OBJECT"
        if (
            comparable
            and checksum
            != base64.b64encode(bytes.fromhex(obj["ciphertext_sha256"])).decode()
        ):
            raise StorageOwnershipError("Stored checksum differs from receipt")
        strong = (
            comparable
            and request["plan"]["capability_profile"] == "checksum-enforced/1"
        )
        verification.append(
            dict(
                key=obj["key"],
                version_id=obj["version_id"],
                assurance=(
                    "provider_checksum_verified" if strong else "identity_metadata_only"
                ),
                reason=None if strong else "provider_full_object_sha256_unavailable",
            )
        )
    return verification
