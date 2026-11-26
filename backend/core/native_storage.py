"""Native source/artifact/receipt variant; no dispatch or acceptance authority.

The enclosing reservation must supply tenant/target/encryption authority. These
pure controls do not resolve settings, credentials, local files or native jobs.
"""

import hashlib
import hmac
import re

from core.native_inventory import digest, exact, refuse, validate
from core.storage_semantics import UUID

FORMAT = "libvirt-native-fileset/1"
NATIVE_STORAGE_SOURCE_FIELDS = {
    "representation",
    "agent_id",
    "vm_id",
    "inventory_sha256",
    "inventory",
}
NATIVE_STORAGE_ARTIFACT_FIELDS = {
    "artifact_id",
    "disk_id",
    "role",
    "key",
    "plaintext_min",
    "plaintext_max",
    "ciphertext_min",
    "ciphertext_max",
}
NATIVE_STORAGE_RECEIPT_FIELDS = {
    "protocol",
    "schema",
    "representation",
    "reservation_id",
    "backup_id",
    "endpoint",
    "bucket",
    "objects",
}
NATIVE_STORAGE_OBJECT_RECEIPT_FIELDS = {
    "artifact_id",
    "disk_id",
    "role",
    "key",
    "version_id",
    "etag",
    "plaintext_bytes",
    "ciphertext_bytes",
    "plaintext_sha256",
    "ciphertext_sha256",
}


def validate_source(source):
    exact(source, NATIVE_STORAGE_SOURCE_FIELDS)
    for key in ("agent_id", "vm_id"):
        if type(source[key]) is not str or not UUID.fullmatch(source[key]):
            refuse()
    if source["representation"] != FORMAT:
        refuse()
    validate(source["inventory"])
    if source["inventory_sha256"] != digest(source["inventory"]):
        refuse()
    return source


def encrypted(encryption):
    exact(encryption, {"format", "key_ref"})
    if encryption == {"format": "none", "key_ref": None}:
        return False
    ref = encryption["key_ref"]
    if encryption["format"] != "vnbu1-aes256gcm-chunk5242880" or type(ref) is not str:
        refuse()
    parts = ref.split(":")
    if (
        len(parts) != 3
        or parts[0] != "kek"
        or not UUID.fullmatch(parts[1])
        or not re.fullmatch(r"(?:[0-9a-f]{16}|[0-9a-f]{64})", parts[2])
    ):
        refuse()
    return True


def build_artifacts(source, org_id, backup_id, reservation_id, encryption):
    validate_source(source)
    for value in (org_id, backup_id, reservation_id):
        if type(value) is not str or not UUID.fullmatch(value):
            refuse()
    inventory = source["inventory"]
    if (
        inventory["backup_id"] != backup_id
        or inventory["attempt_id"] != reservation_id
        or reservation_id[14] != "4"
    ):
        refuse()
    use_encryption = encrypted(encryption)
    root = (
        "vnbui-owned/v1/"
        + "/".join(hashlib.sha256(v.encode()).hexdigest() for v in (org_id, backup_id))
        + "/payload/"
        + reservation_id
        + "/native/"
    )
    result = []
    for member in inventory["files"]:
        size = member["size"]
        stored = (
            5 + size + 32 * ((size + 5242880 - 1) // 5242880)
            if use_encryption
            else size
        )
        result.append(
            {
                "artifact_id": member["artifact_id"],
                "disk_id": member["disk_id"],
                "role": member["role"],
                "key": root + member["artifact_id"],
                "plaintext_min": size,
                "plaintext_max": size,
                "ciphertext_min": stored,
                "ciphertext_max": stored,
            }
        )
    return sorted(result, key=lambda item: item["key"])


def validate_receipt(receipt, artifacts, backup_id, reservation_id, target, encryption):
    """Match a receipt to an already validated immutable artifact variant.

    Hash strings are producer commitments, not independent byte verification.
    No provider assurance or backend acceptance is inferred here.
    """
    exact(receipt, NATIVE_STORAGE_RECEIPT_FIELDS)
    if (
        receipt["protocol"] != "vnbui-storage-transaction/1"
        or type(receipt["schema"]) is not int
        or receipt["schema"] != 2
        or receipt["representation"] != FORMAT
        or receipt["backup_id"] != backup_id
        or receipt["reservation_id"] != reservation_id
        or receipt["endpoint"] != target["endpoint"]
        or receipt["bucket"] != target["bucket"]
    ):
        refuse()
    objects = receipt["objects"]
    if type(objects) is not list or not 0 < len(objects) == len(artifacts) <= 4096:
        refuse()
    planned = {}
    for artifact in artifacts:
        exact(artifact, NATIVE_STORAGE_ARTIFACT_FIELDS)
        if artifact["key"] in planned:
            refuse()
        planned[artifact["key"]] = artifact
    use_encryption = encrypted(encryption)
    for obj in objects:
        exact(obj, NATIVE_STORAGE_OBJECT_RECEIPT_FIELDS)
        if type(obj["key"]) is not str:
            refuse()
        artifact = planned.pop(obj["key"], None)
        if artifact is None or any(
            obj[k] != artifact[k] for k in ("artifact_id", "disk_id", "role")
        ):
            refuse()
        for prefix in ("plaintext", "ciphertext"):
            size = obj[prefix + "_bytes"]
            value = obj[prefix + "_sha256"]
            if (
                type(size) is not int
                or not artifact[prefix + "_min"] <= size <= artifact[prefix + "_max"]
                or type(value) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", value)
            ):
                refuse()
        if (
            type(obj["etag"]) is not str
            or not obj["etag"].strip()
            or len(obj["etag"].encode()) > 1024
            or (
                obj["version_id"] is not None
                and (
                    type(obj["version_id"]) is not str
                    or not 0 < len(obj["version_id"].encode()) <= 1024
                )
            )
        ):
            refuse()
        size = obj["plaintext_bytes"]
        stored = (
            5 + size + 32 * ((size + 5242880 - 1) // 5242880)
            if use_encryption
            else size
        )
        if obj["ciphertext_bytes"] != stored or (
            not use_encryption
            and not hmac.compare_digest(
                obj["plaintext_sha256"], obj["ciphertext_sha256"]
            )
        ):
            refuse()
    import json

    body = json.dumps(
        receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if len(body) > 4 * 1024 * 1024:
        refuse()
    return body, hashlib.sha256(body).hexdigest()
