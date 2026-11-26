"""Bounded immutable artifact plans. Producers supply persisted volume identities.

This is not an inventory discovery API: callers must derive volume IDs and size
bounds from the selected backup's persisted source, never from a receipt.
"""

import hashlib

from core.s3_ownership import StorageOwnershipError

MAX_ARTIFACTS = 4096
MAX_BYTES = 2**63 - 1
ROLES = {"volume_payload", "volume_manifest", "backup_metadata", "chain_manifest"}


def artifact_key(claim, volume_id, role):
    if (
        role not in ROLES
        or not isinstance(volume_id, str)
        or not 0 < len(volume_id) <= 512
    ):
        raise StorageOwnershipError("Invalid stable artifact identity")
    if claim.kind == "chain_manifest":
        if role != "chain_manifest" or volume_id != claim.backup_id:
            raise StorageOwnershipError("Invalid root manifest identity")
        return claim.object_key
    if (
        claim.kind != "payload"
        or role == "chain_manifest"
        or not claim.object_key.endswith("/")
    ):
        raise StorageOwnershipError("Invalid payload reservation")
    digest = hashlib.sha256(volume_id.encode()).hexdigest()
    return claim.object_key + digest + "/" + role


def build_plan(claim, artifacts):
    """Compile exact keys and inclusive bounds without names or configuration."""
    if type(artifacts) is not list or not 0 < len(artifacts) <= MAX_ARTIFACTS:
        raise StorageOwnershipError("Artifact plan inventory is empty or unbounded")
    fields = {
        "volume_id",
        "role",
        "plaintext_min",
        "plaintext_max",
        "ciphertext_min",
        "ciphertext_max",
    }
    seen, planned = set(), []
    for item in artifacts:
        if type(item) is not dict or set(item) != fields:
            raise StorageOwnershipError("Invalid artifact plan fields")
        key = artifact_key(claim, item["volume_id"], item["role"])
        identity = (item["volume_id"], item["role"])
        if identity in seen:
            raise StorageOwnershipError("Duplicate artifact role and volume")
        for prefix in ("plaintext", "ciphertext"):
            low, high = item[prefix + "_min"], item[prefix + "_max"]
            if (
                type(low) is not int
                or type(high) is not int
                or not 0 <= low <= high <= MAX_BYTES
            ):
                raise StorageOwnershipError("Invalid artifact byte bounds")
        seen.add(identity)
        planned.append({**item, "key": key})
    return {"schema": 1, "artifacts": sorted(planned, key=lambda item: item["key"])}


def validate_plan(claim, plan):
    if type(plan) is dict and plan.get("schema") == 2:
        from core.storage_source import source_artifacts

        if (
            type(plan["schema"]) is not int
            or set(plan) != {"schema", "source", "artifacts"}
            or claim.kind != "payload"
        ):
            raise StorageOwnershipError("Invalid source-bound plan")
        expected = build_plan(claim, source_artifacts(plan["source"]))
        expected.update(schema=2, source=plan["source"])
        if expected != plan:
            raise StorageOwnershipError("Artifact plan differs from committed source")
        return expected
    if (
        type(plan) is not dict
        or set(plan) != {"schema", "artifacts"}
        or type(plan["schema"]) is not int
        or plan["schema"] != 1
    ):
        raise StorageOwnershipError("Missing or unsupported artifact plan")
    artifacts = plan["artifacts"]
    if (
        type(artifacts) is not list
        or not 0 < len(artifacts) <= MAX_ARTIFACTS
        or any(type(item) is not dict or "key" not in item for item in artifacts)
    ):
        raise StorageOwnershipError("Invalid artifact plan inventory")
    canonical = build_plan(
        claim, [{k: v for k, v in item.items() if k != "key"} for item in artifacts]
    )
    if canonical != plan:
        raise StorageOwnershipError(
            "Artifact plan keys differ from immutable owner identities"
        )
    return canonical
