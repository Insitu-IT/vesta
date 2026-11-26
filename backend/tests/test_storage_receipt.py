"""Wire failures must never produce a usable publication inventory."""

from copy import deepcopy
from types import SimpleNamespace
import hashlib
import base64

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_receipt import validate_receipt, verify_stored_receipt
from core.storage_plan import build_plan, MAX_ARTIFACTS


def specimen():
    claim = SimpleNamespace(
        id="reservation",
        backup_id="backup",
        endpoint="https://storage.example",
        bucket="backups",
        object_key="vnbui-owned/v1/org/backup/payload/",
        kind="payload",
        state="reserved",
    )
    claim.expected_plan = build_plan(
        claim,
        [
            dict(
                volume_id="stable-volume",
                role="volume_payload",
                plaintext_min=4,
                plaintext_max=4,
                ciphertext_min=32,
                ciphertext_max=32,
            )
        ],
    )
    receipt = dict(
        schema=1,
        reservation_id=claim.id,
        backup_id=claim.backup_id,
        endpoint=claim.endpoint,
        bucket=claim.bucket,
        objects=[
            dict(
                key=claim.expected_plan["artifacts"][0]["key"],
                volume_id="stable-volume",
                role="volume_payload",
                version_id=None,
                etag="opaque-multipart-3",
                plaintext_bytes=4,
                ciphertext_bytes=32,
                plaintext_sha256="a" * 64,
                ciphertext_sha256="b" * 64,
            )
        ],
    )
    return claim, receipt


@pytest.mark.parametrize("version", [None, "null", "version-1"])
def test_receipt_retains_exact_identity_without_publishing(version):
    claim, receipt = specimen()
    receipt["objects"][0]["version_id"] = version
    result = validate_receipt(claim, receipt)
    assert result == receipt
    receipt["objects"][0]["etag"] = "changed"
    assert result["objects"][0]["etag"] == "opaque-multipart-3"
    assert claim.state == "reserved"


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("reservation_id", "other"),
        ("backup_id", "other"),
        ("endpoint", "http://storage.example"),
        ("bucket", "other"),
        ("objects", []),
        ("objects", None),
    ],
)
def test_wrong_reservation_or_schema_refused(field, value):
    claim, receipt = specimen()
    receipt[field] = value
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


@pytest.mark.parametrize(
    "suffix", ["", "../other", "a/../b", "/disk", "%2e%2e/disk", "a\\b", "a\x00b"]
)
def test_nonliteral_child_refused(suffix):
    claim, receipt = specimen()
    receipt["objects"][0]["key"] = claim.object_key + suffix
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("key", "vnbui-owned/v1/other/backup/payload/disk.enc"),
        ("version_id", ""),
        ("etag", ""),
        ("plaintext_bytes", True),
        ("ciphertext_bytes", -1),
        ("plaintext_sha256", "a" * 63),
        ("ciphertext_sha256", "opaque-etag"),
    ],
)
def test_invalid_object_identity_refused(field, value):
    claim, receipt = specimen()
    receipt["objects"][0][field] = value
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


def test_duplicates_unknown_fields_and_cleanup_refused():
    claim, original = specimen()
    for mutate in (
        lambda r: r["objects"].append(deepcopy(r["objects"][0])),
        lambda r: r.update(checkpoint_committed=True),
        lambda r: r["objects"][0].update(upload_id="unfinished"),
    ):
        receipt = deepcopy(original)
        mutate(receipt)
        with pytest.raises(StorageOwnershipError):
            validate_receipt(claim, receipt)
    claim.state = "cleanup_required"
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, original)


def test_manifest_requires_exact_key():
    claim, receipt = specimen()
    claim.kind = "chain_manifest"
    claim.object_key = "vnbui-owned/v1/org/backup/chain.json"
    claim.expected_plan = build_plan(
        claim,
        [
            dict(
                volume_id=claim.backup_id,
                role="chain_manifest",
                plaintext_min=4,
                plaintext_max=4,
                ciphertext_min=32,
                ciphertext_max=32,
            )
        ],
    )
    receipt["objects"][0].update(volume_id=claim.backup_id, role="chain_manifest")
    receipt["objects"][0]["key"] = claim.object_key
    assert validate_receipt(claim, receipt) == receipt
    receipt["objects"][0]["key"] += "/child"
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


@pytest.mark.parametrize("change", ["missing", "extra", "role", "volume", "bytes"])
def test_complete_plan_is_required(change):
    claim, receipt = specimen()
    artifact = {
        k: v for k, v in claim.expected_plan["artifacts"][0].items() if k != "key"
    }
    manifest = dict(artifact, role="volume_manifest")
    claim.expected_plan = build_plan(claim, [artifact, manifest])
    second = dict(receipt["objects"][0], role="volume_manifest")
    second["key"] = next(
        a["key"]
        for a in claim.expected_plan["artifacts"]
        if a["role"] == "volume_manifest"
    )
    receipt["objects"].append(second)
    assert len(validate_receipt(claim, receipt)["objects"]) == 2
    if change == "missing":
        receipt["objects"].pop()
    elif change == "extra":
        receipt["objects"].append(dict(second, key=second["key"] + "extra"))
    elif change == "role":
        second["role"] = "volume_payload"
    elif change == "volume":
        second["volume_id"] = "other"
    else:
        second["plaintext_bytes"] = 5
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


def test_plan_rejects_duplicate_unbounded_and_missing_inventory():
    claim, receipt = specimen()
    artifact = {
        k: v for k, v in claim.expected_plan["artifacts"][0].items() if k != "key"
    }
    for inventory in ([], [artifact, artifact], [artifact] * (MAX_ARTIFACTS + 1)):
        with pytest.raises(StorageOwnershipError):
            build_plan(claim, inventory)
    claim.expected_plan = None
    with pytest.raises(StorageOwnershipError):
        validate_receipt(claim, receipt)


@pytest.mark.parametrize(
    "fault", [None, "checksum", "size", "etag", "version", "metadata", "target"]
)
def test_store_verification_is_metadata_only(fault):
    claim, receipt = specimen()
    obj = receipt["objects"][0]
    obj["version_id"] = "immutable-version"
    data = b"x" * 32
    obj["ciphertext_sha256"] = hashlib.sha256(data).hexdigest()
    metadata = {
        "vnbui-reservation-id": claim.id,
        "vnbui-backup-id": claim.backup_id,
        "vnbui-plaintext-sha256": obj["plaintext_sha256"],
        "vnbui-ciphertext-sha256": obj["ciphertext_sha256"],
        "vnbui-plaintext-bytes": "4",
        "vnbui-ciphertext-bytes": "32",
    }
    response = dict(
        ContentLength=32,
        ETag=obj["etag"],
        VersionId=obj["version_id"],
        Metadata=metadata,
        ChecksumType="FULL_OBJECT",
        ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode(),
    )
    if fault == "checksum":
        response["ChecksumSHA256"] = base64.b64encode(
            hashlib.sha256(b"y" * 32).digest()
        ).decode()
    if fault == "size":
        response["ContentLength"] = 31
    if fault == "etag":
        response["ETag"] = "replacement"
    if fault == "version":
        response["VersionId"] = "replacement"
    if fault == "metadata":
        metadata["vnbui-reservation-id"] = "other"
    calls = []

    def head_object(**kwargs):
        calls.append(kwargs)
        return response

    def forbidden_body_read(**kwargs):
        pytest.fail("Normal verification must not GET object bytes")

    client = SimpleNamespace(
        meta=SimpleNamespace(
            endpoint_url=(
                "https://other.example" if fault == "target" else claim.endpoint
            )
        ),
        head_object=head_object,
        get_object=forbidden_body_read,
    )
    if fault:
        with pytest.raises(StorageOwnershipError):
            verify_stored_receipt(claim, receipt, client)
    else:
        result = verify_stored_receipt(claim, receipt, client)
        assert result["receipt"] == receipt
        assert not result["scrub_required"]
        assert result["verification"][0]["assurance"] == "provider_checksum_verified"
    if fault == "target":
        assert calls == []
    else:
        assert calls == [
            dict(
                Bucket=claim.bucket,
                Key=obj["key"],
                IfMatch=obj["etag"],
                VersionId="immutable-version",
                ChecksumMode="ENABLED",
            )
        ]
    assert claim.state == "reserved"


@pytest.mark.parametrize("checksum_type", [None, "COMPOSITE", "unknown"])
def test_weaker_provider_assurance_is_explicit_without_body_fallback(checksum_type):
    claim, receipt = specimen()
    obj = receipt["objects"][0]
    calls = []

    def head_object(**kwargs):
        calls.append(kwargs)
        return dict(
            ContentLength=32,
            ETag=obj["etag"],
            ChecksumType=checksum_type,
            ChecksumSHA256="not-a-full-object-checksum" if checksum_type else None,
            Metadata={
                "vnbui-reservation-id": claim.id,
                "vnbui-backup-id": claim.backup_id,
                "vnbui-plaintext-sha256": obj["plaintext_sha256"],
                "vnbui-ciphertext-sha256": obj["ciphertext_sha256"],
                "vnbui-plaintext-bytes": "4",
                "vnbui-ciphertext-bytes": "32",
            },
        )

    def forbidden_body_read(**kwargs):
        pytest.fail("Weak checksum must not trigger a download")

    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=claim.endpoint),
        head_object=head_object,
        get_object=forbidden_body_read,
    )
    result = verify_stored_receipt(claim, receipt, client)
    assert result["scrub_required"]
    assert result["verification"][0]["assurance"] == "identity_metadata_only"
    assert len(calls) == 1
    assert claim.state == "reserved"
