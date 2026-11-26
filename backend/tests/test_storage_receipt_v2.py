"""C01 schema-2 receipt/HEAD controls; no DB acceptance claim from these doubles."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical, decode, validate, verify


def receipt_fixture():
    request = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "agent/contracts/storage_semantic_valid.json"
        ).read_text()
    )
    claim = SimpleNamespace(
        id=request["reservation_id"],
        backup_id=request["backup_id"],
        org_id=request["org_id"],
        endpoint=request["plan"]["target"]["endpoint"],
        bucket=request["plan"]["target"]["bucket"],
        state="reserved",
        dispatch_token="durable-fixture-custody",
        expected_plan={"schema": 3, "transaction": request},
    )
    receipt = dict(
        protocol=request["protocol"],
        schema=2,
        reservation_id=claim.id,
        backup_id=claim.backup_id,
        endpoint=claim.endpoint,
        bucket=claim.bucket,
        objects=[
            dict(
                key=a["key"],
                volume_id=a["volume_id"],
                role=a["role"],
                version_id=None,
                etag='"opaque"',
                plaintext_bytes=1,
                ciphertext_bytes=1,
                plaintext_sha256="a" * 64,
                ciphertext_sha256="a" * 64,
            )
            for a in request["plan"]["artifacts"]
        ],
    )
    return claim, receipt


def head_fixture(claim, request, obj):
    return dict(
        ContentLength=obj["ciphertext_bytes"],
        ETag=obj["etag"],
        VersionId=obj["version_id"],
        Metadata={
            "vnbui-protocol": "1",
            "vnbui-org-id": claim.org_id,
            "vnbui-backup-id": claim.backup_id,
            "vnbui-reservation-id": claim.id,
            "vnbui-plan-sha256": request["plan_sha256"],
            "vnbui-artifact-id": hashlib.sha256(
                (obj["volume_id"] + ":" + obj["role"]).encode()
            ).hexdigest(),
        },
    )


def test_receipt_hash_preserves_order_and_detaches():
    claim, receipt = receipt_fixture()
    _, validated, digest = validate(claim, receipt)
    assert digest == hashlib.sha256(canonical(receipt)).hexdigest()
    receipt["objects"].reverse()
    assert validate(claim, receipt)[2] != digest
    assert validated["objects"][0] != receipt["objects"][0]


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "extra",
        "duplicate",
        "role",
        "volume",
        "bytes",
        "bool",
        "hash",
        "framing",
        "version",
        "etag",
        "schema",
        "protocol",
        "target",
        "custody",
        "state",
        "request-digest",
        "extra-field",
    ],
)
def test_receipt_refuses_before_head(case):
    claim, r = receipt_fixture()
    obj = r["objects"][0]
    if case == "missing":
        r["objects"].pop()
    elif case == "extra":
        r["objects"].append(deepcopy(obj))
    elif case == "duplicate":
        r["objects"][1] = deepcopy(obj)
    elif case in {"role", "volume", "hash", "version", "etag"}:
        obj[
            {
                "role": "role",
                "volume": "volume_id",
                "hash": "ciphertext_sha256",
                "version": "version_id",
                "etag": "etag",
            }[case]
        ] = (
            "" if case in {"version", "etag"} else "wrong"
        )
    elif case == "bytes":
        obj["plaintext_bytes"] = 2**63
    elif case == "bool":
        obj["plaintext_bytes"] = True
    elif case == "framing":
        obj["ciphertext_bytes"] = 2
    elif case == "schema":
        r["schema"] = 1
    elif case == "protocol":
        r["protocol"] = "future"
    elif case == "target":
        r["endpoint"] = "https://foreign.invalid"
    elif case == "custody":
        claim.dispatch_token = None
    elif case == "state":
        claim.state = "cleanup_required"
    elif case == "request-digest":
        claim.expected_plan["transaction"]["plan_sha256"] = "0" * 64
    elif case == "extra-field":
        r["assurance"] = "provider_checksum_verified"
    with pytest.raises(StorageOwnershipError):
        validate(claim, r)


@pytest.mark.parametrize(
    "case",
    [
        "absent",
        "checksum",
        "checksum-mismatch",
        "metadata",
        "version",
        "size",
        "etag",
        "unknown-checksum",
    ],
)
def test_exact_metadata_only_verification(case):
    claim, receipt = receipt_fixture()
    request, receipt, _ = validate(claim, receipt)
    calls = []

    def head(**args):
        calls.append(args)
        obj = next(o for o in receipt["objects"] if o["key"] == args["Key"])
        assert args == dict(
            Bucket=claim.bucket,
            Key=obj["key"],
            IfMatch=obj["etag"],
            ChecksumMode="ENABLED",
        )
        result = head_fixture(claim, request, obj)
        if case.startswith("checksum"):
            result.update(
                ChecksumType="FULL_OBJECT",
                ChecksumSHA256=base64.b64encode(bytes.fromhex("a" * 64)).decode(),
            )
        if case == "checksum-mismatch":
            result["ChecksumSHA256"] = "wrong"
        if case == "metadata":
            result["Metadata"]["vnbui-plan-sha256"] = "wrong"
        if case == "version":
            result["VersionId"] = "wrong"
        if case == "size":
            result["ContentLength"] = 2
        if case == "etag":
            result["ETag"] = '"wrong"'
        if case == "unknown-checksum":
            result["ChecksumType"] = "future"
        return result

    # No GET/list/body interface exists on this test client.
    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=claim.endpoint), head_object=head
    )
    if case in {"absent", "checksum"}:
        result = verify(claim, request, receipt, client)
        assert len(calls) == 2
        assert all(v["assurance"] == "identity_metadata_only" for v in result)
    else:
        with pytest.raises(StorageOwnershipError):
            verify(claim, request, receipt, client)


def test_duplicate_json_fields_refuse():
    with pytest.raises(ValueError):
        decode(b'{"schema":2,"schema":2}')


@pytest.mark.parametrize("version", [None, "version-exact"])
def test_versioned_checksum_enforced_profile(version):
    from core.storage_wire import plan_digest

    claim, receipt = receipt_fixture()
    request = claim.expected_plan["transaction"]
    request["plan"]["capability_profile"] = "checksum-enforced/1"
    request["plan_sha256"] = plan_digest(request["plan"])
    for obj in receipt["objects"]:
        obj["version_id"] = version
    request, receipt, _ = validate(claim, receipt)

    def head(**args):
        assert args.get("VersionId") == version
        assert ("VersionId" in args) == (version is not None)
        obj = next(o for o in receipt["objects"] if o["key"] == args["Key"])
        return dict(
            head_fixture(claim, request, obj),
            ChecksumType="FULL_OBJECT",
            ChecksumSHA256=base64.b64encode(
                bytes.fromhex(obj["ciphertext_sha256"])
            ).decode(),
        )

    client = SimpleNamespace(
        meta=SimpleNamespace(endpoint_url=claim.endpoint), head_object=head
    )
    assert all(
        v["assurance"] == "provider_checksum_verified" and v["reason"] is None
        for v in verify(claim, request, receipt, client)
    )


@pytest.mark.parametrize("size", [0, 1, 5242880, 5242881])
def test_encrypted_receipt_exact_framing(size):
    from core.storage_wire import plan_digest

    claim, receipt = receipt_fixture()
    request = claim.expected_plan["transaction"]
    request["plan"]["encryption"] = dict(
        format="vnbu1-aes256gcm-chunk5242880",
        key_ref="kek:11111111-1111-4111-8111-111111111111:" + "a" * 16,
    )
    request["plan"]["source"]["volumes"][0]["capacity_bytes"] = 10485760
    for artifact in request["plan"]["artifacts"]:
        if artifact["role"] == "volume_payload":
            artifact["plaintext_max"] = 10485760
            artifact["ciphertext_min"] = 5
            n = artifact["plaintext_max"]
            artifact["ciphertext_max"] = 5 + n + 32 * ((n + 5242879) // 5242880)
    request["plan_sha256"] = plan_digest(request["plan"])
    obj = next(o for o in receipt["objects"] if o["role"] == "volume_payload")
    obj.update(
        plaintext_bytes=size,
        ciphertext_bytes=5 + size + 32 * ((size + 5242879) // 5242880),
        ciphertext_sha256="b" * 64,
    )
    validate(claim, receipt)
    obj["ciphertext_bytes"] += 1
    with pytest.raises(StorageOwnershipError):
        validate(claim, receipt)
