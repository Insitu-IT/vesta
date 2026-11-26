"""Generated wire shape and fail-closed, non-activated transaction admission."""

import json
import hashlib
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import pytest

from core.storage_dispatch import compile_request
from core.s3_ownership import StorageOwnershipError
from core.storage_wire import (
    Artifact,
    DiskMapping,
    Encryption,
    Parent,
    Plan,
    Profile,
    Source,
    NativeDiskSource,
    Target,
    TransactionRequest,
    Volume,
    decode_request,
    plan_digest,
)
from contracts import contracts


@pytest.mark.parametrize(
    "field,value",
    [
        ("endpoint", "http://store.invalid"),
        ("endpoint", "https://STORE.invalid"),
        ("endpoint", "https://store.invalid/"),
        ("endpoint", "https://store.invalid:443"),
        ("endpoint", "https://user:private@store.invalid"),
        ("endpoint", "https://store.invalid/path"),
        ("endpoint", "https://store.invalid?redirect=other.invalid"),
        ("endpoint", "https://store.invalid#fragment"),
        ("endpoint", 6),
        ("bucket", 6),
        ("region", False),
        ("prefix", []),
        ("prefix", None),
        ("capability_profile", "unknown/1"),
    ],
)
def test_transaction_target_requires_literal_typed_authority(monkeypatch, field, value):
    from core.storage_dispatch import read_target

    target = dict(
        endpoint="https://store.invalid",
        bucket="bucket",
        region="",
        prefix="",
        capability_profile="db-rooted-consumer-verified/1",
    )
    target[field] = value
    monkeypatch.setenv("STORAGE_CAPABILITY_PROFILE", target["capability_profile"])
    settings = SimpleNamespace(
        get_many=lambda keys: {
            key: (
                "s3"
                if key == "storage.type"
                else target[key.removeprefix("storage.s3.")]
            )
            for key in keys
        }
    )
    with pytest.raises(StorageOwnershipError):
        read_target(settings)


def test_transaction_target_preserves_exact_nondefault_origin(monkeypatch):
    from core.storage_dispatch import read_target

    expected = dict(
        endpoint="https://store.invalid:9443",
        bucket="bucket",
        region="eu-central",
        prefix="installation/one",
        capability_profile="db-rooted-consumer-verified/1",
    )
    monkeypatch.setenv("STORAGE_CAPABILITY_PROFILE", expected["capability_profile"])
    settings = SimpleNamespace(
        get_many=lambda keys: {
            key: (
                "s3"
                if key == "storage.type"
                else expected[key.removeprefix("storage.s3.")]
            )
            for key in keys
        }
    )
    assert read_target(settings) == expected


def test_shared_canonical_digest_vectors():
    vectors = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "agent/contracts/storage_digest_vectors.json"
        ).read_text()
    )
    assert len(vectors) == 3
    for vector in vectors:
        assert plan_digest(vector["value"]) == vector["sha256"]


def test_generated_protocol_and_profile_enums():
    assert set(get_args(Profile)) == contracts.STORAGE_PROFILES
    assert (
        set(get_args(TransactionRequest.model_fields["protocol"].annotation))
        == contracts.STORAGE_PROTOCOLS
    )


@pytest.mark.parametrize("name", ["1-disk", "2-disk", "incremental", "libvirt"])
def test_generated_receipt_acceptance_match_c01(name):
    """Field parity only; D06 still owns the schema-2 acceptance endpoint."""
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / f"tests/fixtures/storage-contract-v1/{name}.json"
        ).read_text()
    )
    receipt, acceptance = fixture["prepared_receipt"], fixture["acceptance"]
    assert set(receipt) == contracts.STORAGE_RECEIPT_FIELDS
    assert set(acceptance) == contracts.STORAGE_ACCEPTANCE_FIELDS
    assert len(receipt["objects"]) > 0
    for obj in receipt["objects"]:
        assert set(obj) == contracts.STORAGE_OBJECT_RECEIPT_FIELDS
    for obj in acceptance["verification"]:
        assert set(obj) == contracts.STORAGE_VERIFICATION_FIELDS
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == acceptance["receipt_sha256"]


def request():
    agent = "11111111-1111-4111-8111-111111111111"
    vm_id = "22222222-2222-4222-8222-222222222222"
    backup_id = "33333333-3333-4333-8333-333333333333"
    org = "44444444-4444-4444-8444-444444444444"
    attempt = "55555555-5555-4555-8555-555555555555"
    source = dict(
        schema=1,
        agent_id=agent,
        vm_id=vm_id,
        vm_uid="uid",
        namespace="ns",
        volumes=[
            dict(
                name="data",
                pvc_name="pvc",
                pvc_uid="pvc-uid",
                pvc_resource_version="1",
                capacity_bytes=1048576,
            )
        ],
    )
    vm = SimpleNamespace(
        name="vm",
        agent_id=agent,
        vmi_uid="vmi",
        state="running",
        disks=[
            dict(
                target="data",
                mapping=dict(
                    disk_name="data", device="disk", bus="virtio", serial=None
                ),
            )
        ],
    )
    backup = SimpleNamespace(
        id=backup_id,
        org_id=org,
        parent_backup_id=None,
        backup_type="full",
        exclude_disks=[],
    )
    claim = SimpleNamespace(
        id=attempt,
        object_key="vnbui-owned/v1/"
        + hashlib.sha256(org.encode()).hexdigest()
        + "/"
        + hashlib.sha256(backup_id.encode()).hexdigest()
        + "/payload/",
        endpoint="https://store.invalid",
        bucket="bucket",
    )
    return compile_request(
        claim,
        source,
        vm,
        backup,
        dict(capability_profile="db-rooted-consumer-verified/1"),
    )


@pytest.mark.parametrize(
    "model,name",
    [
        (TransactionRequest, "REQUEST"),
        (Plan, "PLAN"),
        (Source, "SOURCE"),
        (NativeDiskSource, "SOURCE2"),
        (Volume, "VOLUME"),
        (DiskMapping, "MAPPING"),
        (Parent, "PARENT"),
        (Target, "TARGET"),
        (Encryption, "ENCRYPTION"),
        (Artifact, "ARTIFACT"),
    ],
)
def test_generated_go_python_fields(model, name):
    expected = getattr(
        contracts, f"STORAGE_{name if name != 'SOURCE2' else 'SOURCE'}_FIELDS"
    )
    if name == "SOURCE":
        expected = expected - contracts.STORAGE_SOURCE_SCHEMA2_FIELDS
    if name == "PLAN":
        expected = expected - contracts.STORAGE_PLAN_OPTIONAL_FIELDS
    assert set(model.model_fields) == expected


def test_compiled_envelope_roundtrip_and_literal_keys():
    value = request()
    assert decode_request(json.dumps(value).encode()).model_dump() == value
    assert len(value["plan"]["artifacts"]) == 2
    assert all(
        "/payload/" + value["reservation_id"] + "/" in a["key"]
        for a in value["plan"]["artifacts"]
    )


@pytest.mark.parametrize(
    "mutation", ["protocol", "profile", "schema", "extra", "digest", "agent"]
)
def test_unknown_or_unbound_wire_refused(mutation):
    value = deepcopy(request())
    if mutation == "protocol":
        value["protocol"] = "vnbui-storage-transaction/2"
    elif mutation == "profile":
        value["plan"]["capability_profile"] = "unknown/1"
    elif mutation == "schema":
        value["plan"]["source"]["schema"] = True
    elif mutation == "extra":
        value["secret"] = "not-accepted"
    elif mutation == "digest":
        value["plan_sha256"] = "wrong"
    else:
        value["agent_id"] = "foreign"
    with pytest.raises(ValueError):
        decode_request(json.dumps(value).encode())


def test_duplicate_field_refused():
    with pytest.raises(ValueError):
        decode_request(b'{"protocol":"one","protocol":"two"}')


SEMANTICS = Path(__file__).resolve().parents[2] / "agent/contracts"


@pytest.mark.parametrize(
    "case",
    json.loads((SEMANTICS / "storage_semantic_cases.json").read_text()),
    ids=lambda c: c["name"],
)
def test_shared_semantic_corpus(case):
    value = json.loads((SEMANTICS / "storage_semantic_valid.json").read_text())
    for change in case["changes"]:
        parts = change["path"].split(".")
        node = value
        for key in parts[:-1]:
            node = node[int(key)] if isinstance(node, list) else node[key]
        key = int(parts[-1]) if isinstance(node, list) else parts[-1]
        node[key] = change["value"]
    # Re-sign the changed plan: a semantic refusal, not a stale-digest refusal.
    value["plan_sha256"] = plan_digest(value["plan"])
    if case["accepted"]:
        assert decode_request(json.dumps(value).encode()).model_dump() == value
    else:
        with pytest.raises(ValueError):
            decode_request(json.dumps(value).encode())


def test_shared_semantic_baseline_matches_production_compiler():
    assert request() == json.loads(
        (SEMANTICS / "storage_semantic_valid.json").read_text()
    )
