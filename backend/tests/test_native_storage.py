"""Native variant review checkpoint; no mounted upload/acceptance claim."""

import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys

import pytest

from core import native_storage as native
from core.native_inventory import digest
from core.s3_ownership import StorageOwnershipError

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = json.loads(
    (ROOT / "agent/contracts/native_storage_examples.json").read_text()
)


def test_native_storage_generated_parity():
    from agent.contracts import contracts

    for name in ("SOURCE", "ARTIFACT", "RECEIPT", "OBJECT_RECEIPT"):
        field = "NATIVE_STORAGE_" + name + "_FIELDS"
        assert getattr(native, field) == getattr(contracts, field)
    assert contracts.NATIVE_STORAGE_REPRESENTATIONS == {native.FORMAT}
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/generate-native-storage-contract.py"),
            "--check",
        ],
        check=True,
    )


def test_native_uint64_custody_is_lossless():
    source = deepcopy(EXAMPLES[0]["source"])
    source["inventory"]["files"][0]["inode"] = 2**64 - 1
    source["inventory_sha256"] = digest(source["inventory"])
    assert native.validate_source(source) == source


@pytest.mark.parametrize(
    "fault", ["org", "backup", "attempt", "format", "key", "raw_key"]
)
def test_native_artifacts_refuse_binding_and_encryption_drift(fault):
    example = deepcopy(EXAMPLES[1])
    source, encryption = example["source"], example["encryption"]
    org, backup, attempt = (
        example["org_id"],
        example["receipt"]["backup_id"],
        example["receipt"]["reservation_id"],
    )
    if fault == "org":
        org = "name"
    elif fault == "backup":
        backup = org
    elif fault == "attempt":
        attempt = org
    elif fault == "format":
        encryption["format"] = "future-format"
    elif fault == "key":
        encryption["key_ref"] = "unbound"
    else:
        encryption["dek"] = "forbidden"
    with pytest.raises(StorageOwnershipError):
        native.build_artifacts(source, org, backup, attempt, encryption)


@pytest.mark.parametrize("example", EXAMPLES)
def test_native_storage_example(example):
    s, r, e = example["source"], example["receipt"], example["encryption"]
    assert native.validate_source(s) == s
    assert digest(s) == example["source_sha256"]
    artifacts = native.build_artifacts(
        s, example["org_id"], r["backup_id"], r["reservation_id"], e
    )
    assert artifacts == example["artifacts"]
    assert sum(a["disk_id"] is None for a in artifacts) == 3
    _, receipt_hash = native.validate_receipt(
        r, artifacts, r["backup_id"], r["reservation_id"], example["target"], e
    )
    assert receipt_hash == example["receipt_sha256"]
    reordered = deepcopy(s)
    reordered["inventory"]["files"].reverse()
    reordered["inventory_sha256"] = digest(reordered["inventory"])
    assert (
        native.build_artifacts(
            reordered, example["org_id"], r["backup_id"], r["reservation_id"], e
        )
        == artifacts
    )
    assert digest(reordered) != digest(s)  # same membership is not identical replay


@pytest.mark.parametrize(
    "fault",
    ["representation", "digest", "agent", "extra", "member", "missing", "uint64"],
)
def test_native_storage_source_refusal(fault):
    s = deepcopy(EXAMPLES[0]["source"])
    if fault == "representation":
        s["representation"] = "libvirt-native-fileset/2"
    elif fault == "digest":
        s["inventory_sha256"] = "0" * 64
    elif fault == "agent":
        s["agent_id"] = "display-name"
    elif fault == "extra":
        s["namespace"] = "guessed"
    elif fault == "member":
        s["inventory"]["files"][0]["member_checkpoint"] = "foreign"
        s["inventory_sha256"] = digest(s["inventory"])
    elif fault == "missing":
        s["inventory"]["files"].pop(0)
        s["inventory_sha256"] = digest(s["inventory"])
    else:
        s["inventory"]["files"][0]["inode"] = 2**64
        s["inventory_sha256"] = digest(s["inventory"])
    with pytest.raises(StorageOwnershipError):
        native.validate_source(s)


@pytest.mark.parametrize("example", EXAMPLES)
@pytest.mark.parametrize(
    "fault",
    [
        "representation",
        "schema",
        "extra",
        "missing",
        "duplicate",
        "artifact",
        "disk",
        "role",
        "key",
        "count",
        "hash",
        "endpoint",
        "backup",
        "version",
    ],
)
def test_native_storage_receipt_refusal(example, fault):
    r = deepcopy(example["receipt"])
    obj = r["objects"][0]
    if fault in {"representation", "endpoint", "backup"}:
        r[{"backup": "backup_id"}.get(fault, fault)] = "foreign"
    elif fault == "schema":
        r["schema"] = True
    elif fault == "extra":
        obj["volume_id"] = "guessed"
    elif fault == "missing":
        r["objects"].pop()
    elif fault == "duplicate":
        r["objects"][-1] = deepcopy(obj)
    elif fault == "artifact":
        obj["artifact_id"] = "0" * 64
    elif fault == "disk":
        obj["disk_id"] = "guessed"
    elif fault == "role":
        obj["role"] = "volume_payload"
    elif fault == "key":
        obj["key"] += "/other"
    elif fault == "count":
        obj["ciphertext_bytes"] += 1
    elif fault == "hash":
        obj["plaintext_sha256"] = "not-a-hash"
    else:
        obj["version_id"] = ""
    with pytest.raises(StorageOwnershipError):
        native.validate_receipt(
            r,
            example["artifacts"],
            example["receipt"]["backup_id"],
            example["receipt"]["reservation_id"],
            example["target"],
            example["encryption"],
        )
