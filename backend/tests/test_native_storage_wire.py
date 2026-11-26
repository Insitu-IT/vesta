"""Whole-envelope negatives, independent of persisted/job authority."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from core.native_inventory import digest
from core.native_storage_wire import NativeTransactionRequest
from core.s3_ownership import StorageOwnershipError
from core.storage_wire import TransactionRequest, plan_digest, validate_transaction

EXAMPLES = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "agent/contracts/native_storage_examples.json"
    ).read_text()
)


def request(example):
    source = deepcopy(example["source"])
    plan = dict(
        attempt_id=source["inventory"]["attempt_id"],
        capability_profile="db-rooted-consumer-verified/1",
        provider="libvirt",
        source=source,
        backup_type="full",
        parent=None,
        exclusions=[],
        target=deepcopy(example["target"]),
        credential_ref="installation/storage.s3",
        encryption=deepcopy(example["encryption"]),
        artifacts=deepcopy(example["artifacts"]),
        checksum_policy="sha256-parts-receipt-v2",
    )
    return dict(
        protocol="vnbui-storage-transaction/1",
        org_id=example["org_id"],
        agent_id=source["agent_id"],
        backup_id=source["inventory"]["backup_id"],
        reservation_id=plan["attempt_id"],
        plan_sha256=plan_digest(plan),
        plan=plan,
    )


@pytest.mark.parametrize("example", EXAMPLES)
def test_native_whole_envelope_positive(example):
    value = request(example)
    assert value == example["request"]
    assert validate_transaction(value) == value
    with pytest.raises(ValueError):
        TransactionRequest.model_validate(value)


def test_native_whole_plan_generated_field_parity():
    from contracts import contracts
    from core.native_storage_wire import NativePlan

    assert set(NativePlan.model_fields) == contracts.NATIVE_STORAGE_PLAN_FIELDS
    assert (
        set(NativeTransactionRequest.model_fields)
        == contracts.NATIVE_TRANSACTION_REQUEST_FIELDS
    )


@pytest.mark.parametrize(
    "fault",
    [
        "agent",
        "org",
        "backup",
        "reservation",
        "attempt",
        "digest",
        "inventory",
        "profile",
        "provider",
        "protocol",
        "parent",
        "incremental",
        "checkpoint",
        "endpoint",
        "userinfo",
        "redirect-path",
        "bucket",
        "prefix",
        "credential",
        "key",
        "bounds",
        "bool-count",
        "disk",
        "role",
        "duplicate",
        "missing",
        "reordered",
        "exclusion",
        "duplicate-exclusion",
        "encryption",
        "raw-key",
        "extra",
    ],
)
def test_native_whole_envelope_refuses_self_consistent_malicious_plan(fault):
    v = request(EXAMPLES[0])
    p = v["plan"]
    if fault in {"agent", "org", "backup", "reservation"}:
        v[fault + "_id"] = "99999999-9999-4999-8999-999999999999"
    elif fault == "attempt":
        p["attempt_id"] = v["org_id"]
    elif fault == "digest":
        v["plan_sha256"] = "0" * 64
    elif fault == "inventory":
        p["source"]["inventory_sha256"] = "0" * 64
    elif fault in {"profile", "provider", "protocol"}:
        (v if fault == "protocol" else p)[
            "capability_profile" if fault == "profile" else fault
        ] = "future"
    elif fault == "parent":
        p["parent"] = {}
    elif fault == "incremental":
        p["backup_type"] = "incremental"
    elif fault == "checkpoint":
        p["source"]["inventory"]["checkpoint"] = "invented"
        p["source"]["inventory_sha256"] = digest(p["source"]["inventory"])
    elif fault in {"endpoint", "userinfo", "redirect-path"}:
        p["target"]["endpoint"] = {
            "endpoint": "http://example.invalid",
            "userinfo": "https://user@example.invalid",
            "redirect-path": "https://example.invalid/path",
        }[fault]
    elif fault == "bucket":
        p["target"]["bucket"] = "../foreign"
    elif fault == "prefix":
        p["target"]["configuration_prefix"] = "../foreign"
    elif fault == "credential":
        p["credential_ref"] = "caller-controlled"
    elif fault == "key":
        p["artifacts"][0]["key"] += "/foreign"
    elif fault == "bounds":
        p["artifacts"][0]["plaintext_max"] += 1
    elif fault == "bool-count":
        p["artifacts"][0]["plaintext_min"] = False
    elif fault == "disk":
        p["artifacts"][0]["disk_id"] = "guessed"
    elif fault == "role":
        p["artifacts"][0]["role"] = "volume_payload"
    elif fault == "duplicate":
        p["artifacts"].append(deepcopy(p["artifacts"][0]))
    elif fault == "missing":
        p["artifacts"].pop()
    elif fault == "reordered":
        p["artifacts"].reverse()
    elif fault == "exclusion":
        p["exclusions"] = [p["source"]["inventory"]["disks"][0]["target"]]
    elif fault == "duplicate-exclusion":
        p["exclusions"] = ["vdc", "vdc"]
    elif fault == "encryption":
        p["encryption"] = deepcopy(EXAMPLES[1]["encryption"])
    elif fault == "raw-key":
        p["encryption"]["dek"] = "forbidden"
    else:
        p["extra"] = True
    if fault != "digest":
        v["plan_sha256"] = plan_digest(p)
    with pytest.raises((ValueError, StorageOwnershipError)):
        NativeTransactionRequest.model_validate(v)
