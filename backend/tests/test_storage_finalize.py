"""Strict native-proof wire controls; persistence evidence lives in PG tests."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from contracts.contracts import STORAGE_FINALIZE_BINDING_FIELDS
from core.s3_ownership import StorageOwnershipError
from core.storage_finalize import validate_binding


def binding_fixture():
    request = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "agent/contracts/storage_semantic_valid.json"
        ).read_text()
    )
    source, parent = request["plan"]["source"], request["plan"]["parent"]
    saved = dict(receipt_sha256="a" * 64, response=dict(acceptance_id="accepted"))
    binding = dict(
        protocol=request["protocol"],
        reservation_id=request["reservation_id"],
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        receipt_sha256=saved["receipt_sha256"],
        acceptance_id="accepted",
        namespace=source["namespace"],
        vm_uid=source["vm_uid"],
        vmi_uid=source["vmi_uid"],
        tracker_name="original-tracker",
        tracker_uid=parent["tracker_uid"] if parent else "original-tracker-uid",
        vmb_name="vnbui-" + request["backup_id"],
        vmb_uid="original-vmb-uid",
        checkpoint="new-checkpoint",
        parent=parent,
        volumes=source["volumes"],
        started_at="2026-09-15T01:00:00Z",
        guest_consistency="unknown",
        guest_evidence_source="kubevirt/VMB.status.conditions",
    )
    return request, saved, binding


def test_finalize_binding_matches_generated_go_wire_and_requires_every_field():
    request, saved, binding = binding_fixture()
    assert set(binding) == STORAGE_FINALIZE_BINDING_FIELDS
    validate_binding(binding, request, saved)
    for key in binding:
        missing = deepcopy(binding)
        del missing[key]
        with pytest.raises(StorageOwnershipError):
            validate_binding(missing, request, saved)
    with pytest.raises(StorageOwnershipError):
        validate_binding(dict(binding, private="not-accepted"), request, saved)


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", "foreign"),
        ("plan_sha256", "b" * 64),
        ("receipt_sha256", "b" * 64),
        ("acceptance_id", "unaccepted"),
        ("volumes", []),
        ("vmb_name", "replacement"),
        ("tracker_uid", "x/other"),
        ("checkpoint", ""),
        ("started_at", "2026-09-15"),
        ("guest_consistency", "requested-quiesce"),
        ("guest_evidence_source", "request"),
    ],
)
def test_finalize_binding_rejects_unbound_or_inferred_evidence(field, value):
    request, saved, binding = binding_fixture()
    binding[field] = value
    with pytest.raises(StorageOwnershipError):
        validate_binding(binding, request, saved)


@pytest.mark.parametrize(
    "configured,accepted",
    [(None, "vnbui"), ("", "vnbui"), ("vnbui", "vnbui"), ("vesta", "vesta")],
)
def test_finalize_binding_requires_exact_installation_resource_prefix(
    monkeypatch, configured, accepted
):
    if configured is None:
        monkeypatch.delenv("KUBEVIRT_RESOURCE_PREFIX", raising=False)
    else:
        monkeypatch.setenv("KUBEVIRT_RESOURCE_PREFIX", configured)
    request, saved, binding = binding_fixture()
    binding["vmb_name"] = accepted + "-" + request["backup_id"]
    validate_binding(binding, request, saved)
    for other in {"vnbui", "vesta", "unrelated"} - {accepted}:
        with pytest.raises(StorageOwnershipError):
            validate_binding(
                dict(binding, vmb_name=other + "-" + request["backup_id"]),
                request,
                saved,
            )


@pytest.mark.parametrize("prefix", ["Vesta", "vesta-", " vesta", "other"])
def test_finalize_binding_invalid_installation_prefix_refuses(monkeypatch, prefix):
    monkeypatch.setenv("KUBEVIRT_RESOURCE_PREFIX", prefix)
    request, saved, binding = binding_fixture()
    with pytest.raises(StorageOwnershipError):
        validate_binding(binding, request, saved)
