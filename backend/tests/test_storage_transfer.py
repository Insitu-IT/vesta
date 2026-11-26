"""Transfer negotiation, strict wire compatibility and shared sizing contract."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_control import part_size
from core.storage_transfer import (
    CAPABILITY,
    refreshed_capabilities,
    select_transfer_profile,
)
from core.storage_wire import (
    TRANSFER_PROFILE_32,
    TransactionRequest,
    TransferPlan,
    plan_digest,
)
from contracts import contracts
from backend.tests.test_storage_wire import request


def test_transfer_plan_preserves_legacy_shape_and_digest():
    legacy = request()
    assert TransactionRequest.model_validate(legacy).model_dump() == legacy
    assert "transfer_profile" not in legacy["plan"]
    current = deepcopy(legacy)
    current["plan"]["transfer_profile"] = TRANSFER_PROFILE_32
    current["plan_sha256"] = plan_digest(current["plan"])
    assert TransactionRequest.model_validate(current).model_dump() == current
    assert current["plan_sha256"] != legacy["plan_sha256"]
    assert set(TransferPlan.model_fields) == contracts.STORAGE_PLAN_FIELDS
    assert contracts.STORAGE_TRANSFER_PROFILES == {TRANSFER_PROFILE_32}
    del current["plan"]["transfer_profile"]
    with pytest.raises(ValueError):
        TransactionRequest.model_validate(current)


@pytest.mark.parametrize(
    "profile", [None, "", "legacy", "kubevirt-64m/1", True, 32, [], {}]
)
def test_explicit_invalid_profile_never_falls_back(profile):
    value = request()
    value["plan"]["transfer_profile"] = profile
    value["plan_sha256"] = plan_digest(value["plan"])
    with pytest.raises(ValueError):
        TransactionRequest.model_validate(value)


def test_shared_part_sizing_vectors():
    path = (
        Path(__file__).resolve().parents[2]
        / "agent/contracts/storage_transfer_vectors.json"
    )
    for vector in json.loads(path.read_text()):
        assert part_size(vector, vector["profile"]) == vector["part_bytes"]
        assert vector["part_bytes"] * 10000 >= vector["ciphertext_max"]
    for maximum in (-1, 1024 * 1024 * 1024 * 10000 + 1, True):
        with pytest.raises(StorageOwnershipError):
            part_size(
                {"ciphertext_max": maximum, "role": "volume_payload"},
                TRANSFER_PROFILE_32,
            )
    with pytest.raises(StorageOwnershipError):
        part_size({"ciphertext_max": 1}, "unknown")


def test_profile_requires_current_agent_advertisement_and_installation_preference(
    monkeypatch,
):
    monkeypatch.setenv("KUBEVIRT_TRANSFER_PROFILE", TRANSFER_PROFILE_32)
    current = {"provider": "kubevirt", CAPABILITY: [TRANSFER_PROFILE_32]}
    agent = SimpleNamespace(capabilities=current)
    assert select_transfer_profile(agent) == TRANSFER_PROFILE_32
    downgraded = refreshed_capabilities(
        current, {"provider": "kubevirt", "incremental": True}
    )
    assert CAPABILITY not in downgraded
    assert CAPABILITY in current
    assert select_transfer_profile(SimpleNamespace(capabilities=downgraded)) is None
    assert CAPABILITY not in refreshed_capabilities(current, {})
    assert (
        select_transfer_profile(
            SimpleNamespace(
                capabilities={"provider": "libvirt", CAPABILITY: [TRANSFER_PROFILE_32]}
            )
        )
        is None
    )
    monkeypatch.setenv("KUBEVIRT_TRANSFER_PROFILE", "legacy")
    assert select_transfer_profile(agent) is None
    monkeypatch.setenv("KUBEVIRT_TRANSFER_PROFILE", "unknown")
    with pytest.raises(StorageOwnershipError):
        select_transfer_profile(agent)


@pytest.mark.parametrize(
    "profiles",
    [
        None,
        "kubevirt-32m/1",
        {},
        [True],
        [TRANSFER_PROFILE_32] * 2,
        [str(n) for n in range(9)],
    ],
)
def test_malformed_agent_advertisement_refuses(profiles):
    with pytest.raises(StorageOwnershipError):
        select_transfer_profile(
            SimpleNamespace(capabilities={"provider": "kubevirt", CAPABILITY: profiles})
        )
