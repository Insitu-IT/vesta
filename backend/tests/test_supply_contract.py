"""Reviewed support declarations cannot contradict transported image inventory."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "supply_contract", ROOT / "packaging/okd/supply_contract.py"
)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def images(full=False):
    return {
        key: "sha256:" + "a" * 64
        for key in ["backend", "frontend", "agent"] + (["postgres"] if full else [])
    }


@pytest.mark.parametrize("profile", ["full", "customer-postgresql"])
def test_binds_exact_inventory_and_preserves_source_release(profile):
    inventory = images(profile == "full")
    receipt = contract.build_contract(
        profile,
        {
            "images": inventory,
            "runtime_source": "abc",
            "supply_contract": {"old": True},
        },
    )
    contract.validate_contract(
        receipt, inventory, {"images": inventory, "runtime_source": "abc"}
    )
    assert receipt["release"] == {"runtime_source": "abc"}
    assert receipt["qualification"]["status"] == "pending"
    assert "never restrict upstream" in receipt["upstream_rights"]
    changed = copy.deepcopy(inventory)
    changed["agent"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError):
        contract.validate_contract(
            receipt, changed, {"images": changed, "runtime_source": "abc"}
        )


def test_customer_profile_refuses_supplied_database_or_retained_image():
    with pytest.raises(ValueError):
        contract.build_contract("customer-postgresql", {"images": images(True)})
    inventory = images()
    inventory["hidden"] = "sha256:" + "a" * 64
    with pytest.raises(ValueError):
        contract.build_contract("customer-postgresql", {"images": inventory})


@pytest.mark.parametrize(
    "field,value",
    [
        ("qualification", {"status": "complete"}),
        ("components", []),
        ("policy_sha256", "a" * 64),
    ],
)
def test_refuses_unreviewed_terms_or_false_qualification(field, value):
    receipt = contract.build_contract("full", {"images": images(True)})
    receipt[field] = value
    with pytest.raises(ValueError):
        contract.validate_contract(receipt, images(True), {"images": images(True)})


def test_native_prerequisites_match_both_rpm_dependency_declarations():
    policy = json.loads(contract.DATA.read_text())
    native = policy["profiles"]["native-rpm"]
    assert native[0]["supplier"] == "S2"
    assert native[1]["supplier"] == "customer"
    for name in ("vesta-agent.spec", "vesta-agent-prebuilt.spec"):
        spec = (ROOT / "packaging/rpm" / name).read_text()
        for dependency in (
            "libvirt-daemon",
            "libvirt-daemon-driver-qemu",
            "python3-libvirt",
            "qemu-img",
            "acl",
            "polkit",
            "systemd",
            "python3",
        ):
            assert any(
                line.startswith("Requires:") and line.split()[1] == dependency
                for line in spec.splitlines()
            )


@pytest.mark.parametrize(
    "field",
    ["runtime_source", "source_revision", "runtime_version", "installer_revision"],
)
def test_release_receipt_refuses_contradictory_outer_or_inner_metadata(field):
    metadata = {
        "images": images(True),
        "runtime_source": "source-a",
        "source_revision": "installer-a",
        "runtime_version": "6.0.73",
        "installer_revision": "install9",
    }
    receipt = contract.build_contract("full", metadata)
    changed = copy.deepcopy(metadata)
    changed[field] = "contradictory"
    with pytest.raises(ValueError):
        contract.validate_contract(receipt, metadata["images"], changed)
    receipt["release"][field] = "contradictory"
    with pytest.raises(ValueError):
        contract.validate_contract(receipt, metadata["images"], metadata)
