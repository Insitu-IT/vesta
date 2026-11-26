"""Release-bound supply/support receipt; qualification is separate from declarations."""

import copy
import hashlib
import json
from pathlib import Path
import re

SCHEMA = "vesta-supply-contract/1"
DATA = Path(__file__).with_name("supply-contract.json")
IMAGE_KEYS = {"backend", "frontend", "agent"}


def release_fields(metadata):
    """Exactly the outer release metadata bound into the supply receipt."""
    return {
        key: copy.deepcopy(value)
        for key, value in metadata.items()
        if key not in {"images", "supply_contract", "profile"}
    }


def build_contract(profile, metadata):
    """Bind reviewed responsibilities to the exact transported image references."""
    if profile not in {"full", "customer-postgresql"}:
        raise ValueError("Unsupported supply profile")
    document = DATA.read_bytes()
    policy = json.loads(document)
    result = {
        "schema": SCHEMA,
        "profile": profile,
        "policy_sha256": hashlib.sha256(document).hexdigest(),
        "images": copy.deepcopy(metadata["images"]),
        "release": release_fields(metadata),
        "components": copy.deepcopy(policy["profiles"][profile]),
        "qualification": {
            "status": "pending",
            "required": policy["qualification_required"],
        },
        "upstream_rights": policy["upstream_rights"],
        "customer_postgresql": (
            copy.deepcopy(policy["customer_postgresql"])
            if profile == "customer-postgresql"
            else None
        ),
    }
    validate_contract(result, metadata["images"], metadata)
    return result


def validate_contract(contract, supplied_images, metadata):
    """Fail closed on relabelling supplied bytes as customer prerequisites.

    The caller must independently verify the closed OCI graph and file hashes;
    declarations here do not inspect layer contents or prove legal fulfilment.
    """
    policy = json.loads(DATA.read_bytes())
    profile = contract.get("profile")
    expected = IMAGE_KEYS | ({"postgres"} if profile == "full" else set())
    if (
        contract.get("schema") != SCHEMA
        or profile not in {"full", "customer-postgresql"}
        or set(supplied_images) != expected
        or contract.get("images") != supplied_images
        or contract.get("release") != release_fields(metadata)
        or contract.get("components") != policy["profiles"][profile]
        or contract.get("upstream_rights") != policy["upstream_rights"]
        or contract.get("customer_postgresql")
        != (policy["customer_postgresql"] if profile == "customer-postgresql" else None)
        or contract.get("policy_sha256")
        != hashlib.sha256(DATA.read_bytes()).hexdigest()
    ):
        raise ValueError(
            "Supply contract differs from reviewed profile or actual supplied images"
        )
    if any(
        not isinstance(ref, str)
        or not re.fullmatch(r"(?:[^\s@]+@)?sha256:[0-9a-f]{64}", ref)
        for ref in supplied_images.values()
    ):
        raise ValueError("Supply contract requires digest-pinned image origins")
    # An unqualified declaration must never silently become a compliance receipt.
    if contract.get("qualification") != {
        "status": "pending",
        "required": policy["qualification_required"],
    }:
        raise ValueError("Qualification needs separate exact-artifact evidence")
