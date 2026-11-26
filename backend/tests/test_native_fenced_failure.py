"""Fenced failure proof is exact original execution custody, not backup data."""

from copy import deepcopy

import pytest

from core.native_fenced_failure import validate
from core.native_inventory import digest
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical


def specimen():
    intent = dict(
        backup_id="backup",
        attempt_id="attempt",
        source=dict(
            disks=[dict(target="vda"), dict(target="vdb"), dict(target="vdc")],
            exclusions=["vdc"],
        ),
    )
    execution = dict(
        schema=1,
        state="bound",
        request_sha256="a" * 64,
        intent_sha256=digest(intent),
        intent_canonical=canonical(intent).decode(),
        bound_xid=12,
    )
    proof = dict(
        schema="libvirt-failed-output-fence/1",
        request_sha256="a" * 64,
        target_binding_sha256="b" * 64,
        directory=[10, 1],
        data_directory=[10, 2],
        artifacts=[
            dict(target=target, device=10, inode=n, size=4096, verity_sha256="c" * 64)
            for n, target in enumerate(["vda", "vdb"], 3)
        ],
    )
    return intent, execution, proof


@pytest.mark.parametrize(
    "xid,binding,allowed",
    [
        (None, None, True),
        (10, None, False),
        (10, dict(state="bound", bound_xid=9), False),
        (10, dict(state="bound", bound_xid=10), False),
        (10, dict(state="bound", bound_xid=11), True),
        (10, dict(state="bound", bound_xid=True), False),
        (10, dict(state="preexisting", boundary_xid=11), False),
    ],
)
def test_incremental_parent_must_follow_committed_fence(xid, binding, allowed):
    from types import SimpleNamespace
    from core.native_lineage import require_parent_after_fence

    parent = SimpleNamespace(native_execution=binding)
    if allowed:
        require_parent_after_fence(parent, xid)
    else:
        with pytest.raises(StorageOwnershipError):
            require_parent_after_fence(parent, xid)


def wire(intent, proof):
    return dict(
        intent_canonical=canonical(intent).decode(),
        intent_sha256=digest(intent),
        fence_canonical=canonical(proof).decode(),
        fence_sha256=digest(proof),
    )


def test_original_canonical_fence_is_read_only_and_failed_only():
    intent, execution, proof = specimen()
    before = deepcopy((intent, execution, proof))
    assert validate(wire(intent, proof), intent, execution) == proof
    assert (intent, execution, proof) == before


def test_supported_128_disk_proof_and_numeric_boundaries():
    intent, execution, proof = specimen()
    targets = [f"vd{n:03}" for n in range(128)]
    intent["source"] = dict(disks=[dict(target=t) for t in targets], exclusions=[])
    execution.update(
        intent_canonical=canonical(intent).decode(), intent_sha256=digest(intent)
    )
    proof["directory"] = [2**64 - 1, 1]
    proof["data_directory"] = [2**64 - 1, 2]
    proof["artifacts"] = [
        dict(
            target=t,
            device=2**64 - 1,
            inode=n + 3,
            size=0 if n == 0 else 2**63 - 1,
            verity_sha256="c" * 64,
        )
        for n, t in enumerate(targets)
    ]
    assert validate(wire(intent, proof), intent, execution) == proof


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "request",
        "binding",
        "directory-bool",
        "directory-zero",
        "same-directory",
        "cross-device-directory",
        "directory-extra",
        "missing-disk",
        "excluded-disk",
        "order",
        "duplicate-inode",
        "directory-as-file",
        "file-bool",
        "file-zero",
        "cross-device-file",
        "negative-size",
        "huge-size",
        "bool-size",
        "verity",
        "artifact-extra",
        "proof-extra",
        "job-absence",
        "success",
    ],
)
def test_rehashed_invalid_proofs_are_refused(fault):
    intent, execution, proof = specimen()
    artifact = proof["artifacts"][0]
    if fault in {"schema", "request", "binding"}:
        proof[
            {"request": "request_sha256", "binding": "target_binding_sha256"}.get(
                fault, fault
            )
        ] = "wrong"
    elif fault == "directory-bool":
        proof["directory"][1] = True
    elif fault == "directory-zero":
        proof["directory"][1] = 0
    elif fault == "same-directory":
        proof["data_directory"] = proof["directory"]
    elif fault == "cross-device-directory":
        proof["data_directory"][0] = 11
    elif fault == "directory-extra":
        proof["directory"].append(3)
    elif fault == "missing-disk":
        proof["artifacts"].pop()
    elif fault == "excluded-disk":
        artifact["target"] = "vdc"
    elif fault == "order":
        proof["artifacts"].reverse()
    elif fault == "duplicate-inode":
        artifact["inode"] = 4
    elif fault == "directory-as-file":
        artifact["inode"] = 1
    elif fault == "file-bool":
        artifact["inode"] = True
    elif fault == "file-zero":
        artifact["inode"] = 0
    elif fault == "cross-device-file":
        artifact["device"] = 11
    elif fault == "negative-size":
        artifact["size"] = -1
    elif fault == "huge-size":
        artifact["size"] = 2**63
    elif fault == "bool-size":
        artifact["size"] = True
    elif fault == "verity":
        artifact["verity_sha256"] = "C" * 64
    elif fault == "artifact-extra":
        artifact["closed"] = True
    else:
        proof[fault] = True
    with pytest.raises(StorageOwnershipError):
        validate(wire(intent, proof), intent, execution)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "preexisting",
        "schema-bool",
        "xid-bool",
        "xid-zero",
        "request",
        "intent",
        "canonical",
        "extra",
    ],
)
def test_fence_cannot_adopt_unbound_or_different_execution(fault):
    intent, execution, proof = specimen()
    if fault == "missing":
        execution = None
    elif fault == "preexisting":
        execution = dict(schema=1, state="preexisting", boundary_xid=10)
    elif fault == "schema-bool":
        execution["schema"] = True
    elif fault == "xid-bool":
        execution["bound_xid"] = True
    elif fault == "xid-zero":
        execution["bound_xid"] = 0
    elif fault == "request":
        execution["request_sha256"] = "d" * 64
    elif fault == "intent":
        execution["intent_sha256"] = "d" * 64
    elif fault == "canonical":
        execution["intent_canonical"] += " "
    else:
        execution["extra"] = True
    with pytest.raises(StorageOwnershipError):
        validate(wire(intent, proof), intent, execution)


@pytest.mark.parametrize(
    "fault",
    ["whitespace", "duplicate-key", "wrong-hash", "oversized", "extra-envelope"],
)
def test_noncanonical_or_unbound_wire_is_refused(fault):
    import hashlib

    intent, execution, proof = specimen()
    value = wire(intent, proof)
    if fault == "whitespace":
        value["fence_canonical"] += " "
    elif fault == "duplicate-key":
        value["fence_canonical"] = '{"schema":"ignored",' + value["fence_canonical"][1:]
    elif fault == "wrong-hash":
        value["fence_sha256"] = "d" * 64
    elif fault == "oversized":
        value["fence_canonical"] += " " * (128 * 1024)
    else:
        value["success"] = True
    if fault != "wrong-hash":
        value["fence_sha256"] = hashlib.sha256(
            value["fence_canonical"].encode()
        ).hexdigest()
    with pytest.raises(StorageOwnershipError):
        validate(value, intent, execution)
