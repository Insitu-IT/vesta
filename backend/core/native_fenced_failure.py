"""Validate failed-only fenced output against the committed producer execution.

This wire validator neither establishes a kernel fence nor releases capacity.
The authenticated agent must inspect the current kernel protection before
submission; the settlement transaction must independently enforce DB custody.
"""

import hashlib
import json
import re

from core.native_inventory import digest, exact, refuse
from core.storage_receipt_v2 import canonical

HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_PROOF_BYTES = 128 * 1024


def _hash(value):
    if type(value) is not str or HASH.fullmatch(value) is None:
        refuse()


def _identity(value):
    if (
        type(value) is not list
        or len(value) != 2
        or any(type(n) is not int or not 0 <= n < 2**64 for n in value)
        or value[1] == 0
    ):
        refuse()
    return tuple(value)


def validate(value, intent, execution):
    """Return only canonical original-output proof, never success/no-effect."""
    exact(
        value, {"intent_canonical", "intent_sha256", "fence_canonical", "fence_sha256"}
    )
    if (
        any(type(v) is not str for v in value.values())
        or len(value["fence_canonical"].encode()) > MAX_PROOF_BYTES
        or len(value["intent_canonical"].encode()) > MAX_PROOF_BYTES
        or value["intent_canonical"] != canonical(intent).decode()
        or value["intent_sha256"] != digest(intent)
    ):
        refuse()
    _hash(value["fence_sha256"])
    if (
        hashlib.sha256(value["fence_canonical"].encode()).hexdigest()
        != value["fence_sha256"]
    ):
        refuse()
    exact(
        execution,
        {
            "schema",
            "state",
            "request_sha256",
            "intent_sha256",
            "intent_canonical",
            "bound_xid",
        },
    )
    if (
        type(execution["schema"]) is not int
        or execution["schema"] != 1
        or execution["state"] != "bound"
        or type(execution["bound_xid"]) is not int
        or execution["bound_xid"] <= 0
        or execution["intent_sha256"] != value["intent_sha256"]
        or execution["intent_canonical"] != value["intent_canonical"]
    ):
        refuse()
    _hash(execution["request_sha256"])
    try:
        proof = json.loads(value["fence_canonical"])
        if canonical(proof).decode() != value["fence_canonical"]:
            refuse()
        exact(
            proof,
            {
                "schema",
                "request_sha256",
                "target_binding_sha256",
                "artifacts",
                "directory",
                "data_directory",
            },
        )
        if (
            proof["schema"] != "libvirt-failed-output-fence/1"
            or proof["request_sha256"] != execution["request_sha256"]
        ):
            refuse()
        _hash(proof["target_binding_sha256"])
        directory, data = _identity(proof["directory"]), _identity(
            proof["data_directory"]
        )
        if directory == data or directory[0] != data[0]:
            refuse()
        selected = sorted(
            d["target"]
            for d in intent["source"]["disks"]
            if d["target"] not in intent["source"]["exclusions"]
        )
        artifacts = proof["artifacts"]
        if (
            type(artifacts) is not list
            or not 0 < len(artifacts) == len(selected) <= 128
        ):
            refuse()
        seen = {directory, data}
        for target, artifact in zip(selected, artifacts):
            exact(artifact, {"target", "device", "inode", "size", "verity_sha256"})
            identity = _identity([artifact["device"], artifact["inode"]])
            if (
                artifact["target"] != target
                or identity in seen
                or identity[0] != data[0]
                or type(artifact["size"]) is not int
                or not 0 <= artifact["size"] < 2**63
            ):
                refuse()
            _hash(artifact["verity_sha256"])
            seen.add(identity)
    except (ValueError, TypeError, KeyError, RecursionError):
        refuse()
    return proof


def settle(db, backup_id, agent_id, value, credential):
    """Atomically fail/release original custody, without human re-admission."""
    from core.storage_attempt_key import _credential
    from models import Backup, Organization, S3Publication, StorageLineageGeneration, VM

    try:
        initial = db.query(Backup).filter_by(id=backup_id).one_or_none()
        if initial is None:
            refuse()
        db.query(Organization).filter_by(id=initial.org_id).with_for_update().one()
        vm = (
            db.query(VM)
            .filter_by(id=initial.vm_id, org_id=initial.org_id)
            .with_for_update()
            .one()
        )
        backup = (
            db.query(Backup)
            .filter_by(id=backup_id, org_id=initial.org_id)
            .populate_existing()
            .with_for_update()
            .one()
        )
        _credential(db, agent_id, credential)
        intent = backup.native_job_intent
        if (
            vm.provider != "libvirt"
            or vm.agent_id != agent_id
            or type(intent) is not dict
            or intent.get("agent_id") != agent_id
            or intent.get("org_id") != backup.org_id
            or intent.get("backup_id") != backup.id
            or intent.get("producer") != "libvirt-push-qcow2/1"
            or not backup.native_job_transaction_id
            or backup.native_no_effect is not None
            or backup.native_closed_failure is not None
            or backup.native_inventory is not None
            or backup.wrapped_dek is not None
            or db.query(S3Publication.id).filter_by(backup_id=backup.id).first()
            or db.query(StorageLineageGeneration.id)
            .filter_by(backup_id=backup.id)
            .first()
        ):
            refuse()
        validate(value, intent, backup.native_execution)
        if backup.native_fenced_failure is not None:
            if (
                backup.native_fenced_failure != value
                or backup.status != "failed"
                or backup.capacity_state != "released"
            ):
                refuse()
        else:
            if backup.capacity_state != "reserved" or backup.status not in {
                "pending",
                "running",
                "cleanup_required",
                "failed",
            }:
                refuse()
            backup.native_fenced_failure = value
            db.flush()
            db.refresh(backup)
        if (
            backup.status != "failed"
            or backup.capacity_state != "released"
            or type(backup.native_fenced_failure_xid) is not int
            or backup.native_fenced_failure_xid <= backup.native_execution["bound_xid"]
        ):
            refuse()
        result = dict(
            settled=True,
            attempt_id=intent["attempt_id"],
            intent_sha256=value["intent_sha256"],
            fence_sha256=value["fence_sha256"],
            capacity_id=str(backup.capacity_id),
        )
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
