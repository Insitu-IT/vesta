"""Settle only an authenticated original agent's durable pre-begin refusal.

This is negative evidence: no original human/grant readmission, provider I/O,
new producer or cleanup. The database owns terminal state and capacity release.
"""

import json
import re

from core.native_inventory import digest, exact, refuse
from core.storage_receipt_v2 import canonical
from core.storage_attempt_key import _credential
from models import Backup, Organization, S3Publication, VM

HASH = re.compile(r"[0-9a-f]{64}\Z")


def validate(value, intent):
    exact(
        value,
        {"intent_canonical", "intent_sha256", "refusal_canonical", "refusal_sha256"},
    )
    if any(type(v) is not str for v in value.values()):
        refuse()
    if any(
        HASH.fullmatch(value[k]) is None for k in ("intent_sha256", "refusal_sha256")
    ):
        refuse()
    if value["intent_canonical"] != canonical(intent).decode() or value[
        "intent_sha256"
    ] != digest(intent):
        refuse()
    try:
        refusal = json.loads(value["refusal_canonical"])
    except (ValueError, TypeError, RecursionError):
        refuse()
    exact(
        refusal,
        {
            "schema",
            "request_sha256",
            "backup_id",
            "attempt_id",
            "domain_uuid",
            "reason",
        },
    )
    if (
        canonical(refusal).decode() != value["refusal_canonical"]
        or digest(refusal) != value["refusal_sha256"]
        or refusal["schema"] != "libvirt-prebegin-refusal/1"
        or refusal["backup_id"] != intent["backup_id"]
        or refusal["attempt_id"] != intent["attempt_id"]
        or refusal["domain_uuid"] != intent["source"]["domain_uuid"]
        or type(refusal["request_sha256"]) is not str
        or HASH.fullmatch(refusal["request_sha256"]) is None
        or type(refusal["reason"]) is not str
        or not 0 < len(refusal["reason"]) <= 2048
    ):
        refuse()


def settle(db, backup_id, agent_id, value, credential):
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
            or backup.native_closed_failure is not None
            or backup.native_inventory is not None
            or backup.wrapped_dek is not None
            or db.query(S3Publication.id).filter_by(backup_id=backup.id).first()
        ):
            refuse()
        validate(value, intent)
        if backup.native_no_effect is not None:
            if (
                backup.native_no_effect != value
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
            backup.native_no_effect = value
            db.flush()  # The database guard sets failed/released atomically.
            db.refresh(backup)
            if backup.status != "failed" or backup.capacity_state != "released":
                refuse()
        response = dict(
            settled=True,
            attempt_id=intent["attempt_id"],
            intent_sha256=value["intent_sha256"],
            refusal_sha256=value["refusal_sha256"],
            capacity_id=str(backup.capacity_id),
        )
        db.commit()
        return response
    except Exception:
        db.rollback()
        raise
