"""Positive failed-writer closure; never a producer seal or no-effect claim."""

import json
import re

from core.native_inventory import digest, exact, refuse
from core.storage_receipt_v2 import canonical
from core.storage_attempt_key import _credential
from models import Backup, Organization, S3Publication, VM

HASH = re.compile(r"[0-9a-f]{64}\Z")
INVOCATION = re.compile(r"[0-9a-f]{32}\Z")
JOB = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,511}\Z")
TRANSITIONS = {
    None: {"created"},
    "created": {"running", "aborting"},
    "running": {"paused", "waiting", "pending", "aborting", "concluded"},
    "paused": {"running", "aborting"},
    "waiting": {"pending", "aborting", "concluded"},
    "pending": {"aborting", "concluded"},
    "aborting": {"concluded"},
    "concluded": {"null"},
    "null": set(),
}


def validate_certificate(closure, intent):
    exact(
        closure,
        {
            "schema",
            "request_sha256",
            "backup_id",
            "attempt_id",
            "domain_uuid",
            "invocation_id",
            "begin_ack_sha256",
            "job_ids",
            "terminal_events",
            "artifacts",
        },
    )
    if (
        closure["schema"] != "libvirt-closed-failure/1"
        or closure["backup_id"] != intent["backup_id"]
        or closure["attempt_id"] != intent["attempt_id"]
        or closure["domain_uuid"] != intent["source"]["domain_uuid"]
        or any(
            type(closure[k]) is not str or HASH.fullmatch(closure[k]) is None
            for k in ("request_sha256", "begin_ack_sha256")
        )
        or type(closure["invocation_id"]) is not str
        or INVOCATION.fullmatch(closure["invocation_id"]) is None
        or len(canonical(closure)) > 4 * 1024 * 1024
    ):
        refuse()
    selected = {
        d["target"]
        for d in intent["source"]["disks"]
        if d["target"] not in intent["source"]["exclusions"]
    }
    jobs, events, artifacts = (
        closure[k] for k in ("job_ids", "terminal_events", "artifacts")
    )
    if (
        type(jobs) is not list
        or not 0 < len(jobs) == len(selected) <= 128
        or any(type(j) is not str or JOB.fullmatch(j) is None for j in jobs)
        or jobs != sorted(set(jobs))
        or type(events) is not list
        or not 0 < len(events) <= 8192
        or type(artifacts) is not list
        or len(artifacts) != len(selected)
    ):
        refuse()
    states = {job: None for job in jobs}
    for event in events:
        exact(event, {"id", "status"})
        if (
            type(event["id"]) is not str
            or event["id"] not in states
            or type(event["status"]) is not str
            or event["status"] not in TRANSITIONS[states[event["id"]]]
        ):
            refuse()
        states[event["id"]] = event["status"]
    if any(state != "null" for state in states.values()):
        refuse()
    seen = set()
    for artifact in artifacts:
        exact(artifact, {"path", "device", "inode", "size", "mtime_ns", "ctime_ns"})
        if (
            type(artifact["path"]) is not str
            or artifact["path"] in seen
            or artifact["path"] not in {name + ".qcow2" for name in selected}
            or any(
                type(artifact[k]) is not int or not 0 <= artifact[k] < 2**64
                for k in ("device", "inode")
            )
            or artifact["inode"] == 0
            or any(
                type(artifact[k]) is not int or not 0 <= artifact[k] < 2**63
                for k in ("size", "mtime_ns", "ctime_ns")
            )
        ):
            refuse()
        seen.add(artifact["path"])


def validate(value, intent):
    exact(
        value,
        {"intent_canonical", "intent_sha256", "closure_canonical", "closure_sha256"},
    )
    if (
        any(type(v) is not str for v in value.values())
        or value["intent_canonical"] != canonical(intent).decode()
        or value["intent_sha256"] != digest(intent)
        or value["closure_sha256"] != digest_text(value["closure_canonical"])
    ):
        refuse()
    try:
        closure = json.loads(value["closure_canonical"])
        if canonical(closure).decode() != value["closure_canonical"]:
            refuse()
        validate_certificate(closure, intent)
    except (ValueError, TypeError, KeyError, RecursionError):
        refuse()
    return closure


def digest_text(value):
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()


def settle(db, backup_id, agent_id, value, credential):
    """Release original capacity only; retain failed output and original intent."""
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
            or backup.native_inventory is not None
            or backup.wrapped_dek is not None
            or db.query(S3Publication.id).filter_by(backup_id=backup.id).first()
        ):
            refuse()
        validate(value, intent)
        if backup.native_closed_failure is not None:
            if (
                backup.native_closed_failure != value
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
            backup.native_closed_failure = value
            db.flush()  # Database validates custody and releases atomically.
            db.refresh(backup)
            if backup.status != "failed" or backup.capacity_state != "released":
                refuse()
        response = dict(
            settled=True,
            attempt_id=intent["attempt_id"],
            intent_sha256=value["intent_sha256"],
            closure_sha256=value["closure_sha256"],
            capacity_id=str(backup.capacity_id),
        )
        db.commit()
        return response
    except Exception:
        db.rollback()
        raise
