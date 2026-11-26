"""Exact native hold observations are display metadata, never effect authority."""

from core.native_inventory import digest
from models import Backup


def observe_native_hold(db, agent, event):
    """Retain a bounded, credential-free observation without changing custody.

    Repeated heartbeats repair lost delivery. A locked row is skipped for the
    next heartbeat; it must not stall agent health behind producer admission.
    No original human/grant admission is needed to *observe* a retained hold,
    including after revocation. Every actual resume still requires admission.
    """
    if (
        type(event) is not dict
        or set(event)
        != {"type", "schema", "backup_id", "attempt_id", "intent_sha256", "reason"}
        or event["type"] != "native_attempt_held"
        or type(event["schema"]) is not int
        or event["schema"] != 1
        or any(
            type(event[k]) is not str or not 0 < len(event[k]) <= 128
            for k in ("backup_id", "attempt_id", "intent_sha256", "reason")
        )
        or event["reason"] not in {"native_attempt_retained", "native_upload_held"}
    ):
        return False
    row = (
        db.query(Backup)
        .filter_by(
            id=event["backup_id"], org_id=agent.org_id, capacity_state="reserved"
        )
        .filter(Backup.status.in_(("pending", "running", "uploading")))
        .populate_existing()
        .with_for_update(skip_locked=True)
        .one_or_none()
    )
    if row is None:
        return False
    intent = row.native_job_intent
    if (
        type(intent) is not dict
        or intent.get("producer") != "libvirt-push-qcow2/1"
        or intent.get("backup_id") != row.id
        or intent.get("org_id") != row.org_id
        or intent.get("agent_id") != agent.id
        or intent.get("attempt_id") != event["attempt_id"]
        or digest(intent) != event["intent_sha256"]
    ):
        return False
    observation = {
        k: event[k] for k in ("schema", "attempt_id", "intent_sha256", "reason")
    }
    tags = dict(row.tags or {})
    if tags.get("native_hold") == observation:
        return False
    tags["native_hold"] = observation
    row.tags = tags
    return True
