"""Exact transaction telemetry; no publication, cleanup or release authority."""

from datetime import datetime

from models import Backup, S3Publication


def observe_storage_progress(db, agent, event):
    fields = {
        "type",
        "schema",
        "backup_id",
        "reservation_id",
        "plan_sha256",
        "phase",
        "bytes_transferred",
        "total_bytes",
    }
    phases = {"pending": 0, "preparing": 1, "uploading": 2, "finalizing": 3}
    if (
        type(event) is not dict
        or set(event) != fields
        or event["type"] != "storage_transaction_progress"
        or type(event["schema"]) is not int
        or event["schema"] != 1
        or any(
            type(event[k]) is not str or not 0 < len(event[k]) <= 128
            for k in ("backup_id", "reservation_id", "plan_sha256", "phase")
        )
        or event["phase"] not in phases
        or type(event["bytes_transferred"]) is not int
        or type(event["total_bytes"]) is not int
        or not 0 <= event["bytes_transferred"] <= event["total_bytes"] <= 2**63 - 1
    ):
        return False
    # The same lock order as hold/publication. Missing or contended custody
    # skips this observation and the next heartbeat repeats it.
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
    claim = (
        db.query(S3Publication)
        .filter_by(
            id=event["reservation_id"],
            backup_id=row.id,
            org_id=agent.org_id,
            kind="payload",
        )
        .populate_existing()
        .with_for_update(skip_locked=True)
        .one_or_none()
    )
    if claim is None or claim.state != "reserved":
        return False
    expected = claim.expected_plan
    request = (
        expected.get("transaction")
        if type(expected) is dict and expected.get("schema") == 3
        else None
    )
    if (
        type(request) is not dict
        or request.get("backup_id") != row.id
        or request.get("org_id") != row.org_id
        or request.get("agent_id") != agent.id
        or request.get("reservation_id") != claim.id
        or request.get("plan_sha256") != event["plan_sha256"]
        or type(request.get("plan")) is not dict
        or request["plan"].get("provider") != "kubevirt"
    ):
        return False
    artifacts = request["plan"].get("artifacts")
    if type(artifacts) is not list or not artifacts:
        return False
    maximum = 0
    for artifact in artifacts:
        if type(artifact) is not dict:
            return False
        if artifact.get("role") == "volume_payload":
            size = artifact.get("ciphertext_max")
            if type(size) is not int or size < 0:
                return False
            maximum += size
    if event["total_bytes"] > maximum:
        return False
    previous = row.storage_progress or {}
    if type(previous) is not dict:
        return False
    if previous and (
        previous.get("reservation_id") != claim.id
        or previous.get("plan_sha256") != event["plan_sha256"]
        or event["bytes_transferred"] < previous.get("bytes_transferred", 0)
        or (
            previous.get("total_bytes", 0) > 0
            and event["total_bytes"] != previous["total_bytes"]
        )
        or phases[event["phase"]] < phases.get(previous.get("phase"), 0)
    ):
        return False
    observation = {k: event[k] for k in fields - {"type", "backup_id"}}
    # Preserve meaningful change time on repeats; do not rewrite JSON every
    # heartbeat for an unchanged snapshot. Old observations cannot regress it.
    if previous and all(previous.get(k) == v for k, v in observation.items()):
        return False
    observation["updated_at"] = datetime.utcnow().isoformat() + "Z"
    row.storage_progress = observation
    total = event["total_bytes"]
    row.progress = min(99, 100 * event["bytes_transferred"] // total) if total else 0
    # Keep the lifecycle states accepted by the publication transaction. A
    # missing final heartbeat must never prevent publication after uploading.
    row.status = "pending" if event["phase"] == "pending" else "running"
    return {
        "backup_id": row.id,
        "status": row.status,
        "progress": row.progress,
        "phase": event["phase"],
        "bytes_transferred": event["bytes_transferred"],
        "total_bytes": total,
    }
