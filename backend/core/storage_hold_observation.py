"""Exact retained storage transactions can report a hold, never release custody."""

from datetime import datetime
import re

from models import Backup, S3Publication

SAFETY_WORDS = {
    "stage",
    "reason",
    "native_stop_phase",
    "observation_reason",
    "read_observation_reason",
}
SAFETY_TIMES = {
    "started_at",
    "last_progress_at",
    "deadline",
    "producer_deadline",
    "first_byte_at",
    "first_ack_at",
    "stop_at",
    "scratch_sample_at",
    "observation_uncertain_since",
    "observation_deadline",
    "last_trustworthy_observation_at",
    "read_observation_uncertain_since",
    "read_observation_deadline",
}
SAFETY_COUNTS = {
    "http_status",
    "native_stop_http_status",
    "volume",
    "page",
    "offset",
    "raw_ranges",
    "stored_ranges",
    "acknowledged_bytes",
    "no_progress_budget_seconds",
    "no_progress_seconds",
    "run_budget_seconds",
    "estimated_bytes",
    "estimated_bytes_per_second",
    "last_map_volume",
    "last_map_page",
    "last_map_offset",
    "last_map_raw_ranges",
    "last_map_stored_ranges",
    "scratch_required_bytes",
    "scratch_available_bytes",
    "scratch_peak_growth_bytes_per_second",
    "scratch_time_to_full_seconds",
    "expected_native_volumes",
    "observed_native_volumes",
    "observed_export_links",
}


def valid_safety_diagnostic(value):
    """Small negative observations only; no remote text, URLs or credentials."""
    if type(value) is not dict or not {"stage", "reason", "disposition"} <= set(value):
        return False
    if set(value) - SAFETY_WORDS - SAFETY_TIMES - SAFETY_COUNTS - {"disposition"}:
        return False
    if type(value["disposition"]) is not str or value["disposition"] not in {
        "refused",
        "transient",
        "uncertain",
    }:
        return False
    for key, item in value.items():
        if key in SAFETY_WORDS and (
            type(item) is not str or not re.fullmatch(r"[a-z][a-z_]{0,79}", item)
        ):
            return False
        if key in SAFETY_COUNTS and (type(item) is not int or not 0 <= item < 2**63):
            return False
        if key in SAFETY_TIMES:
            if (
                type(item) is not str
                or not 20 <= len(item) <= 35
                or not item.endswith("Z")
            ):
                return False
            try:
                datetime.fromisoformat(item.replace("Z", "+00:00"))
            except ValueError:
                return False
    for key in ("http_status", "native_stop_http_status"):
        if key in value and not 100 <= value[key] <= 599:
            return False
    return True


def public_safety_diagnostic(backup):
    """Bounded observations only; never a release or retry permission."""
    if backup.status not in {"cleanup_required", "failed"}:
        return None
    tags = backup.tags
    # SQLAlchemy wraps the persisted tags column in MutableDict. Keep the
    # diagnostic's strict wire validation below, but accept its ORM container.
    hold = tags.get("storage_hold") if isinstance(tags, dict) else None
    if type(hold) is not dict or hold.get("schema") != 2:
        return None
    diagnostic = hold.get("diagnostic")
    return dict(diagnostic) if valid_safety_diagnostic(diagnostic) else None


def observe_storage_hold(db, agent, event):
    if (
        type(event) is not dict
        or set(event)
        != (
            {"type", "schema", "backup_id", "reservation_id", "plan_sha256", "reason"}
            | ({"diagnostic"} if event.get("schema") == 2 else set())
        )
        or event["type"] != "storage_transaction_held"
        or type(event["schema"]) is not int
        or event["schema"] not in (1, 2)
        or (
            event["schema"] == 2
            and not valid_safety_diagnostic(event.get("diagnostic"))
        )
        or any(
            type(event[k]) is not str or not 0 < len(event[k]) <= 128
            for k in ("backup_id", "reservation_id", "plan_sha256", "reason")
        )
        or event["reason"] != "storage_transaction_retained"
    ):
        return False
    # A negative observation remains useful after human/grant revocation. It
    # grants no effect authority. Skip contended rows; a future heartbeat retries.
    row = (
        db.query(Backup)
        .filter_by(
            id=event["backup_id"], org_id=agent.org_id, capacity_state="reserved"
        )
        .filter(
            Backup.status.in_(("pending", "running", "uploading", "cleanup_required"))
        )
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
    if claim is None or claim.state not in {"reserved", "cleanup_required"}:
        return False
    plan = claim.expected_plan
    request = (
        plan.get("transaction")
        if type(plan) is dict and plan.get("schema") == 3
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
    observation = {
        k: event[k] for k in ("schema", "reservation_id", "plan_sha256", "reason")
    }
    if event["schema"] == 2:
        observation["diagnostic"] = dict(event["diagnostic"])
    tags = dict(row.tags or {})
    if row.status == "cleanup_required" and tags.get("storage_hold") == observation:
        return False
    tags["storage_hold"] = observation
    tags["cleanup_required"] = True
    tags.setdefault(
        "error", "Agent retained this storage transaction for reconciliation"
    )
    if event["schema"] == 2:
        d = event["diagnostic"]
        tags["error"] = (
            f"Backup stopped during {d['stage']}: {d['reason']}. Original native and storage custody retained."
        )
    row.status, row.tags = "cleanup_required", tags
    return True
