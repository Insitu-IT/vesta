"""Deterministic state plans for simulated demo backup and restore operations."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

BackupType = Literal["full", "incremental"]
BackupScenario = Literal["success", "upload_failure"]


class DemoExecutionError(ValueError):
    """A deliberate, user-visible refusal in the demo executor."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ExecutionEvent:
    status: str
    progress: int
    stage: str
    message: str
    simulated: bool = True
    environment: str = "demo"

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "progress": self.progress,
            "stage": self.stage,
            "message": self.message,
            "simulated": self.simulated,
            "environment": self.environment,
        }


def backup_plan(
    operation_id: str,
    backup_type: BackupType,
    *,
    supports_incremental: bool,
    has_completed_parent: bool,
    scenario: BackupScenario = "success",
) -> tuple[ExecutionEvent, ...]:
    """Return an immutable plan without touching a real executor or storage.

    An incremental request is never converted to a full backup. Missing capability
    and missing chain ancestry are explicit terminal refusals.
    """

    if backup_type not in {"full", "incremental"}:
        raise DemoExecutionError(
            "BACKUP_TYPE_UNSUPPORTED",
            f"Demo supports full or incremental backup, not {backup_type!r}.",
        )
    if scenario not in {"success", "upload_failure"}:
        raise DemoExecutionError(
            "SCENARIO_UNSUPPORTED", f"Unknown demo scenario: {scenario!r}."
        )
    if backup_type == "incremental" and not supports_incremental:
        raise DemoExecutionError(
            "INCREMENTAL_UNSUPPORTED",
            "Incremental backup is unavailable for this VM; no full backup was started.",
        )
    if backup_type == "incremental" and not has_completed_parent:
        raise DemoExecutionError(
            "INCREMENTAL_PARENT_REQUIRED",
            "Incremental backup requires a completed parent; no full backup was started.",
        )

    size_gib = 2 + (int(sha256(operation_id.encode()).hexdigest()[:4], 16) % 7)
    events = [
        ExecutionEvent("queued", 0, "queue", "Simulated operation accepted"),
        ExecutionEvent("running", 10, "connect", "Simulated agent connected"),
        ExecutionEvent("running", 35, "snapshot", "Simulated snapshot created"),
        ExecutionEvent("running", 70, "transfer", f"Simulated {size_gib} GiB transfer"),
        ExecutionEvent("uploading", 92, "upload", "Simulated encrypted upload"),
    ]
    if scenario == "upload_failure":
        events.append(
            ExecutionEvent(
                "upload_failed",
                92,
                "upload",
                "Simulated object-store timeout; retry is available",
            )
        )
    else:
        events.append(
            ExecutionEvent("completed", 100, "complete", "Simulated backup completed")
        )
    return tuple(events)


def retry_upload_plan() -> tuple[ExecutionEvent, ...]:
    return (
        ExecutionEvent(
            "uploading", 92, "upload_retry", "Simulated upload retry started"
        ),
        ExecutionEvent(
            "completed", 100, "complete", "Simulated backup completed after retry"
        ),
    )


def restore_plan(*, backup_status: str) -> tuple[ExecutionEvent, ...]:
    if backup_status != "completed":
        raise DemoExecutionError(
            "RESTORE_POINT_NOT_READY",
            f"Restore requires a completed backup; current status is {backup_status!r}.",
        )
    return (
        ExecutionEvent("pending", 0, "queue", "Simulated restore accepted"),
        ExecutionEvent("running", 20, "assemble", "Simulated backup chain assembled"),
        ExecutionEvent("running", 55, "decrypt", "Simulated payload decrypted"),
        ExecutionEvent("running", 85, "restore", "Simulated disk restore"),
        ExecutionEvent(
            "completed",
            100,
            "complete",
            "Simulated restore completed; no VM or disk was changed",
        ),
    )
