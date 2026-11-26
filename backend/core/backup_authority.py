"""Read original authority, never confer execution permission.

Scheduler dispatch is deliberately dormant. Callers must continue to use their
existing human re-admission checks; parsing a binding is not authorization.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class HumanAuthority:
    user_id: str


@dataclass(frozen=True)
class SchedulerAuthority:
    occurrence_id: str


def read_authority(record):
    kind = record.authority_kind
    user = record.initiating_user_id
    occurrence = record.scheduler_occurrence_id
    if kind == "human" and user and occurrence is None:
        return HumanAuthority(user)
    if kind == "scheduler" and occurrence and user is None:
        return SchedulerAuthority(occurrence)
    raise ValueError("Original executable authority unavailable; retain custody")


def human_authority(record):
    authority = read_authority(record)
    if not isinstance(authority, HumanAuthority):
        raise ValueError("Scheduler execution awaits integrated admission")
    return authority


def schedule_authority_state(schedule, grant, organization):
    """Read-only presentation, independent of the enrolling human's status."""
    if schedule.retired_at is not None:
        return "retired"
    if grant is None:
        return "unenrolled" if schedule.current_grant_id is None else "binding_invalid"
    if (
        organization.id != schedule.org_id
        or schedule.current_grant_id != grant.id
        or schedule.org_id != grant.org_id
        or schedule.id != grant.schedule_id
        or schedule.authority_revision != grant.schedule_revision
    ):
        return "binding_invalid"
    if grant.state == "revoked":
        return "revoked"
    if grant.state != "active":
        return "binding_invalid"
    if not organization.enabled or grant.org_epoch != organization.scheduler_epoch:
        return "org_epoch_held"
    return "active" if schedule.enabled else "paused"
