"""Deterministic automatic full/incremental policy; no effect authority.

The caller must supply facts from validated accepted lineage under the VM lock.
Neither a completed Backup alone nor a missing query result proves a usable
parent. Dates are UTC calendar dates at admission, not local dates or guessed
timestamps. Unknown/partial facts refuse rather than silently reseeding.
"""

from datetime import date

# Shared by model metadata and the forward migration. CASE bounds casts before
# conversion; malformed JSON must refuse, never become SQL CHECK's UNKNOWN.
AUTOMATIC_POLICY_CHECK = """(
 jsonb_typeof(__policy__)='object'
 AND __policy__ ?& ARRAY['schema','full_every_days','max_incrementals']
 AND __policy__-ARRAY['schema','full_every_days','max_incrementals']='{}'::jsonb
 AND jsonb_typeof(__policy__->'schema')='number' AND __policy__->>'schema'='1'
 AND jsonb_typeof(__policy__->'full_every_days')='number'
 AND CASE WHEN __policy__->>'full_every_days' ~ '^[1-9][0-9]{0,4}$'
   THEN (__policy__->>'full_every_days')::int BETWEEN 1 AND 36500 ELSE false END
 AND jsonb_typeof(__policy__->'max_incrementals')='number'
 AND CASE WHEN __policy__->>'max_incrementals' ~ '^[1-9][0-9]{0,2}$'
   THEN (__policy__->>'max_incrementals')::int BETWEEN 1 AND 255 ELSE false END
)"""
SCHEDULE_POLICY_CHECK = (
    "(retired_at IS NOT NULL OR "
    "(backup_type IN ('full','incremental') AND backup_policy IS NULL) OR "
    "(backup_type='automatic' AND "
    + AUTOMATIC_POLICY_CHECK.replace("__policy__", "backup_policy")
    + " IS TRUE)) IS TRUE"
)


class BackupPolicyError(ValueError):
    pass


def validate_policy(value):
    """One supported policy shape, with no coercion or ignored fields."""
    if (
        type(value) is not dict
        or set(value) != {"schema", "full_every_days", "max_incrementals"}
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or type(value["full_every_days"]) is not int
        or not 1 <= value["full_every_days"] <= 36500
        or type(value["max_incrementals"]) is not int
        # Full plus255 incrementals is the existing256-member restore bound.
        or not 1 <= value["max_incrementals"] <= 255
    ):
        raise BackupPolicyError("invalid_automatic_backup_policy")
    return dict(value)


def validate_mode(mode, policy):
    """Fixed modes never implicitly grant automatic full-reseed authority."""
    if mode == "automatic":
        return validate_policy(policy)
    if mode not in ("full", "incremental") or policy is not None:
        raise BackupPolicyError("invalid_scheduled_backup_mode")
    return None


def decide_automatic(value, *, today, root_date=None, incremental_count=None):
    """Choose a kind/reason; this never authorizes or executes a backup.

    Both absent parent facts mean the caller established no usable accepted parent.
    A partial snapshot, invalid count or future root date is not evidence of absence.
    An automatic grant permits early full reseeds; its bounds prohibit indefinitely
    extending an incremental chain, rather than prohibiting an earlier full.
    """
    policy = validate_policy(value)
    if type(today) is not date:
        raise BackupPolicyError("invalid_policy_observation")
    if root_date is None and incremental_count is None:
        return {"backup_type": "full", "reason": "parent_unavailable"}
    if (
        type(root_date) is not date
        or type(incremental_count) is not int
        or incremental_count < 0
        or root_date > today
    ):
        raise BackupPolicyError("invalid_policy_parent_facts")
    if incremental_count >= policy["max_incrementals"]:
        return {"backup_type": "full", "reason": "max_incrementals"}
    if (today - root_date).days >= policy["full_every_days"]:
        return {"backup_type": "full", "reason": "full_interval"}
    return {"backup_type": "incremental", "reason": "within_policy"}
