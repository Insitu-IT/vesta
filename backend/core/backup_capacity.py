"""Unmounted capacity transactions. Returns custody, never a send continuation.

Only PostgreSQL is an admission authority. Callers supply a fresh session factory;
no caller transaction is committed, retried or silently downgraded in isolation.
"""

from sqlalchemy import text

CAPACITY_LOCK = (1447977557, 1)


class CapacityRefused(RuntimeError):
    pass


def lock_capacity(db):
    """Accounting lock, after owner rows; never retained by effect services."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:domain,:slot)"),
            dict(domain=CAPACITY_LOCK[0], slot=CAPACITY_LOCK[1]),
        )


def _visible(db, backup_id):
    from core.tenant_context import identity, is_demo

    org, _, platform = identity()
    if not org or platform or is_demo.get():
        raise CapacityRefused("Capacity requires original tenant scope")
    row = (
        db.execute(
            text("""SELECT id,org_id,vm_id,authority_kind,initiating_user_id,
      scheduler_occurrence_id,capacity_state,capacity_id,capacity_reserved_at,
      capacity_policy_revision,capacity_release FROM backups WHERE id=:id"""),
            dict(id=backup_id),
        )
        .mappings()
        .one_or_none()
    )
    if org == "default":
        org = db.scalar(
            text("SELECT org_id FROM organization_defaults WHERE slot='oss'")
        )
    if row is None or row["org_id"] != org:
        raise CapacityRefused("Capacity owner unavailable")
    # The SQL trigger validates effective persisted OSS org and RLS context too.
    return dict(row)


def lookup_capacity(factory, backup_id):
    with factory() as db:
        return _visible(db, backup_id)


def _transition(factory, backup_id, target, before_commit=None):
    with factory() as db:
        if db.in_transaction() or db.new or db.dirty or db.deleted:
            raise CapacityRefused("Fresh capacity transaction required")
        if db.get_bind().dialect.name != "postgresql":
            raise CapacityRefused("PostgreSQL capacity authority required")
        db.connection(execution_options={"isolation_level": "READ COMMITTED"})
        row = _visible(db, backup_id)
        if row["capacity_state"] == target:
            return dict(row, disposition="existing_custody")
        # Original org, original human or schedule/grant, backup, then global.
        # No operation under the global lock subsequently waits for owner rows.
        db.execute(
            text("SELECT id FROM organizations WHERE id=:org FOR UPDATE"),
            dict(org=row["org_id"]),
        ).one()
        if row["authority_kind"] == "human":
            db.execute(
                text("SELECT id FROM users WHERE id=:actor AND org_id=:org FOR UPDATE"),
                dict(actor=row["initiating_user_id"], org=row["org_id"]),
            ).all()
        elif row["authority_kind"] == "scheduler":
            occurrence = (
                db.execute(
                    text(
                        "SELECT schedule_id,grant_id FROM schedule_occurrences WHERE id=:id AND org_id=:org"
                    ),
                    dict(id=row["scheduler_occurrence_id"], org=row["org_id"]),
                )
                .mappings()
                .one()
            )
            db.execute(
                text(
                    "SELECT id FROM schedules WHERE id=:id AND org_id=:org FOR UPDATE"
                ),
                dict(id=occurrence["schedule_id"], org=row["org_id"]),
            ).all()
            db.execute(
                text(
                    "SELECT id FROM scheduler_grants WHERE id=:id AND org_id=:org FOR UPDATE"
                ),
                dict(id=occurrence["grant_id"], org=row["org_id"]),
            ).all()
            db.execute(
                text(
                    "SELECT id FROM backup_queue WHERE started_backup_id=:backup "
                    "AND scheduler_occurrence_id=:occurrence AND vm_id=:vm FOR UPDATE"
                ),
                dict(
                    backup=backup_id,
                    occurrence=row["scheduler_occurrence_id"],
                    vm=row["vm_id"],
                ),
            ).all()
        db.execute(
            text("SELECT id FROM backups WHERE id=:id AND org_id=:org FOR UPDATE"),
            dict(id=backup_id, org=row["org_id"]),
        ).one()
        row = _visible(db, backup_id)
        if row["capacity_state"] == target:
            return dict(row, disposition="existing_custody")
        if target == "reserved":
            from models import Agent, Backup, VM
            from core.storage_source import validate_native_disk_selection

            backup = db.get(Backup, backup_id, populate_existing=True)
            vm = db.get(VM, row["vm_id"], populate_existing=True)
            if backup is None or vm is None:
                raise CapacityRefused("Capacity source unavailable")
            validate_native_disk_selection(
                backup, vm, db.get(Agent, vm.agent_id, populate_existing=True), db=db
            )
        lock_capacity(db)
        db.execute(
            text(
                "UPDATE backups SET capacity_state=:target WHERE id=:id AND org_id=:org"
            ),
            dict(target=target, id=backup_id, org=row["org_id"]),
        )
        result = _visible(db, backup_id)
        if before_commit is not None:
            before_commit(db)
        db.commit()
        return dict(result, disposition="committed_custody")


def reserve_capacity(factory, backup_id, *, before_commit=None):
    return _transition(factory, backup_id, "reserved", before_commit)


def release_never_effect(factory, backup_id, *, before_commit=None):
    return _transition(factory, backup_id, "released", before_commit)


def validate_reserved_capacity(db, backup_id, capacity_id):
    """Owner-first read validation, not allocation or a continuation factory.

    Fixed installation policy is read on a separate read-only configuration
    connection after tenant visibility, never by elevating the owner session.
    The caller already holds the original Backup lock against release.
    """
    from models import SettingV3
    from core.installation_config import read_configuration

    row = _visible(db, backup_id)
    if row["capacity_state"] != "reserved" or row["capacity_id"] != capacity_id:
        raise CapacityRefused("Original capacity reservation unavailable")
    rows = read_configuration(db, SettingV3, "backup.capacity_admission")
    import json

    try:
        policy = json.loads(rows[0].value) if len(rows) == 1 else None
    except (ValueError, TypeError):
        raise CapacityRefused("Persisted capacity policy absent or invalid")
    if (
        type(policy) is not dict
        or set(policy) != {"schema", "revision", "limit", "maintenance"}
        or type(policy["schema"]) is not int
        or policy["schema"] != 1
        or type(policy["revision"]) is not int
        or not 0 < policy["revision"] < 2**63
        or type(policy["limit"]) is not int
        or not 1 <= policy["limit"] <= 100000
        or type(policy["maintenance"]) is not bool
    ):
        raise CapacityRefused("Persisted capacity policy absent or invalid")
    if policy["maintenance"]:
        raise CapacityRefused("Capacity maintenance")
