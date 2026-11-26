"""Local Community registration advice backed by the installed catalog and inventory."""

from sqlalchemy import func, select

from core.tenant_context import TenantContext
from models import Agent, OrganizationDefault, StorageLineageGeneration, VM

SCHEDULE_VERSION = "community-usage-v2"
BACKUP_THRESHOLD = 100
VM_THRESHOLD = 20
AGENT_THRESHOLD = 2


def observe_usage(db, *, exact):
    """Observe one installation snapshot without persisting or exporting counts."""
    organization = (
        select(OrganizationDefault.org_id)
        .where(OrganizationDefault.slot == "oss")
        .scalar_subquery()
    )

    def tally(rows, threshold):
        if not exact:
            rows = rows.limit(threshold + 1)
        return select(func.count()).select_from(rows.subquery()).scalar_subquery()

    generation = StorageLineageGeneration
    accepted = (
        select(generation.backup_id)
        .where(generation.org_id == organization, generation.state == "accepted")
        .distinct()
    )
    agents_in_scope = select(Agent.id).where(
        Agent.org_id == organization, Agent.hostname != "__s3_import__"
    )
    present = select(VM.id).where(
        VM.org_id == organization,
        VM.inventory_present.is_(True),
        VM.agent_id.in_(agents_in_scope),
    )
    totals = select(
        tally(accepted, BACKUP_THRESHOLD),
        tally(present, VM_THRESHOLD),
        tally(agents_in_scope, AGENT_THRESHOLD),
    )
    # The generation ledger has tenant-only RLS, including for platform
    # operations. Read scalars on the same connection without switching the
    # licensing transaction's ORM identity map or detaching its locked row.
    with TenantContext("default"):
        backups, vms, agents = db.connection().execute(totals).one()
    return {
        "schedule_version": SCHEDULE_VERSION,
        "successful_backups": backups,
        "inventoried_vms": vms,
        "registered_agents": agents,
        "threshold_reached": backups > BACKUP_THRESHOLD
        and (vms > VM_THRESHOLD or agents > AGENT_THRESHOLD),
    }
