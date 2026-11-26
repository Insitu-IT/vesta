"""Enumerate persisted work scopes; privileged enumeration returns only IDs."""

from sqlalchemy import select
import asyncio
from builtins import ExceptionGroup

from core.tenant_context import PlatformContext, TenantContext, commercial_mode
from models import Organization, OrganizationDefault


def organization_work_ids(session_factory):
    """End the privileged transaction before any tenant work is invoked."""
    with PlatformContext(), session_factory() as db:
        query = select(Organization.id).where(Organization.enabled.is_(True))
        if not commercial_mode():
            default = db.execute(
                select(OrganizationDefault.org_id).where(
                    OrganizationDefault.slot == "oss"
                )
            ).scalar_one()
            query = query.where(Organization.id == default)
        return tuple(db.execute(query.order_by(Organization.id)).scalars())


def run_organization_coroutines(session_factory, work):
    """Use one event loop for the whole fan-out, with sequential tenant scopes.

    Enumeration ends before mutable work. Async transports reused by work must
    not move between event loops at each organization boundary.
    """
    asyncio.run(run_organization_coroutines_on_loop(session_factory, work))


async def run_organization_coroutines_on_loop(session_factory, work):
    """Fan out on an already-owned loop; never transfer a shared transport."""
    organizations = organization_work_ids(session_factory)
    failures = []
    for org_id in organizations:
        try:
            with TenantContext(org_id):
                await work()
        except Exception as exc:
            # Cancellation deliberately stops this invocation; ordinary failure
            # must not starve the next tenant.
            failures.append(exc)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise ExceptionGroup("Organization work failed", failures)
