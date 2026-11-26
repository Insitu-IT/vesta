"""Health's displayed VM metric agrees with scoped current inventory."""

import asyncio
from types import SimpleNamespace

from models import Organization, VM
from routers.dashboard import get_dashboard_summary
from routers.health import get_health
from .conftest import make_agent, make_vm


def test_health_vm_metric_matches_current_inventory_and_tenant(db_session, monkeypatch):
    db = db_session
    agent = make_agent(db)
    for state in ["running", "shutoff", "stopped"]:
        make_vm(db, agent, state=state)
    make_vm(db, agent, inventory_present=False)
    other = Organization(name="Other tenant")
    db.add(other)
    db.flush()
    make_vm(db, make_agent(db, org_id=other.id), org_id=other.id)
    # This aggregate test never contacts S3; PostgreSQL-only probe metadata is
    # deliberately unavailable on the real SQLite fixture and does not hide data.
    monkeypatch.setattr("routers.health.SettingsService.get_s3_config", lambda _: {})
    user = SimpleNamespace(org_id=agent.org_id)
    health = asyncio.run(get_health(include="metrics", current_user=user, db=db))
    dashboard = asyncio.run(get_dashboard_summary(current_user=user, db=db))
    assert health["metrics"]["total_vms"] == dashboard["vms"]["total"] == 3
    for vm in db.query(VM).filter_by(org_id=agent.org_id):
        vm.inventory_present = False
    db.commit()
    empty = asyncio.run(get_health(include="metrics", current_user=user, db=db))
    assert empty["metrics"]["total_vms"] == 0
