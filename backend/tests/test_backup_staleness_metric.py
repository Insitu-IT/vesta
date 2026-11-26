"""Per-VM backup-staleness metric (#38).

`collect_gauge_metrics` emits `vnbui_backup_last_success_age_seconds{vm_name,vm_id}`
= seconds since each VM's last successful backup (age since registration if it
never succeeded). This is the SMTP-independent signal monitoring/zabbix alerts on
— the gap that let backups fail silently for months (notify_on_failure needs
email configured to actually deliver).
"""

import uuid
from datetime import datetime, timedelta

from core import metrics


def _agent(db):
    from models import Agent

    a = Agent(
        id=str(uuid.uuid4()),
        hostname=f"h-{uuid.uuid4().hex[:6]}",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    db.add(a)
    db.commit()
    return a


def _vm(db, agent, name, **kw):
    from models import VM

    d = dict(
        id=str(uuid.uuid4()),
        name=name,
        agent_id=agent.id,
        state="running",
        uuid=str(uuid.uuid4()),
        memory_kb=2048,
        vcpu_count=2,
        disks=[{"target": "vda", "format": "qcow2"}],
    )
    d.update(kw)
    v = VM(**d)
    db.add(v)
    db.commit()
    return v


def _backup(db, vm, **kw):
    from models import Backup

    d = dict(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="pending",
        backup_type="full",
        tags={},
        storage_path=f"file:///backups/{uuid.uuid4()}",
    )
    d.update(kw)
    b = Backup(**d)
    db.add(b)
    db.commit()
    return b


def _age(vm):
    return metrics.REGISTRY.get_sample_value(
        "vnbui_backup_last_success_age_seconds",
        {"vm_name": vm.name, "vm_id": str(vm.id)},
    )


def test_backup_last_success_age_per_vm(db_session, patch_session_local):
    agent = _agent(db_session)

    # Fresh: a completed backup ~1h ago → small age.
    vm_fresh = _vm(db_session, agent, "fresh-vm")
    _backup(
        db_session,
        vm_fresh,
        status="completed",
        completed_at=datetime.utcnow() - timedelta(hours=1),
    )

    # Stale: only an old completed backup (110 days) → large age (the Mesh case).
    vm_stale = _vm(db_session, agent, "stale-vm")
    _backup(
        db_session,
        vm_stale,
        status="completed",
        completed_at=datetime.utcnow() - timedelta(days=110),
    )

    # Never succeeded: only a failed backup; VM registered 200 days ago →
    # age falls back to registration age (so it still flags as stale).
    vm_never = _vm(
        db_session,
        agent,
        "never-vm",
        created_at=datetime.utcnow() - timedelta(days=200),
    )
    _backup(db_session, vm_never, status="failed")

    metrics.collect_gauge_metrics()

    a_fresh, a_stale, a_never = _age(vm_fresh), _age(vm_stale), _age(vm_never)
    assert a_fresh is not None and a_fresh < 2 * 3600  # ~1h
    assert a_stale is not None and a_stale > 100 * 86400  # ~110d
    assert a_never is not None and a_never > 150 * 86400  # ~200d since registration


def test_stale_series_cleared_between_collections(db_session, patch_session_local):
    """.clear() drops series for VMs that no longer exist (no unbounded growth)."""
    from models import Backup, VM

    agent = _agent(db_session)
    vm = _vm(db_session, agent, "temp-vm")
    _backup(
        db_session,
        vm,
        status="completed",
        completed_at=datetime.utcnow() - timedelta(hours=2),
    )
    metrics.collect_gauge_metrics()
    assert _age(vm) is not None

    db_session.query(Backup).filter(Backup.vm_id == vm.id).delete()
    db_session.query(VM).filter(VM.id == vm.id).delete()
    db_session.commit()
    metrics.collect_gauge_metrics()
    assert _age(vm) is None
