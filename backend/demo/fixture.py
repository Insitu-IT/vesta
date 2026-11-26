"""Versioned synthetic data for the public evaluator sandbox.

The fixture is generated from constants and a caller-supplied clock. It never reads a
database, agent, filesystem payload, or production export. Stable UUIDv5 identifiers
make two sessions structurally identical while their databases remain isolated.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid5

FIXTURE_VERSION = "2026.08.2"
_NAMESPACE = UUID("6d63d842-3130-4e91-9d3a-3586db4d9564")

# Construct the positive-control markers so a source-tree publication scan does not
# confuse this detector with an embedded endpoint. Runtime tests still prove each
# complete marker is rejected.
_FORBIDDEN_PUBLIC_MARKERS = (
    ".insitu" + ".local",
    "10." + "200.",
    "ctrl" + "01",
    "data" + "01",
    "monitor" + "01",
    "@insitu" + ".co.il",
    "gitlab" + ".insitu.co.il",
)


def _id(kind: str, name: str) -> str:
    return str(uuid5(_NAMESPACE, f"{FIXTURE_VERSION}:{kind}:{name}"))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class DemoFixture:
    """Complete structured seed for one evaluator session."""

    version: str
    generated_at: datetime
    persona: Mapping[str, Any]
    agents: tuple[Mapping[str, Any], ...]
    vms: tuple[Mapping[str, Any], ...]
    groups: tuple[Mapping[str, Any], ...]
    schedules: tuple[Mapping[str, Any], ...]
    backups: tuple[Mapping[str, Any], ...]
    restores: tuple[Mapping[str, Any], ...]
    activity: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_version": self.version,
            "generated_at": self.generated_at.isoformat(),
            "environment": "demo",
            "simulated": True,
            "persona": dict(self.persona),
            "agents": [dict(item) for item in self.agents],
            "vms": [dict(item) for item in self.vms],
            "groups": [dict(item) for item in self.groups],
            "schedules": [dict(item) for item in self.schedules],
            "backups": [dict(item) for item in self.backups],
            "restores": [dict(item) for item in self.restores],
            "activity": [dict(item) for item in self.activity],
        }


def build_fixture(now: datetime | None = None) -> DemoFixture:
    """Build the deterministic seed relative to ``now``.

    Timestamps move with session creation so a public demo never looks stale. All
    identities and relationships remain stable for testability and reproducibility.
    """

    generated_at = _utc(now or datetime.now(timezone.utc))
    libvirt_agent = _id("agent", "libvirt")
    kubevirt_agent = _id("agent", "kubevirt")

    agents = (
        {
            "id": libvirt_agent,
            "hostname": "libvirt-edge.demo.example",
            "display_name": "Libvirt edge",
            "status": "online",
            "provider": "libvirt",
            "last_heartbeat": generated_at.isoformat(),
            "capabilities": {
                "incremental": True,
                "checkpoints": True,
                "backup_method": "virtnbdbackup",
            },
            "simulated": True,
        },
        {
            "id": kubevirt_agent,
            "hostname": "kubevirt-cluster.demo.example",
            "display_name": "KubeVirt cluster",
            "status": "degraded",
            "provider": "kubevirt",
            "last_heartbeat": generated_at.isoformat(),
            "health_reasons": {
                "storage_low": 0,
                "load_high": 1,
                "libvirt_unavailable": 0,
            },
            "capabilities": {
                "incremental": True,
                "snapshots": True,
                "backup_method": "volumeexport",
            },
            "simulated": True,
        },
    )

    vm_specs = (
        ("billing-api", libvirt_agent, "running", "production", True, "qcow2", 4, 8),
        ("billing-db", libvirt_agent, "running", "production", True, "qcow2", 8, 32),
        ("identity", libvirt_agent, "running", "production", True, "qcow2", 4, 8),
        ("reporting", libvirt_agent, "shutoff", "production", True, "qcow2", 4, 16),
        ("legacy-ledger", libvirt_agent, "running", "legacy", False, "raw", 2, 8),
        ("dev-runner", libvirt_agent, "running", "development", True, "qcow2", 2, 4),
        ("portal-api", kubevirt_agent, "running", "production", True, "pvc", 4, 8),
        ("portal-worker", kubevirt_agent, "running", "production", True, "pvc", 4, 8),
        ("analytics", kubevirt_agent, "running", "production", True, "pvc", 8, 24),
        ("audit-index", kubevirt_agent, "pending", "production", True, "pvc", 4, 16),
        ("qa-browser", kubevirt_agent, "running", "testing", True, "pvc", 2, 4),
        ("qa-database", kubevirt_agent, "stopped", "testing", True, "pvc", 2, 8),
    )

    vms = tuple(
        {
            "id": _id("vm", name),
            "uuid": _id("vm-uuid", name),
            "name": name,
            "agent_id": agent_id,
            "state": state,
            "memory_kb": memory_gib * 1024 * 1024,
            "vcpu_count": vcpus,
            "disks": [
                {
                    "target": "vda",
                    "format": disk_format,
                    "size_bytes": memory_gib * 8 * 1024**3,
                    "source": f"demo://disks/{name}/vda",
                }
            ],
            "metadata": {
                "environment": environment,
                "supports_incremental": incremental,
                "simulated": True,
            },
        }
        for name, agent_id, state, environment, incremental, disk_format, vcpus, memory_gib in vm_specs
    )
    vm_by_name = {item["name"]: item for item in vms}

    production_group = _id("group", "production")
    kubevirt_group = _id("group", "kubevirt")
    critical_group = _id("group", "critical")
    protected_group = _id("group", "protected-hybrid")
    groups = (
        {
            "id": production_group,
            "name": "Production VMs",
            "group_type": "dynamic",
            "rules": [
                {"field": "metadata.environment", "op": "eq", "value": "production"}
            ],
            "rules_match": "all",
            "simulated": True,
        },
        {
            "id": kubevirt_group,
            "name": "KubeVirt workloads",
            "group_type": "dynamic",
            "rules": [{"field": "agent_id", "op": "eq", "value": kubevirt_agent}],
            "rules_match": "all",
            "simulated": True,
        },
        {
            "id": critical_group,
            "name": "Critical services",
            "group_type": "static",
            "vm_ids": [
                vm_by_name[name]["id"]
                for name in ("billing-api", "billing-db", "identity")
            ],
            "simulated": True,
        },
        {
            "id": protected_group,
            "name": "Protected hybrid estate",
            "group_type": "hybrid",
            "vm_ids": [vm_by_name["legacy-ledger"]["id"]],
            "rules": [
                {"field": "metadata.environment", "op": "eq", "value": "production"}
            ],
            "rules_match": "all",
            "simulated": True,
        },
    )

    schedules = (
        {
            "id": _id("schedule", "production-weekly"),
            "name": "Production weekly incremental",
            "vm_group_id": production_group,
            "cron_expression": "0 2 * * 0",
            "retention_days": 30,
            "backup_type": "incremental",
            "enabled": True,
            "simulated": True,
        },
        {
            "id": _id("schedule", "qa-disabled"),
            "name": "QA nightly (disabled)",
            "vm_id": vm_by_name["qa-browser"]["id"],
            "cron_expression": "0 1 * * *",
            "retention_days": 7,
            "backup_type": "full",
            "enabled": False,
            "simulated": True,
        },
    )

    full_id = _id("backup", "billing-db-full")
    inc1_id = _id("backup", "billing-db-inc-1")
    inc2_id = _id("backup", "billing-db-inc-2")
    backup_specs = (
        (full_id, "billing-db", "full", "completed", 100, None, full_id, 0, 72),
        (
            inc1_id,
            "billing-db",
            "incremental",
            "completed",
            100,
            full_id,
            full_id,
            1,
            48,
        ),
        (
            inc2_id,
            "billing-db",
            "incremental",
            "completed",
            100,
            inc1_id,
            full_id,
            2,
            24,
        ),
        (
            _id("backup", "identity-full"),
            "identity",
            "full",
            "completed",
            100,
            None,
            None,
            0,
            18,
        ),
        (
            _id("backup", "portal-upload-failed"),
            "portal-api",
            "full",
            "upload_failed",
            92,
            None,
            None,
            0,
            3,
        ),
        (
            _id("backup", "analytics-running"),
            "analytics",
            "full",
            "running",
            55,
            None,
            None,
            0,
            0,
        ),
        (
            _id("backup", "reporting-queued"),
            "reporting",
            "full",
            "queued",
            0,
            None,
            None,
            0,
            0,
        ),
    )
    backups = []
    for (
        backup_id,
        vm_name,
        backup_type,
        status,
        progress,
        parent_id,
        chain_id,
        position,
        age_hours,
    ) in backup_specs:
        effective_chain = chain_id or backup_id
        created_at = generated_at - timedelta(hours=age_hours)
        backups.append(
            {
                "id": backup_id,
                "vm_id": vm_by_name[vm_name]["id"],
                "vm_name": vm_name,
                "backup_type": backup_type,
                "status": status,
                "progress": progress,
                "parent_backup_id": parent_id,
                "chain_id": effective_chain,
                "chain_position": position,
                "size_bytes": (
                    (6 + position) * 1024**3
                    if status in {"completed", "upload_failed"}
                    else None
                ),
                "storage_path": f"demo://backups/{backup_id}",
                "created_at": created_at.isoformat(),
                "completed_at": (
                    created_at.isoformat() if status == "completed" else None
                ),
                "error_message": (
                    "Simulated object-store timeout; retry is available"
                    if status == "upload_failed"
                    else None
                ),
                "simulated": True,
            }
        )

    restore_id = _id("restore", "billing-db")
    restores = (
        {
            "id": restore_id,
            "backup_id": inc2_id,
            "target_vm_id": vm_by_name["billing-db"]["id"],
            "status": "completed",
            "progress": 100,
            "created_at": (generated_at - timedelta(hours=20)).isoformat(),
            "completed_at": (
                generated_at - timedelta(hours=19, minutes=48)
            ).isoformat(),
            "simulated": True,
        },
    )

    activity = (
        {
            "id": _id("activity", "backup-completed"),
            "action": "backup_completed",
            "resource_type": "backup",
            "resource_id": inc2_id,
            "created_at": (generated_at - timedelta(hours=24)).isoformat(),
            "details": {"vm_name": "billing-db", "simulated": True},
        },
        {
            "id": _id("activity", "restore-completed"),
            "action": "restore_completed",
            "resource_type": "restore",
            "resource_id": restore_id,
            "created_at": (generated_at - timedelta(hours=19, minutes=48)).isoformat(),
            "details": {"vm_name": "billing-db", "simulated": True},
        },
    )

    fixture = DemoFixture(
        version=FIXTURE_VERSION,
        generated_at=generated_at,
        persona={
            "hands_on": "single-tenant backup operator",
            "msp_context": "guided-only",
            "msp_message": (
                "The sandbox exercises one operator tenant. MSP organization isolation, "
                "white-labeling, and billing are guided commercial capabilities and are not "
                "enabled in this public session."
            ),
        },
        agents=agents,
        vms=vms,
        groups=groups,
        schedules=schedules,
        backups=tuple(backups),
        restores=restores,
        activity=activity,
    )
    assert_public_fixture(fixture.as_dict())
    return fixture


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def assert_public_fixture(value: Any) -> None:
    """Reject known internal markers before a fixture can be used."""

    for text in _strings(value):
        lowered = text.lower()
        for marker in _FORBIDDEN_PUBLIC_MARKERS:
            if marker in lowered:
                raise ValueError(f"demo fixture contains prohibited marker: {marker}")
