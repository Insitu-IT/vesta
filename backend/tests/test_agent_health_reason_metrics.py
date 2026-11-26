"""Bounded agent degradation reasons exposed for retained monitoring (#57)."""

from datetime import datetime, timedelta
import uuid

import pytest
from core import metrics
from core.agent_health import (
    HEALTH_REASONS,
    assess_agent_health,
)

THRESHOLDS = {
    "storage_free_gb_threshold": 10,
    "storage_free_percent_threshold": 10,
    "load_percent_threshold": 80,
}


@pytest.mark.parametrize(
    ("heartbeat", "expected_reason"),
    [
        (
            {
                "backup_storage_free_bytes": 5 * 1024**3,
                "backup_storage_total_bytes": 100 * 1024**3,
            },
            "storage_low",
        ),
        ({"cpu_cores": 4, "load_average_15m": 4}, "load_high"),
        ({"libvirt_accessible": False}, "libvirt_unavailable"),
    ],
)
def test_each_health_criterion_has_one_stable_reason(heartbeat, expected_reason):
    heartbeat.setdefault("libvirt_accessible", True)
    issues, reasons = assess_agent_health(heartbeat, **THRESHOLDS)

    assert issues
    assert reasons == [expected_reason]


def test_instantaneous_cpu_does_not_degrade_agent():
    issues, reasons = assess_agent_health(
        {"cpu_usage_percent": 100, "libvirt_accessible": True}, **THRESHOLDS
    )

    assert issues == []
    assert reasons == []


def _reason_value(reason):
    return metrics.REGISTRY.get_sample_value(
        "vnbui_agents_degraded_by_reason", {"reason": reason}
    )


def _agent(db, **kwargs):
    from models import Agent

    defaults = {
        "id": str(uuid.uuid4()),
        "hostname": f"host-{uuid.uuid4().hex[:6]}",
        "status": "online",
        "ip_address": "127.0.0.1",
        "port": 8090,
    }
    defaults.update(kwargs)
    agent = Agent(**defaults)
    db.add(agent)
    db.commit()
    return agent


def test_collector_emits_explicit_zeros_and_counts_multiple_reasons(
    db_session, patch_session_local
):
    now = datetime.utcnow()
    _agent(
        db_session,
        metrics={
            "health_status": "degraded",
            "health_reasons": ["storage_low", "libvirt_unavailable"],
        },
        last_heartbeat=now,
    )
    _agent(
        db_session,
        metrics={"health_status": "degraded", "health_reasons": ["storage_low"]},
        last_heartbeat=now,
    )
    # Offline agents do not contribute to either the aggregate or reason counts.
    _agent(
        db_session,
        metrics={"health_status": "degraded", "health_reasons": ["load_high"]},
        last_heartbeat=now - timedelta(minutes=10),
    )

    metrics.collect_gauge_metrics()

    assert metrics.REGISTRY.get_sample_value("vnbui_agents_degraded") == 2
    assert _reason_value("storage_low") == 2
    assert _reason_value("libvirt_unavailable") == 1
    assert _reason_value("load_high") == 0
    assert all(_reason_value(reason) is not None for reason in HEALTH_REASONS)


def test_vesta_metric_aliases_include_product_info_and_operational_values():
    from prometheus_client.parser import text_string_to_metric_families

    samples = {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(metrics.get_metrics().decode())
        for sample in family.samples
    }
    for name in ("info", "agents_online"):
        old = {
            labels: value
            for (metric, labels), value in samples.items()
            if metric == "vnbui_" + name
        }
        current = {
            labels: value
            for (metric, labels), value in samples.items()
            if metric == "vesta_" + name
        }
        assert old and current == old
