"""Exhaustive ownership classification, distinct from enforcement completion.

This inventory includes migration-owned application tables. Adding a table must
make the conformance test fail until its ownership is deliberately classified.
Classification alone is never a claim that all associated policies have landed.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TableScope:
    kind: str
    identity: str
    boundary: str


SCOPES = {
    name: TableScope("tenant", "org_id", "Immutable persisted organization")
    for name in (
        "operator_requests",
        "operator_dispatches",
        "agent_key_rotations",
        "users",
        "oidc_login_states",
        "agents",
        "vms",
        "vm_groups",
        "backups",
        "s3_publications",
        "s3_upload_parts",
        "s3_upload_results",
        "s3_part_observation_scans",
        "s3_part_observation_pages",
        "storage_configuration_generations",
        "storage_configuration_activations",
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
        "storage_lineage_generations",
        "storage_lineage_heads",
        "schedules",
        "scheduler_principals",
        "scheduler_grants",
        "schedule_occurrences",
        "schedule_occurrence_members",
        "restores",
        "notification_rules",
        "notification_logs",
        "encryption_keys",
        "backup_verifications",
        "saved_searches",
        "reports",
        "report_executions",
    )
}
SCOPES.update(
    {
        "activity_logs": TableScope(
            "parent", "user_id", "Required user; no anonymous fallback"
        ),
        "agent_api_keys": TableScope("parent", "agent_id", "Required persisted agent"),
        "agent_certificates": TableScope(
            "parent", "agent_id", "Required persisted agent; ambiguity refused"
        ),
        "agent_registration_keys": TableScope(
            "parent", "created_by", "Required persisted issuer; no role-name bypass"
        ),
        "orchestrator_api_keys": TableScope(
            "parent", "created_by", "Required persisted issuer"
        ),
        "vm_group_members": TableScope(
            "parent", "vm_id,group_id", "Both required and same organization"
        ),
        "backup_queue": TableScope(
            "parent",
            "vm_id",
            "Required VM; optional creator/schedule must share organization",
        ),
        "organizations": TableScope(
            "tenant", "id", "Organization metadata; platform enumeration is explicit"
        ),
        "access_audit": TableScope(
            "tenant",
            "org_id",
            "Migration-owned audit; null attribution is platform-only, append-only",
        ),
        "system_events": TableScope(
            "tenant",
            "org_id,attribution",
            "Immutable tenant events; explicit platform events and unresolved history are platform-only",
        ),
        "organization_defaults": TableScope(
            "global",
            "slot",
            "One installation OSS assignment; never a commercial fallback",
        ),
        "storage_configuration_clock": TableScope(
            "global",
            "slot",
            "Non-secret revision readable by consumers; monotonic platform-only writes",
        ),
        "settings_v3": TableScope(
            "global",
            "key",
            "Installation connection/configuration inputs; tenant admin cannot administer them",
        ),
        "secrets_v3": TableScope(
            "global",
            "key",
            "Installation service credentials; trusted consumers only, no tenant secret export",
        ),
        "system_settings": TableScope(
            "global",
            "key",
            "Legacy installation configuration; same authority as settings_v3",
        ),
        "demo_sessions": TableScope(
            "global",
            "token_hash",
            "Separate synthetic sandbox domain; exact session capability, never tenant inventory",
        ),
        "demo_rate_buckets": TableScope(
            "global", "key_hash", "Public-sandbox abuse accounting across sessions"
        ),
    }
)


def assert_classified(table_names):
    """Compare sets so a new or removed table cannot silently inherit a label."""
    actual = set(table_names)
    expected = set(SCOPES)
    if actual != expected:
        raise RuntimeError(
            f"Table ownership classification mismatch: unclassified={sorted(actual - expected)}, "
            f"absent={sorted(expected - actual)}"
        )
