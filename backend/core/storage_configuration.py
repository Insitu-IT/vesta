"""Unmounted, database-backed configuration binding. No environment enrollment.

Original tenant/owner admission precedes this boundary. Each external request
resolves its own detached snapshot; a previous request cannot lend authority.
"""

from dataclasses import dataclass, field
from types import SimpleNamespace
import hashlib
import ssl

from sqlalchemy import text
from core.tenant_context import PlatformContext
from core.s3_ownership import StorageOwnershipError

LOCK = "SELECT pg_advisory_xact_lock(1447977559,1)"


def require_generation(db, org, facts):
    if db.scalar(text("SELECT current_setting('app.current_org',true)")) != org:
        raise StorageOwnershipError("Configuration owner unavailable")
    row = (
        db.execute(
            text(
                "SELECT id,revision,descriptor FROM storage_configuration_generations "
                "WHERE org_id=:org AND sha256=:digest"
            ),
            dict(org=org, digest=facts["provider_identity"]["configuration_sha256"]),
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise StorageOwnershipError("Configuration generation unavailable")
    db.execute(text(LOCK))
    if (
        db.scalar(text("SELECT current_setting('transaction_isolation')"))
        != "read committed"
    ):
        raise StorageOwnershipError("Configuration admission requires READ COMMITTED")
    current = (
        db.execute(
            text(
                "SELECT c.revision,(SELECT generation_id FROM storage_configuration_activations "
                "WHERE org_id=:org ORDER BY id DESC LIMIT 1) AS generation_id "
                "FROM storage_configuration_clock c WHERE c.slot=1"
            ),
            dict(org=org),
        )
        .mappings()
        .one_or_none()
    )
    d = row["descriptor"]
    if (
        current is None
        or current["revision"] != row["revision"]
        or current["generation_id"] != row["id"]
        or d["target"] != facts["target"]
        or d["profile"] != facts["profile"]
        or d["adapter"] != facts["adapter"]
        or d["wire"] != facts["wire"]
    ):
        raise StorageOwnershipError("Configuration generation fenced")
    if d["schema"] == 2:
        from core.storage_installation_source import require_boot

        require_boot(d)
    return dict(row)


@dataclass(frozen=True)
class ConfigurationSnapshot:
    generation_id: str
    revision: int
    trust_pem: str = field(repr=False)
    secrets: dict = field(repr=False)
    source_material: object = field(default=None, repr=False)


def _capture_db(db, request):
    """One request's configuration; all connections close before decrypt/sign.

    The private read is reached only after a tenant-visible exact generation.
    Configuration writers serialize on LOCK before touching settings rows.
    """
    engine = db.get_bind()
    with engine.connect() as connection:
        ev = (
            connection.execute(
                text(
                    "SELECT facts,sha256 FROM storage_capability_evidence WHERE org_id=:org AND id=:id"
                ),
                dict(
                    org=request["org_id"],
                    id=request["plan"]["capability_evidence"]["id"],
                ),
            )
            .mappings()
            .one_or_none()
        )
        if (
            ev is None
            or ev["sha256"] != request["plan"]["capability_evidence"]["sha256"]
        ):
            raise StorageOwnershipError("Configuration evidence unavailable")
        if (
            ev["facts"]["target"] != request["plan"]["target"]
            or ev["facts"]["profile"] != request["plan"]["capability_profile"]
        ):
            raise StorageOwnershipError("Configuration plan differs")
        generation = require_generation(connection, request["org_id"], ev["facts"])
        # This separate read-only connection has no owner locks. The first
        # connection's configuration lock keeps the two credential rows stable.
        with PlatformContext(), engine.connect() as reader:
            values = reader.execute(
                text(
                    "SELECT key,encrypted_value AS value FROM secrets_v3 "
                    "WHERE key IN ('storage.s3.access_key','storage.s3.secret_key') "
                    "UNION ALL SELECT key,value FROM settings_v3 WHERE key='storage.s3.trust_pem'"
                )
            ).all()
        material = dict(values)
        pem = material.pop("storage.s3.trust_pem", None)
        if (
            not isinstance(pem, str)
            or hashlib.sha256(pem.encode()).hexdigest()
            != generation["descriptor"]["trust_sha256"]
            or set(material) != {"storage.s3.access_key", "storage.s3.secret_key"}
            or any(not isinstance(v, str) or not v for v in material.values())
        ):
            raise StorageOwnershipError("Exact configuration material unavailable")
        return ConfigurationSnapshot(
            generation["id"],
            generation["revision"],
            pem,
            {k: SimpleNamespace(encrypted_value=v) for k, v in material.items()},
        )


def tls_context(snapshot):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=snapshot.trust_pem)
    return context


def capture(db, request):
    """Resolve a source without keeping any database connection across GET."""
    from core.storage_installation_source import resolve, require_boot

    engine = db.get_bind()
    with engine.connect() as connection:
        ev = (
            connection.execute(
                text(
                    "SELECT facts,sha256 FROM storage_capability_evidence WHERE org_id=:org AND id=:id"
                ),
                dict(
                    org=request["org_id"],
                    id=request["plan"]["capability_evidence"]["id"],
                ),
            )
            .mappings()
            .one_or_none()
        )
        if (
            ev is None
            or ev["sha256"] != request["plan"]["capability_evidence"]["sha256"]
            or ev["facts"]["target"] != request["plan"]["target"]
            or ev["facts"]["profile"] != request["plan"]["capability_profile"]
        ):
            raise StorageOwnershipError("Configuration evidence unavailable")
        facts = ev["facts"]
        generation = require_generation(connection, request["org_id"], facts)
    if generation["descriptor"]["schema"] == 1:
        return _capture_db(db, request)
    material = resolve(generation["descriptor"])
    with engine.connect() as connection:
        current = require_generation(connection, request["org_id"], facts)
        boot = require_boot(current["descriptor"])
        if current != generation or material.boot_id != boot.boot_id:
            raise StorageOwnershipError("Installation source changed")
    return ConfigurationSnapshot(
        generation["id"], generation["revision"], material.trust_pem, {}, material
    )
