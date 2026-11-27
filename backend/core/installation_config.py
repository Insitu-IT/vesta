"""Trusted installation readers, isolated from mutable tenant sessions."""

from core.tenant_context import PlatformContext
from sqlalchemy import select

RECOVERY_SIGNING_SEED = "recovery.ed25519_seed.v1"
RECOVERY_SIGNER_IDENTITY = "recovery.signing_identity.v1"
RECOVERY_PUBLICATION_CURSOR = "recovery.publication_cursor.v1"
RESERVED_RECOVERY_SETTINGS = (
    RECOVERY_SIGNING_SEED,
    RECOVERY_SIGNER_IDENTITY,
    RECOVERY_PUBLICATION_CURSOR,
)


def read_configuration(db, model, key=None):
    """Return plain rows only; never elevate or flush the caller's ORM session.

    The allowlist is the configuration domain, not an arbitrary privileged SQL
    interface. Public administration endpoints authorize before calling readers.
    Runtime S3/PKI/OIDC/notification consumers use this explicit read boundary.
    """
    from models import SettingV3, SecretV3, SystemSettings

    if model not in (SettingV3, SecretV3, SystemSettings):
        raise ValueError("Unsupported installation configuration table")
    # Recovery signing custody has a separate installation-local reader. An
    # unfiltered list or exact generic lookup must not expose it.
    statement = select(model.__table__).where(
        model.__table__.c.key.notin_(RESERVED_RECOVERY_SETTINGS)
    )
    if key is not None:
        statement = statement.where(model.__table__.c.key == key)
    engine = db.get_bind()
    if engine.dialect.name != "postgresql":
        # SQLite's in-memory test database may share one physical connection.
        # Core execution avoids autoflush without closing that connection.
        return db.connection().execute(statement).all()
    with PlatformContext(), engine.connect() as connection:
        return connection.execute(statement).all()
