"""Trusted installation readers, isolated from mutable tenant sessions."""

from core.tenant_context import PlatformContext
from sqlalchemy import select


def read_configuration(db, model, key=None):
    """Return plain rows only; never elevate or flush the caller's ORM session.

    The allowlist is the configuration domain, not an arbitrary privileged SQL
    interface. Public administration endpoints authorize before calling readers.
    Runtime S3/PKI/OIDC/notification consumers use this explicit read boundary.
    """
    from models import SettingV3, SecretV3, SystemSettings

    if model not in (SettingV3, SecretV3, SystemSettings):
        raise ValueError("Unsupported installation configuration table")
    statement = select(model.__table__)
    if key is not None:
        statement = statement.where(model.__table__.c.key == key)
    engine = db.get_bind()
    if engine.dialect.name != "postgresql":
        # SQLite's in-memory test database may share one physical connection.
        # Core execution avoids autoflush without closing that connection.
        return db.connection().execute(statement).all()
    with PlatformContext(), engine.connect() as connection:
        return connection.execute(statement).all()
