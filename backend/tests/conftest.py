"""Shared test fixtures for vnbui backend tests.

Provides:
- In-memory SQLite database with JSONB→JSON monkey-patch
- Session factory, db_session, auto-cleanup
- patch_session_local for KMS/database module patching
- Test data builders: make_agent, make_vm, make_backup, make_group
"""

import os
import secrets
import sys
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, event, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch

# Add backend and agent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent"))

TEST_FERNET_KEY = Fernet.generate_key().decode()

# deps.jwt_secret() has no default and raises when JWT_SECRET is unset, so any
# test touching the auth path needs one. Set at import rather than in a fixture:
# conftest is imported before collection, which also covers modules that read the
# key while being imported. Random per run — a fixed literal here is the kind of
# value that ends up copied into a deployment.
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))


@pytest.fixture(autouse=True)
def set_encryption_env(monkeypatch):
    """Set VNBUI_ENCRYPTION_KEY for all tests."""
    monkeypatch.setenv("VNBUI_ENCRYPTION_KEY", TEST_FERNET_KEY)


@pytest.fixture
def db_engine():
    """Create a shared in-memory SQLite database with all tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.close()

    # Monkey-patch JSONB → JSON so SQLite can create the tables
    from models import Base

    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, JSONB):
                col.type = JSON()

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(db_engine):
    """Session factory bound to shared test DB."""
    return sessionmaker(bind=db_engine)


@pytest.fixture(autouse=True)
def _clean_db(db_engine, session_factory):
    """Clean all data before each test for isolation."""
    from models import Base, Organization, OrganizationDefault

    s = session_factory()
    for table in reversed(Base.metadata.sorted_tables):
        s.execute(table.delete())
    # Unit fixtures supply the data a real install receives through Alembic.
    # This is not the PostgreSQL migration-parity acceptance surface.
    org = Organization(name="Unit test OSS organization")
    s.add(org)
    s.flush()
    s.add(OrganizationDefault(slot="oss", org_id=org.id))
    s.commit()
    s.close()


@pytest.fixture
def db_session(session_factory):
    """Create a test DB session."""
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def patch_session_local(session_factory):
    """Patch SessionLocal everywhere it's imported — both database module and local.py's copy."""
    with patch("database.SessionLocal", session_factory), patch(
        "database.SyncSessionLocal", session_factory
    ), patch("core.kms.local.SessionLocal", session_factory):
        yield session_factory


# ═══════════════════════════════════════════════════════════════════════════════
# Test data builders
# ═══════════════════════════════════════════════════════════════════════════════


def make_agent(db_session, hostname=None, **kwargs):
    """Create a minimal agent."""
    from models import Agent

    defaults = dict(
        id=str(uuid.uuid4()),
        hostname=hostname or f"host-{uuid.uuid4().hex[:6]}",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    defaults.update(kwargs)
    agent = Agent(**defaults)
    db_session.add(agent)
    db_session.commit()
    return agent


def make_vm(db_session, agent, name=None, **kwargs):
    """Create a minimal VM linked to an agent."""
    from models import VM

    defaults = dict(
        id=str(uuid.uuid4()),
        name=name or f"vm-{uuid.uuid4().hex[:6]}",
        agent_id=agent.id,
        state="running",
        uuid=str(uuid.uuid4()),
        memory_kb=2048,
        vcpu_count=2,
        disks=[{"target": "vda", "format": "qcow2"}],
    )
    defaults.update(kwargs)
    vm = VM(**defaults)
    db_session.add(vm)
    db_session.commit()
    return vm


def make_backup(db_session, vm, **kwargs):
    """Create a backup record with sensible defaults."""
    from models import Backup

    defaults = dict(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="pending",
        backup_type="full",
        tags={},
        storage_path=f"file:///var/lib/vnbui/backups/{uuid.uuid4()}",
    )
    defaults.update(kwargs)
    backup = Backup(**defaults)
    db_session.add(backup)
    db_session.commit()
    db_session.refresh(backup)
    return backup


def make_group(db_session, name=None, **kwargs):
    """Create a VM group."""
    from models import VMGroup

    defaults = dict(
        id=str(uuid.uuid4()),
        name=name or f"grp-{uuid.uuid4().hex[:6]}",
        group_type="static",
        rules=None,
        rules_match="all",
    )
    defaults.update(kwargs)
    group = VMGroup(**defaults)
    db_session.add(group)
    db_session.commit()
    return group
