"""
Helper functions for integration and security tests
Provides utilities for creating test data with proper tenant isolation
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional
import jwt

from database import SessionLocal
from models import Organization, Backup, VM, Agent, User
from core.tenant_context import TenantContext, AdminContext
from deps import jwt_secret, JWT_ALGORITHM
import bcrypt


def create_test_token(
    org_id: str, user_id: str, username: str = None, role: str = "user"
) -> str:
    """
    Create JWT token for testing

    Args:
        org_id: Organization ID
        user_id: User ID
        username: Username (defaults to user_id)
        role: User role (admin, operator, viewer)

    Returns:
        JWT token string
    """
    payload = {
        "sub": username or f"test-{user_id}",
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }

    return jwt.encode(payload, jwt_secret(), algorithm=JWT_ALGORITHM)


def create_test_org(name: str, parent_id: Optional[str] = None) -> Organization:
    """
    Create test organization

    Args:
        name: Organization name
        parent_id: Optional parent organization ID

    Returns:
        Created Organization object
    """
    db = SessionLocal()
    try:
        with AdminContext():
            org = Organization(
                id=str(uuid.uuid4()),
                name=name,
                parent_id=parent_id,
                enabled=True,
                settings={},
                branding={},
                limits={},
            )
            db.add(org)
            db.commit()
            db.refresh(org)
            return org
    finally:
        db.close()


def create_test_user(
    org_id: str,
    username: str,
    password: str = "test123",
    role: str = "viewer",
    platform_admin: bool = False,
) -> User:
    """
    Create test user in specific organization

    Args:
        org_id: Organization ID
        username: Username
        password: Password (hashed automatically)
        role: User role

    Returns:
        Created User object
    """
    db = SessionLocal()
    try:
        with TenantContext(org_id):
            # Hash password
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            user = User(
                id=str(uuid.uuid4()),
                username=username,
                password_hash=password_hash,
                role=role,
                org_id=org_id,
                is_platform_admin=platform_admin,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            return user
    finally:
        db.close()


def create_test_agent(org_id: str, hostname: str, status: str = "online") -> Agent:
    """
    Create test agent in specific organization

    Args:
        org_id: Organization ID
        hostname: Agent hostname
        status: Agent status (online, offline, error)

    Returns:
        Created Agent object
    """
    db = SessionLocal()
    try:
        with TenantContext(org_id):
            agent = Agent(
                id=str(uuid.uuid4()),
                hostname=hostname,
                status=status,
                org_id=org_id,
                version="2.1.0",
            )
            db.add(agent)
            db.commit()
            db.refresh(agent)
            return agent
    finally:
        db.close()


def create_test_vm(
    org_id: str,
    agent_id: str,
    name: str,
    uuid_str: Optional[str] = None,
    *,
    provider: Optional[str] = None,
) -> VM:
    """
    Create test VM in specific organization

    Args:
        org_id: Organization ID
        agent_id: Agent ID managing this VM
        name: VM name
        uuid_str: Optional VM UUID (generated if not provided)
        provider: Provider recorded at insertion (legacy NULL by default)

    Returns:
        Created VM object
    """
    db = SessionLocal()
    try:
        with TenantContext(org_id):
            vm = VM(
                id=str(uuid.uuid4()),
                name=name,
                uuid=uuid_str or str(uuid.uuid4()),
                provider=provider,
                agent_id=agent_id,
                org_id=org_id,
                vcpu_count=2,
                memory_kb=2048 * 1024,
                state="running",
                disks=[
                    {"target": "vda", "format": "qcow2", "source": "/test/disk.qcow2"}
                ],
            )
            db.add(vm)
            db.commit()
            db.refresh(vm)
            return vm
    finally:
        db.close()


def create_test_backup(
    org_id: str, vm_id: str, status: str = "completed", *, initiating_user_id=None
) -> Backup:
    """
    Create test backup in specific organization

    Args:
        org_id: Organization ID
        vm_id: VM ID to backup
        status: Backup status (pending, running, completed, failed)

    Returns:
        Created Backup object
    """
    db = SessionLocal()
    try:
        with TenantContext(org_id):
            backup = Backup(
                authority_kind="human" if initiating_user_id else "legacy_held",
                id=str(uuid.uuid4()),
                initiating_user_id=initiating_user_id,
                vm_id=vm_id,
                status=status,
                org_id=org_id,
                retention_days=30,
                progress=100 if status == "completed" else 0,
                size_bytes=1024 * 1024 * 100 if status == "completed" else 0,  # 100 MB
            )
            if initiating_user_id is None:
                seed_historical_authority_record(backup)
                return db.get(Backup, backup.id)
            db.add(backup)
            db.commit()
            db.refresh(backup)
            return backup
    finally:
        db.close()


def cleanup_test_org(org_id: str):
    """
    Clean up test organization and all associated data

    Args:
        org_id: Organization ID to clean up
    """
    db = SessionLocal()
    try:
        with AdminContext():
            # Retained custody is deliberately undeletable, even in fixtures.
            # Only the disposable runner's whole-database teardown removes it.
            from models import OperatorRequest

            if (
                db.query(OperatorRequest.id)
                .filter(OperatorRequest.org_id == org_id)
                .first()
            ) or (
                db.query(Backup.id)
                .filter(Backup.org_id == org_id, Backup.capacity_state != "unreserved")
                .first()
            ):
                import os
                from sqlalchemy.engine import make_url

                assert os.environ.get("VNBUI_DISPOSABLE_POSTGRES") == "1"
                assert make_url(os.environ["DATABASE_URL"]).database.startswith(
                    "vnbui_acceptance_"
                )
                return
            # Delete in reverse FK order
            from models import ActivityLog, OIDCLoginState

            db.query(OIDCLoginState).filter(OIDCLoginState.org_id == org_id).delete()
            db.query(ActivityLog).filter(
                ActivityLog.user_id.in_(db.query(User.id).filter(User.org_id == org_id))
            ).delete(synchronize_session=False)
            db.query(Backup).filter(Backup.org_id == org_id).delete()
            db.query(VM).filter(VM.org_id == org_id).delete()
            db.query(Agent).filter(Agent.org_id == org_id).delete()
            db.query(User).filter(User.org_id == org_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
    finally:
        db.close()


def cleanup_test_data(org_ids: list):
    """
    Clean up multiple test organizations

    Args:
        org_ids: List of organization IDs to clean up
    """
    for org_id in org_ids:
        try:
            cleanup_test_org(org_id)
        except Exception as e:
            print(f"Warning: Failed to cleanup {org_id}: {e}")


def get_db_org_count() -> int:
    """Get total number of organizations in database"""
    db = SessionLocal()
    try:
        with AdminContext():
            return db.query(Organization).count()
    finally:
        db.close()


def verify_rls_enabled(table_name: str) -> bool:
    """
    Verify that Row-Level Security is enabled on table

    Args:
        table_name: Table name to check

    Returns:
        True if RLS is enabled
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text

        with AdminContext():
            result = db.execute(
                text(
                    f"""
                SELECT relrowsecurity
                FROM pg_class
                WHERE relname = '{table_name}'
            """
                )
            ).fetchone()

            return result[0] if result else False
    finally:
        db.close()


def count_audit_entries(table_name: str = None, org_id: str = None) -> int:
    """
    Count audit log entries

    Args:
        table_name: Optional filter by table
        org_id: Optional filter by organization

    Returns:
        Number of audit entries
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text

        with AdminContext():
            query = "SELECT COUNT(*) FROM access_audit WHERE 1=1"
            params = {}

            if table_name:
                query += " AND table_name = :table_name"
                params["table_name"] = table_name

            if org_id:
                query += " AND org_id = :org_id"
                params["org_id"] = org_id

            result = db.execute(text(query), params).fetchone()
            return result[0] if result else 0
    finally:
        db.close()


def seed_historical_authority_record(backup):
    """Owner-only construction of pre-migration history in a disposable test DB.

    Runtime acceptance cannot insert actorless history. This fixture uses only
    the test-service owner; negative tests still exercise the untouched runtime.
    """
    import os
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session

    runtime = make_url(os.environ["DATABASE_URL"])
    assert os.environ.get("VNBUI_DISPOSABLE_POSTGRES") == "1"
    assert runtime.database.startswith("vnbui_acceptance_")
    owner = make_url(os.environ["SCHEMA_PARITY_TEST_ADMIN_URL"])
    assert (owner.host, owner.port, owner.query) == (
        runtime.host,
        runtime.port,
        runtime.query,
    )
    table = backup.__table__.name
    assert table in {"backups", "backup_queue"}
    engine = create_engine(owner.set(database=runtime.database))
    try:
        with Session(engine, expire_on_commit=False) as db:
            db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER scheduler_authority"))
            backup.authority_kind = "legacy_held"
            assert backup.initiating_user_id is None
            db.add(backup)
            db.flush()
            # Drain deferred validation before restoring fixture-owner triggers.
            db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER scheduler_authority"))
            db.commit()
    finally:
        engine.dispose()


def reserve_test_capacity(org_id, backup_id):
    """Explicit fixture prerequisite, using the real restricted-runtime service.

    Installation configuration is separate from tenant execution. No reservation
    identity/admission or terminal evidence is seeded by the database owner.
    """
    import os
    from sqlalchemy.engine import make_url
    from core.tenant_context import PlatformContext
    from core.settings_service import SettingsService
    from core.backup_capacity import reserve_capacity
    from models import SettingV3

    assert os.environ.get("VNBUI_DISPOSABLE_POSTGRES") == "1"
    assert make_url(os.environ["DATABASE_URL"]).database.startswith("vnbui_acceptance_")
    with PlatformContext(), SessionLocal() as db:
        if db.get(SettingV3, "backup.capacity_admission") is None:
            SettingsService(db).set(
                "backup.capacity_admission",
                dict(schema=1, revision=1, limit=100000, maintenance=False),
            )
    with TenantContext(org_id):
        return reserve_capacity(SessionLocal, backup_id)
