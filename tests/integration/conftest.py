"""Portable PostgreSQL acceptance fixtures."""

import os
from pathlib import Path

import pytest

_integration_dir = Path(__file__).parent


@pytest.fixture(scope="session")
def migrated_scheduler_template():
    """Migrate once; connected cases still own independent databases/roles."""
    from sqlalchemy import text
    from sqlalchemy import create_engine
    from tests.integration.test_schema_parity_pg import database, migrate

    assert os.environ.get("VNBUI_DISPOSABLE_POSTGRES") == "1"
    with database() as (url, owner):
        migrate(url)
        with owner.connect() as connection:
            # Fresh snapshots contain no backup data or environment-enrolled keys.
            assert connection.scalar(text("SELECT count(*) FROM backups")) == 0
            assert connection.scalar(text("SELECT count(*) FROM encryption_keys")) == 0
        owner.dispose()
        admin = create_engine(
            os.environ["SCHEMA_PARITY_TEST_ADMIN_URL"], isolation_level="AUTOCOMMIT"
        )
        try:
            with admin.connect() as connection:
                connection.execute(
                    text(f'ALTER DATABASE "{url.database}" ALLOW_CONNECTIONS false')
                )
            yield url
        finally:
            admin.dispose()


@pytest.fixture
def assert_backup_admission():
    """Read the real scoped receipt/outbox; never execute or complete the backup."""
    from database import SessionLocal
    from core.tenant_context import TenantContext
    from core.tenant_database import assert_non_bypass_role
    from models import Backup, OperatorRequest, OperatorDispatch

    def check(backup_id, org_id, actor_id, request_id):
        with TenantContext(org_id, actor_id), SessionLocal() as db:
            assert_non_bypass_role(db.connection())
            backup = db.query(Backup).filter_by(id=backup_id, org_id=org_id).one()
            receipt = (
                db.query(OperatorRequest)
                .filter_by(
                    org_id=org_id,
                    actor_id=actor_id,
                    request_id=request_id,
                )
                .one()
            )
            work = (
                db.query(OperatorDispatch)
                .filter_by(
                    org_id=org_id,
                    request_record_id=receipt.id,
                    kind="backup",
                    resource_id=backup_id,
                )
                .one()
            )
            assert receipt.action == "backup.create"
            assert receipt.completed_at is not None and receipt.response_status == 200
            assert receipt.response_body["id"] == backup_id
            assert receipt.response_body["request_id"] == request_id
            assert work.actor_id == actor_id and work.state == "pending"
            assert work.reason is None
            assert backup.initiating_user_id == actor_id
            assert backup.status == "pending" and backup.completed_at is None

    return check


@pytest.fixture
def platform_token():
    from tests.helpers import (
        create_test_org,
        create_test_user,
        create_test_token,
        cleanup_test_org,
    )

    org = create_test_org("Platform operator")
    try:
        user = create_test_user(
            org.id, "platform-operator", role="admin", platform_admin=True
        )
        yield create_test_token(org.id, user.id, user.username, role="admin")
    finally:
        cleanup_test_org(org.id)


def pytest_collection_modifyitems(config, items):
    for item in items:
        path = Path(str(item.fspath))
        if path.parent != _integration_dir:
            continue
        if path.name == "test_schema_parity_pg.py":
            # Required migration acceptance fails on absent configuration.
            continue
        if "postgresql" not in os.environ.get("DATABASE_URL", ""):
            item.add_marker(
                pytest.mark.skip(reason="Integration tests require PostgreSQL")
            )
