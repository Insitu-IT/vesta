import pytest
from core.admin_credentials import (
    ensure_initial_admin,
    recover_missing_admin,
    reset_existing_admin,
)
from deps import verify_password
from models import Base, Organization, OrganizationDefault, SystemEvent, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.mark.parametrize(
    "commercial,role,platform,allowed",
    [
        (False, "admin", False, True),
        (False, "operator", False, False),
        (False, "viewer", True, False),
        (True, "admin", False, False),
        (True, "operator", False, False),
        (True, "viewer", True, True),
    ],
)
def test_installation_authority_keeps_oss_and_platform_roles_distinct(
    monkeypatch, commercial, role, platform, allowed
):
    from core import tenant_context
    from deps import get_installation_admin
    from fastapi import HTTPException
    from unittest.mock import MagicMock
    from types import SimpleNamespace

    monkeypatch.setattr(tenant_context, "commercial_mode", lambda: commercial)
    user = User(role=role, is_platform_admin=platform, org_id="oss-fixture")
    session = MagicMock()
    session.return_value.__enter__.return_value.get.return_value = SimpleNamespace(
        org_id=user.org_id
    )
    monkeypatch.setattr("database.SessionLocal", session)
    if allowed:
        assert get_installation_admin(user) is user
    else:
        with pytest.raises(HTTPException) as refusal:
            get_installation_admin(user)
        assert refusal.value.status_code == 403


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    organization = Organization(name="Admin unit-test organization")
    session.add(organization)
    session.flush()
    session.add(OrganizationDefault(slot="oss", org_id=organization.id))
    session.commit()
    try:
        yield session
    finally:
        session.close()


def password_file(tmp_path, value="Managed1!Password"):
    path = tmp_path / "admin-password"
    path.write_text(value + "\n", encoding="utf-8")
    return str(path)


def test_empty_database_requires_managed_bootstrap(db):
    with pytest.raises(RuntimeError, match="User table is empty"):
        ensure_initial_admin(db, None, None)


def test_bootstrap_creates_local_admin_from_file(db, tmp_path):
    path = password_file(tmp_path)
    assert ensure_initial_admin(db, "managed-admin", path) is True

    user = db.query(User).one()
    assert user.username == "managed-admin"
    assert user.role == "admin"
    assert user.auth_source == "local"
    assert user.is_active is True
    assert verify_password("Managed1!Password", user.password_hash)


def test_populated_database_does_not_require_bootstrap_secret(db):
    db.add(User(username="existing", password_hash="not-used", role="admin"))
    db.commit()
    assert ensure_initial_admin(db, None, None) is False


def test_reset_existing_admin_from_file(db, tmp_path):
    old_path = password_file(tmp_path, "Managed1!OldPassword")
    ensure_initial_admin(db, "managed-admin", old_path)
    user = db.query(User).one()
    user.is_active = False
    db.commit()

    new_path = password_file(tmp_path, "Managed2!NewPassword")
    reset_existing_admin(db, "managed-admin", new_path)
    db.refresh(user)
    assert user.is_active is True
    assert verify_password("Managed2!NewPassword", user.password_hash)
    assert user.id == db.query(User).one().id
    event = db.query(SystemEvent).one()
    assert event.event_type == "admin_password_recovered"
    assert event.resource_id == user.id


def test_reset_refuses_non_admin(db, tmp_path):
    db.add(User(username="operator", password_hash="not-used", role="operator"))
    db.commit()
    with pytest.raises(RuntimeError, match="not a local admin"):
        reset_existing_admin(db, "operator", password_file(tmp_path))


def test_password_file_must_satisfy_policy(db, tmp_path):
    with pytest.raises(RuntimeError, match="Initial admin password is invalid"):
        ensure_initial_admin(db, "managed-admin", password_file(tmp_path, "weak"))


def test_recover_access_creates_admin_only_when_none_active(db, tmp_path):
    recover_missing_admin(db, "recovery-admin", password_file(tmp_path))
    user = db.query(User).one()
    assert user.role == "admin"
    assert user.is_active is True
    event = db.query(SystemEvent).one()
    assert event.event_type == "admin_access_recovered"
    assert event.details == {"username": "recovery-admin", "action": "created"}

    with pytest.raises(RuntimeError, match="active administrator already exists"):
        recover_missing_admin(db, "another-admin", password_file(tmp_path))


def test_recover_access_reactivates_local_user(db, tmp_path):
    user = User(
        username="disabled-admin",
        password_hash="not-used",
        role="admin",
        is_active=False,
    )
    db.add(user)
    db.commit()

    recover_missing_admin(db, "disabled-admin", password_file(tmp_path))
    db.refresh(user)
    assert user.role == "admin"
    assert user.is_active is True
    assert verify_password("Managed1!Password", user.password_hash)
    event = db.query(SystemEvent).one()
    assert event.details == {"username": "disabled-admin", "action": "reactivated"}


def test_recover_access_refuses_to_promote_operator(db, tmp_path):
    db.add(
        User(
            username="operator",
            password_hash="not-used",
            role="operator",
            is_active=False,
        )
    )
    db.commit()

    with pytest.raises(RuntimeError, match="not a disabled local admin"):
        recover_missing_admin(db, "operator", password_file(tmp_path))
