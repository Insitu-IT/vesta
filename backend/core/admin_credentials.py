"""Managed initial-admin bootstrap and recovery primitives."""

from pathlib import Path

from core.password_validator import validate_password
from deps import hash_password
from models import SystemEvent, User
from sqlalchemy.orm import Session
from sqlalchemy import text


def recover_platform_access(
    db: Session, org_id: str, username: str, password_file: str, reason: str
) -> str:
    """Operator-only recovery of explicit platform authority.

    This is not called by HTTP startup, user CRUD, OIDC or role mapping. The
    operator must select an existing local administrator by persisted org ID.
    Audit and authority commit together; failure leaves neither committed.
    """
    from core.tenant_context import PlatformContext, _validate_org_id
    from models import Organization

    _validate_org_id(org_id)
    if org_id == "default" or not reason.strip():
        raise RuntimeError("Explicit organization UUID and audit reason required")
    with PlatformContext():
        if db.bind.dialect.name == "postgresql":
            # Serialize the zero-active-authorities predicate with user changes.
            db.execute(text("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE"))
        if (
            db.query(User)
            .filter(User.is_platform_admin.is_(True), User.is_active.is_(True))
            .first()
        ):
            raise RuntimeError("An active platform authority already exists")
        organization = db.get(Organization, org_id)
        if organization is None or not organization.enabled:
            raise RuntimeError("Organization must exist and be active")
        user = db.query(User).filter_by(org_id=org_id, username=username).one_or_none()
        if user is None or user.auth_source != "local" or user.role != "admin":
            raise RuntimeError(
                "Recovery target must be an existing local organization admin"
            )
        password = _validated_password(db, password_file)
        user.password_hash = hash_password(password)
        user.is_active = True
        user.is_platform_admin = True
        db.add(
            SystemEvent(
                event_type="platform_authority_recovered",
                attribution="platform",
                source="operator_command",
                resource_type="user",
                resource_id=user.id,
                details={"org_id": org_id, "reason": reason, "username": username},
            )
        )
        user_id = user.id
        db.commit()
        return user_id


def read_password_file(path: str) -> str:
    """Read a password from a mounted secret file without altering spaces."""
    try:
        password = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise RuntimeError(f"Cannot read admin password file {path!r}: {exc}") from exc
    if not password:
        raise RuntimeError(f"Admin password file {path!r} is empty")
    return password


def _validated_password(db: Session, password_file: str) -> str:
    password = read_password_file(password_file)
    valid, errors = validate_password(password, db)
    if not valid:
        raise RuntimeError("Initial admin password is invalid: " + "; ".join(errors))
    return password


def ensure_initial_admin(
    db: Session,
    username: str | None,
    password_file: str | None,
) -> bool:
    """Create the first admin from an explicit managed secret.

    Populated databases do not require bootstrap inputs. An empty user table
    fails closed unless both inputs are present.
    """
    if db.query(User).count() != 0:
        return False
    if not username or not password_file:
        raise RuntimeError(
            "User table is empty; set INITIAL_ADMIN_USERNAME and "
            "INITIAL_ADMIN_PASSWORD_FILE to a managed secret file"
        )

    password = _validated_password(db, password_file)
    db.add(
        User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            auth_source="local",
            role_source="local",
            is_active=True,
        )
    )
    db.commit()
    return True


def reset_existing_admin(db: Session, username: str, password_file: str) -> None:
    """Reset an existing local admin using a password file.

    This deliberately cannot create or promote a user. Recovery of a missing
    admin is a different, higher-authority operation than password recovery.
    """
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise RuntimeError(f"Admin user {username!r} does not exist")
    if user.role != "admin" or user.auth_source != "local":
        raise RuntimeError(f"User {username!r} is not a local admin")

    password = _validated_password(db, password_file)
    user.password_hash = hash_password(password)
    user.is_active = True
    db.add(
        SystemEvent(
            event_type="admin_password_recovered",
            source="system",
            resource_type="user",
            resource_id=user.id,
            details={"username": username},
        )
    )
    db.commit()


def recover_missing_admin(db: Session, username: str, password_file: str) -> None:
    """Restore admin access only when no active administrator exists."""
    active_admin = (
        db.query(User).filter(User.role == "admin", User.is_active.is_(True)).first()
    )
    if active_admin is not None:
        raise RuntimeError(
            "An active administrator already exists; use the authenticated user API"
        )

    password = _validated_password(db, password_file)
    user = db.query(User).filter(User.username == username).first()
    action = "reactivated"
    if user is None:
        action = "created"
        user = User(
            username=username,
            auth_source="local",
            role_source="local",
        )
        db.add(user)
    elif user.auth_source != "local" or user.role != "admin":
        raise RuntimeError(f"User {username!r} is not a disabled local admin")

    user.password_hash = hash_password(password)
    user.role = "admin"
    user.role_source = "local"
    user.is_active = True
    db.flush()
    db.add(
        SystemEvent(
            event_type="admin_access_recovered",
            source="system",
            resource_type="user",
            resource_id=user.id,
            details={"username": username, "action": action},
        )
    )
    db.commit()
