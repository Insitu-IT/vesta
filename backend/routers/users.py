"""
User management endpoints: CRUD operations for user accounts.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Annotated
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from database import get_db
from models import User, Organization, generate_uuid
from deps import get_admin_user, log_activity, iso_utc, hash_password
from schemas import UserCreate, UserUpdate
from core.password_validator import validate_password

router = APIRouter(prefix="/api/v1", tags=["users"])


def locked_user_mutation(db: Session, actor: User, user_id: str):
    """Serialize tenant user mutations; READ COMMITTED rechecks follow the lock.

    The transaction lock is released only by endpoint commit/rollback. It grants
    no RLS bypass and is scoped by persisted organization, never display name.
    """
    actor_id, org_id = actor.id, actor.org_id
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"vnbui/users/{org_id}"},
    )
    actor = (
        db.query(User)
        .populate_existing()
        .filter(User.id == actor_id, User.org_id == org_id)
        .first()
    )
    if actor is None or not actor.is_active:
        raise HTTPException(401, "User authority is no longer available")
    organization = db.get(Organization, org_id, populate_existing=True)
    if organization is None or not organization.enabled:
        raise HTTPException(401, "Organization unavailable")
    if actor.role != "admin":
        raise HTTPException(403, "Admin authority required")
    target = (
        db.query(User)
        .populate_existing()
        .filter(User.id == user_id, User.org_id == org_id)
        .first()
    )
    if target is None:
        raise HTTPException(404, "User not found")
    return actor, target


def require_remaining_admin(db: Session, org_id: str):
    """Count persisted active tenant roles, including OIDC and local pins."""
    if (
        not db.query(User)
        .filter(User.org_id == org_id, User.role == "admin", User.is_active.is_(True))
        .count()
    ):
        raise HTTPException(409, "At least one active tenant admin is required")


@router.get("/users")
async def list_users(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """List all users (admin only)"""
    # Enforce max limit
    limit = min(limit, 100)

    # Get total count
    total = db.query(User).count()

    # Get users with pagination
    users = (
        db.query(User)
        .order_by(User.created_at.desc(), User.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    # Build response
    items = [
        {
            "id": user.id,
            "username": user.username,
            "org_id": user.org_id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "auth_source": user.auth_source,
            "role_source": user.role_source,
            "oidc_subject": user.oidc_subject,
            "oidc_issuer": user.oidc_issuer,
            "last_login": iso_utc(user.last_login),
            "created_at": iso_utc(user.created_at),
        }
        for user in users
    ]

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Create a new user (admin only)"""
    # Check if username already exists
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User conflicts with an existing account",
        )

    # Validate password against configured rules
    is_valid, password_errors = validate_password(user_data.password, db)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet requirements: {'; '.join(password_errors)}",
        )

    # Validate role
    valid_roles = ["admin", "operator", "viewer"]
    if user_data.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}",
        )

    # Create user
    new_user = User(
        id=generate_uuid(),
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        full_name=user_data.full_name,
        email=user_data.email,
        is_active=user_data.is_active,
        auth_source="local",
        role_source="local",
    )

    try:
        db.add(new_user)
        db.flush()
        log_activity(
            db,
            admin_user,
            action="user_created",
            resource_type="user",
            resource_id=new_user.id,
            details={"username": new_user.username, "role": new_user.role},
            commit=False,
        )
        response = {
            "id": new_user.id,
            "username": new_user.username,
            "role": new_user.role,
            "created_at": iso_utc(new_user.created_at),
        }
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(400, "User conflicts with an existing account") from None
    except Exception:
        db.rollback()
        raise
    return response


@router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Get user details (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "auth_source": user.auth_source,
        "role_source": user.role_source,
        "oidc_subject": user.oidc_subject,
        "oidc_issuer": user.oidc_issuer,
        "last_login": iso_utc(user.last_login) if user.last_login else None,
        "created_at": iso_utc(user.created_at),
    }


@router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Update user (admin only)"""
    admin_user, user = locked_user_mutation(db, admin_user, user_id)

    # Track what changed for activity log
    if user.is_platform_admin and not admin_user.is_platform_admin:
        raise HTTPException(403, "Platform authority required to modify this account")
    fields = user_data.model_fields_set
    # Decide the complete mutation before touching ORM state. Provider identity
    # is not editable, even when a client sends its current value or null.
    if user.auth_source == "oidc":
        if fields & {"username", "full_name", "email", "password"}:
            raise HTTPException(400, "Provider-owned identity fields are immutable")
        if user_data.role_source == "local" and user_data.role is None:
            raise HTTPException(400, "A pinned local role is required")
        effective_source = user_data.role_source or user.role_source
        if effective_source != "local" and user_data.role is not None:
            raise HTTPException(
                400, "OIDC roles apply on next login; omit role override"
            )
    elif user_data.role_source not in (None, "local"):
        raise HTTPException(400, "Local users require local role source")
    if user.id == admin_user.id:
        if user_data.is_active is False:
            raise HTTPException(400, "Cannot deactivate your own account")
        if user_data.role is not None or (
            user_data.role_source is not None
            and user_data.role_source != user.role_source
        ):
            raise HTTPException(400, "Cannot change your own role authority")
    if user_data.password is not None:
        valid, errors = validate_password(user_data.password, db)
        if not valid:
            raise HTTPException(
                400, "Password does not meet requirements: " + "; ".join(errors)
            )
    if user_data.username is not None and user_data.username != user.username:
        duplicate = (
            db.query(User)
            .filter(User.username == user_data.username, User.id != user.id)
            .first()
        )
        if duplicate:
            raise HTTPException(400, "User conflicts with an existing account")
    changes = {}

    # Update username if provided (not allowed for OIDC users)
    if user_data.username is not None and user_data.username != user.username:
        if user.auth_source == "oidc":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change username for OIDC users",
            )
        old_username = user.username
        user.username = user_data.username
        changes["username"] = f"{old_username} -> {user_data.username}"

    # Update full_name if provided
    if "full_name" in fields:
        user.full_name = user_data.full_name
        changes["full_name"] = "updated"

    # Update email if provided
    if "email" in fields:
        user.email = user_data.email
        changes["email"] = "updated"

    # Update is_active if provided
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
        changes["is_active"] = str(user_data.is_active)

    # Update password if provided (not for OIDC users)
    if user_data.password:
        if user.auth_source == "oidc":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot set password for OIDC users",
            )
        user.password_hash = hash_password(user_data.password)
        changes["password"] = "updated"

    # Update role if provided
    if user_data.role:
        valid_roles = ["admin", "operator", "viewer"]
        if user_data.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}",
            )

        # Prevent changing your own role (stupidproof)
        if user.id == admin_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change your own role (security: prevents accidental lockout)",
            )

        old_role = user.role
        user.role = user_data.role
        changes["role"] = f"{old_role} -> {user_data.role}"

    # Update role_source if provided (for OIDC users only)
    if user_data.role_source is not None:
        valid_sources = ["local", "oidc"]
        if user_data.role_source not in valid_sources:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role_source. Must be one of: {', '.join(valid_sources)}",
            )
        old_source = user.role_source
        user.role_source = user_data.role_source
        changes["role_source"] = f"{old_source} -> {user_data.role_source}"
    if user.auth_source != "oidc":
        user.role_source = "local"

    response = {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "auth_source": user.auth_source,
        "role_source": user.role_source,
        "oidc_subject": user.oidc_subject,
        "oidc_issuer": user.oidc_issuer,
        "created_at": iso_utc(user.created_at),
    }
    try:
        db.flush()
        require_remaining_admin(db, admin_user.org_id)
        log_activity(
            db,
            admin_user,
            action="user_updated",
            resource_type="user",
            resource_id=user.id,
            details={"username": user.username, "changes": changes},
            commit=False,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(400, "User conflicts with an existing account") from None
    except Exception:
        db.rollback()
        raise
    return response


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Delete user (admin only)"""
    admin_user, user = locked_user_mutation(db, admin_user, user_id)

    # Prevent deleting self
    if user.is_platform_admin and not admin_user.is_platform_admin:
        raise HTTPException(403, "Platform authority required to modify this account")
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    username = user.username

    try:
        db.delete(user)
        db.flush()
        require_remaining_admin(db, admin_user.org_id)
        log_activity(
            db,
            admin_user,
            action="user_deleted",
            resource_type="user",
            resource_id=user_id,
            details={"username": username},
            commit=False,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "User has retained references and cannot be deleted"
        ) from None
    except Exception:
        db.rollback()
        raise

    return {"message": f"User {username} deleted successfully"}
