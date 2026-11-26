"""
Shared dependencies for FastAPI routers.

Contains database session, authentication, and authorization utilities.
"""

from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import jwt
from jwt import InvalidTokenError
from typing import Optional
import os
import bcrypt
import secrets
import hashlib
import hmac

from models import User, Agent, AgentCertificate, ActivityLog
from database import get_db

# Auth configuration
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))


def jwt_secret() -> str:
    """The session signing key, or a hard failure.

    This deliberately has no default. A signing key with a value baked into
    published source is a key every reader of the repository holds, and it is
    reached precisely when someone forgets to set the real one — so the fallback
    removes the error that would have told them. A backend that refuses to start
    is a far better outcome than one that starts and signs sessions with a string
    from a public repo.

    Read on every call rather than cached: the value is cheap to fetch, and a
    cache would keep serving a stale key past a test's monkeypatch, which makes
    the test pass while exercising a different secret than it thinks.

    Raises:
        RuntimeError: if JWT_SECRET is unset or empty. This is not caught by the
            InvalidTokenError handlers around token verification, which is intentional —
            a misconfigured server should fail loudly, not answer "invalid
            credentials" and look like a user error.
    """
    secret = os.getenv("JWT_SECRET", "")
    if not secret:
        raise RuntimeError(
            "JWT_SECRET is not set. Refusing to sign or verify session tokens. "
            "Generate one with: openssl rand -base64 32"
        )
    return secret


# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# Re-export get_db from database module for convenience
# Usage: from deps import get_db

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO format with UTC indicator for proper browser timezone handling"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================================================================
# AUTH UTILITIES
# ============================================================================


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_access_token(data: dict, db: Session = None) -> str:
    """Create JWT access token with configurable expiry"""
    from core.settings_reader import get_session_timeout_minutes

    to_encode = data.copy()

    # Get session timeout from settings (in minutes), fall back to JWT_EXPIRY_HOURS
    if db:
        timeout_minutes = get_session_timeout_minutes(db)
        expire = datetime.utcnow() + timedelta(minutes=timeout_minutes)
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, jwt_secret(), algorithm=JWT_ALGORITHM)
    return encoded_jwt


def require_enabled_organization(db: Session, user: User):
    """Account activity cannot override its persisted organization's suspension."""
    from models import Organization

    organization = db.get(Organization, user.org_id)
    if organization is None or not organization.enabled:
        raise HTTPException(status_code=401, detail="Organization unavailable")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        if username is None or user_id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    from core.tenant_context import commercial_mode, get_current_org

    query = db.query(User).filter(User.username == username)
    if commercial_mode():
        user_id = payload.get("user_id")
        if not user_id or payload.get("org_id") != get_current_org():
            raise credentials_exception
        query = query.filter(User.id == user_id, User.org_id == get_current_org())
    user = query.first()
    if user is None or str(user.id) != str(user_id):
        raise credentials_exception

    # Check if user account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    require_enabled_organization(db, user)
    return user


# ============================================================================
# RBAC - Role-Based Access Control
# ============================================================================


def check_role(current_user: User, allowed_roles: list):
    """Check if user has required role, raise 403 if not"""
    if current_user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Required role: {', '.join(allowed_roles)}. Your role: {current_user.role}",
        )


def require_role(*allowed_roles):
    """FastAPI dependency to require specific role"""

    def role_dependency(current_user: User = Depends(get_current_user)) -> User:
        check_role(current_user, list(allowed_roles))
        return current_user

    return role_dependency


def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure user is admin"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return current_user


def get_platform_admin(current_user: User = Depends(get_current_user)) -> User:
    """Platform authority is persisted separately from organization roles."""
    if not current_user.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform authority required")
    return current_user


async def get_platform_db(
    current_user: User = Depends(get_platform_admin), db: Session = Depends(get_db)
):
    """Explicit platform endpoint scope, after database-backed authority check."""
    from core.tenant_context import PlatformContext

    with PlatformContext():
        yield db


def get_installation_admin(current_user: User = Depends(get_current_user)) -> User:
    """Persisted OSS-default admin or commercial platform authority."""
    from core.tenant_context import commercial_mode

    commercial = commercial_mode()
    allowed = (
        current_user.is_platform_admin if commercial else current_user.role == "admin"
    )
    if allowed and not commercial:
        from database import SessionLocal
        from models import OrganizationDefault

        # Do not resolve the ambient tenant as the installation default: a
        # still-valid bearer may belong to another persisted organization.
        with SessionLocal() as db:
            assignment = db.get(OrganizationDefault, "oss")
            allowed = (
                assignment is not None and assignment.org_id == current_user.org_id
            )
    if not allowed:
        raise HTTPException(status_code=403, detail="Installation authority required")
    return current_user


async def get_installation_db(
    current_user: User = Depends(get_installation_admin),
):
    from database import SessionLocal
    from core.tenant_context import PlatformContext

    # Authentication used a tenant session. Administration gets a distinct
    # session so its writes cannot flush that session across an identity change.
    with PlatformContext(), SessionLocal() as db:
        yield db


async def get_organization_admin_db(
    org_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from core.tenant_context import TenantContext

    if not current_user.is_platform_admin and (
        current_user.role != "admin" or current_user.org_id != org_id
    ):
        raise HTTPException(
            status_code=403, detail="Organization admin authority required"
        )
    with TenantContext(org_id, current_user.id):
        yield db


def get_operator_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure user is operator or admin"""
    if current_user.role not in ["admin", "operator"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator or Admin access required",
        )
    return current_user


# ============================================================================
# AGENT AUTHENTICATION
# ============================================================================


def generate_agent_api_key() -> str:
    """Generate cryptographically secure agent API key"""
    return secrets.token_urlsafe(32)  # 256-bit key


def hash_api_key(api_key: str) -> str:
    """Hash API key for storage (like password hashing)"""
    return hashlib.sha256(api_key.encode()).hexdigest()


REQUIRE_MTLS = os.getenv("REQUIRE_MTLS", "false").lower() == "true"


import logging as _logging  # noqa: E402

_auth_logger = _logging.getLogger("vnbui.auth")


def _unique_credential(query):
    """Legacy credential columns may collide; never select an arbitrary owner.

    Read at most two matching rows before any expiry filtering or mutation.
    Ambiguity is terminal, including when another authentication method exists.
    """
    matches = query.limit(2).all()
    if len(matches) > 1:
        raise HTTPException(401, "Ambiguous credential ownership")
    return matches[0] if matches else None


def _verify_agent_cert(fingerprint: Optional[str], db: Session) -> Optional[Agent]:
    """Verify agent via client cert fingerprint. Returns Agent or None."""
    if not fingerprint:
        return None

    cert = _unique_credential(
        db.query(AgentCertificate).filter(AgentCertificate.fingerprint == fingerprint)
    )

    if not cert or cert.status != "active":
        _auth_logger.debug(
            f"Cert auth failed: no active certificate with fingerprint {fingerprint[:16]}..."
        )
        return None

    # Check expiry
    if cert.expires_at is None or cert.expires_at <= datetime.utcnow():
        _auth_logger.warning(
            f"Cert auth failed: certificate {fingerprint[:16]}... expired at {cert.expires_at}"
        )
        return None

    agent = db.query(Agent).filter(Agent.id == cert.agent_id).first()
    if agent is None or agent.cert_fingerprint != fingerprint:
        return None
    return agent


def agent_key_usable(db, agent, digest, *, lock=False):
    """Legacy-only agents remain supported; present metadata is authoritative too."""
    from models import AgentAPIKey

    if (
        not agent
        or not digest
        or not hmac.compare_digest(agent.api_key_hash or "", digest)
    ):
        return False
    query = (
        db.query(AgentAPIKey)
        .filter(AgentAPIKey.agent_id == agent.id)
        .populate_existing()
    )
    if lock:
        query = query.with_for_update()
    key = _unique_credential(query)
    if key is None:
        return True  # An old installation can genuinely have only legacy fields.
    return bool(
        key.enabled
        and not key.is_expired()
        and hmac.compare_digest(key.key_hash or "", digest)
    )


def _authenticate_agent(
    x_agent_key: Optional[str],
    x_client_cert_fingerprint: Optional[str],
    db: Session,
) -> Agent:
    """
    Verify agent identity via mTLS cert or API key (dual-mode).

    Priority:
    1. mTLS client cert fingerprint from the verified TLS transport
    2. API key (via X-Agent-Key header)

    If REQUIRE_MTLS=true, API key fallback is disabled.
    """
    # Try mTLS first
    if x_client_cert_fingerprint:
        agent = _verify_agent_cert(x_client_cert_fingerprint, db)
        if agent:
            return agent
        # Cert was provided but verification failed
        _auth_logger.debug(
            "mTLS cert provided but verification failed, checking fallback"
        )

    # If mTLS required and cert auth failed, reject
    if REQUIRE_MTLS:
        raise HTTPException(
            status_code=401, detail="mTLS authentication required (REQUIRE_MTLS=true)"
        )

    # Fall back to API key
    if not x_agent_key:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication: X-Agent-Key or verified client certificate required",
        )

    key_hash = hash_api_key(x_agent_key)
    agent = _unique_credential(db.query(Agent).filter(Agent.api_key_hash == key_hash))

    if not agent or not agent_key_usable(db, agent, key_hash):
        raise HTTPException(status_code=403, detail="Invalid agent API key")

    return agent


async def verify_agent_api_key(
    x_agent_key: str = Header(None, alias="X-Agent-Key"),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Resolve a credential globally, then scope the entire handler to its owner.

    The lookup session never reaches the handler. No caller-supplied organization
    or agent id selects authority, and platform scope ends before tenant work.
    Async yield keeps the context in the request task, including background tasks.
    """
    from database import SessionLocal
    from core.task_lifetime import run_owned_worker
    from core.tenant_context import PlatformContext, TenantContext
    from core.verified_tls import verified_peer

    fingerprint = verified_peer(request.scope) if request is not None else None
    if REQUIRE_MTLS and fingerprint is None:
        raise HTTPException(401, "Verified certificate transport unavailable")

    def resolve_credential():
        with PlatformContext(), SessionLocal() as lookup:
            authenticated = _authenticate_agent(
                None if fingerprint else x_agent_key, fingerprint, lookup
            )
            return authenticated.id, authenticated.org_id

    # Certificate/key lookup can wait on PostgreSQL. Keep that synchronous
    # work off the API loop while retaining this task's tenant context through
    # the handler and its background work.
    agent_id, org_id = await run_owned_worker(resolve_credential)
    with TenantContext(org_id):

        def mark_used():
            agent = db.get(
                Agent, agent_id, populate_existing=True, with_for_update=True
            )
            if agent is None:
                raise HTTPException(403, "Authenticated agent is no longer available")
            if fingerprint:
                certified = _verify_agent_cert(fingerprint, db)
                if certified is None or certified.id != agent.id:
                    raise HTTPException(
                        401, "Authenticated certificate is no longer current"
                    )
            elif not agent_key_usable(db, agent, hash_api_key(x_agent_key), lock=True):
                raise HTTPException(401, "Authenticated agent key is no longer current")
            agent.key_last_used_at = datetime.utcnow()
            db.commit()
            return agent

        agent = await run_owned_worker(mark_used)
        yield agent


async def registration_database(
    api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Registration belongs to the key issuer's persisted organization."""
    from database import SessionLocal
    from models import AgentRegistrationKey
    from core.tenant_context import PlatformContext, TenantContext

    if not api_key:
        raise HTTPException(401, "Registration key required")
    with PlatformContext(), SessionLocal() as lookup:
        record = _unique_credential(
            lookup.query(AgentRegistrationKey).filter(
                AgentRegistrationKey.key_hash == hash_api_key(api_key)
            )
        )
        if record is None:
            raise HTTPException(401, "Invalid registration key")
        issuer = lookup.get(User, record.created_by)
        if not record.is_valid() or issuer is None or not issuer.is_active:
            raise HTTPException(401, "Invalid registration key or issuer")
        org_id = issuer.org_id
    with TenantContext(org_id):
        yield db


# ============================================================================
# ACTIVITY LOGGING
# ============================================================================


def log_activity(
    db: Session,
    user: User,
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    details: dict = None,
    *,
    commit: bool = True,
):
    """
    Log user activity to audit trail

    Args:
        db: Database session
        user: Current user
        action: Action performed (e.g., "backup_created", "vm_group_deleted")
        resource_type: Type of resource (e.g., "backup", "vm_group")
        resource_id: ID of affected resource
        details: Additional context as dictionary
        commit: Commit by default; False flushes into the caller-owned transaction
    """
    log = ActivityLog(
        user_id=user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details if details else {},
    )
    db.add(log)
    if commit:
        db.commit()
    else:
        db.flush()
