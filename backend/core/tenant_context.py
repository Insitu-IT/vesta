"""Authenticated identity; platform authority is trusted process scope only."""

from contextvars import ContextVar
import uuid

from fastapi import HTTPException
from sqlalchemy import text

current_org = ContextVar("current_org", default=None)
current_user_id = ContextVar("current_user_id", default=None)
is_superuser = ContextVar("platform_authority", default=False)
is_demo = ContextVar("demo_authority", default=False)


def _validate_org_id(value):
    if value == "default":
        return value  # OSS marker resolved from the persisted assignment.
    try:
        uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"Invalid organization ID format: {value}") from None
    return value


def _validate_user_id(value):
    try:
        uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"Invalid user ID format: {value}") from None
    return value


def commercial_mode():
    from core.licensing import features

    return features.profile.auth_mode == "multi_organization"


class TenantContext:
    def __init__(self, org_id, user_id=None, superuser=False):
        if superuser:
            raise ValueError("Use explicit PlatformContext for trusted maintenance")
        self.org_id, self.user_id = org_id, user_id

    def __enter__(self):
        self.tokens = (
            current_org.set(self.org_id),
            current_user_id.set(self.user_id),
            is_superuser.set(False),
            is_demo.set(False),
        )
        return self

    def __exit__(self, *args):
        for variable, token in zip(
            (current_org, current_user_id, is_superuser, is_demo), self.tokens
        ):
            variable.reset(token)


class PlatformContext(TenantContext):
    """Explicit trusted process operation, never an organization-admin role."""

    def __init__(self):
        super().__init__(None)

    def __enter__(self):
        super().__enter__()
        is_superuser.set(True)
        return self


AdminContext = PlatformContext


class DemoContext(TenantContext):
    """Synthetic storage capability, without tenant or platform authority.

    Only demo request dependencies, rate accounting and expiry workers enter it.
    Browser capabilities are still checked by DemoSessionService, never by a
    caller-supplied organization or an ordinary user role.
    """

    def __init__(self):
        super().__init__(None)

    def __enter__(self):
        super().__enter__()
        is_demo.set(True)
        return self


def get_current_org():
    return current_org.get()


def get_current_user_id():
    return current_user_id.get()


def identity():
    org, user, platform = current_org.get(), current_user_id.get(), is_superuser.get()
    if org is not None:
        _validate_org_id(org)
    if user is not None:
        _validate_user_id(user)
    if (
        not platform
        and not is_demo.get()
        and commercial_mode()
        and (org is None or org == "default")
    ):
        raise HTTPException(401, "Authenticated organization identity required")
    return org, user, platform


def install_cursor_context(cursor, paramstyle="pyformat"):
    """Overwrite every setting transaction-locally, including false/empty values."""
    org, user, platform = identity()
    if org is None or org == "default":
        if platform or is_demo.get():
            org = ""
        else:
            cursor.execute("SELECT org_id FROM organization_defaults WHERE slot='oss'")
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError(
                    "OSS assignment missing; run reviewed Alembic migration"
                )
            org = row[0]
    markers = (
        ("$1", "$2", "$3", "$4")
        if paramstyle == "numeric_dollar"
        else ("%s", "%s", "%s", "%s")
    )
    cursor.execute(
        f"SELECT set_config('app.current_org', {markers[0]}, true), "
        f"set_config('app.user_id', {markers[1]}, true), "
        f"set_config('app.platform_admin', {markers[2]}, true), "
        f"set_config('app.demo', {markers[3]}, true)",
        (
            org,
            user or "",
            "true" if platform else "false",
            "true" if is_demo.get() else "false",
        ),
    )


def set_db_session_context(session):
    # Engine hooks cover raw SQL, ORM, flushes and async adapted cursors alike.
    identity()
    session.execute(text("SELECT 1"))


def resolved_organization():
    """Resolve an event/job identity using the same persisted OSS assignment."""
    org, _, platform = identity()
    if platform:
        raise RuntimeError("Tenant event requires an explicit organization scope")
    if org is not None and org != "default":
        return org
    from database import SessionLocal
    from models import OrganizationDefault

    with SessionLocal() as db:
        assigned = db.get(OrganizationDefault, "oss")
        if assigned is None:
            raise RuntimeError("OSS organization assignment missing")
        return assigned.org_id


def extract_org_from_jwt(token):
    import jwt
    from deps import jwt_secret, JWT_ALGORITHM

    payload = jwt.decode(token, jwt_secret(), algorithms=[JWT_ALGORITHM])
    org = payload.get("org_id")
    if org is None or org == "default":
        raise ValueError("Token has no authenticated organization")
    return _validate_org_id(org)


async def tenant_middleware(request, call_next):
    from fastapi.responses import JSONResponse

    org, user = None, None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            import jwt
            from deps import jwt_secret, JWT_ALGORITHM

            payload = jwt.decode(auth[7:], jwt_secret(), algorithms=[JWT_ALGORITHM])
            user = _validate_user_id(payload.get("user_id"))
            if commercial_mode():
                org = extract_org_from_jwt(auth[7:])
        except Exception:
            return JSONResponse(
                {"detail": "Invalid tenant credentials"}, status_code=401
            )
    # Commercial bootstrap/agent paths must establish their own identity before
    # SQL. The testing header and role-name platform bypass do not exist here.
    with TenantContext(org, user):
        return await call_next(request)
