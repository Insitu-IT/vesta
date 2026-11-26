"""
Authentication endpoints: login, OIDC SSO.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import secrets
import os
import logging
from pydantic import BaseModel, ConfigDict, ValidationError

from database import get_db
from models import User
from deps import (
    get_current_user,
    verify_password,
    create_access_token,
    log_activity,
    iso_utc,
    get_installation_admin,
    require_enabled_organization,
)
from core.settings_service import SettingsService
from core.oidc_service import OIDCService

logger = logging.getLogger(__name__)


class AuthRoute(APIRoute):
    """Callback custody is cleared even when a dependency refuses admission."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def guarded(request):
            if request.url.path == "/api/v1/auth/login":
                try:
                    return await handler(request)
                except (HTTPException, RequestValidationError) as exc:
                    if isinstance(exc, HTTPException) and exc.status_code not in (
                        400,
                        401,
                        403,
                        422,
                    ):
                        raise
                    return JSONResponse(
                        {"detail": "Invalid credentials"},
                        status_code=401,
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            if request.url.path != "/api/v1/auth/oidc/callback":
                return await handler(request)
            try:
                response = await handler(request)
            except (HTTPException, RequestValidationError) as exc:
                response = HTMLResponse(
                    "<h1>Authentication Error</h1>",
                    status_code=(
                        exc.status_code if isinstance(exc, HTTPException) else 400
                    ),
                )
            except Exception:
                logger.error("OIDC callback failed")
                response = HTMLResponse(
                    "<h1>Authentication Error</h1>", status_code=500
                )
            response.delete_cookie("oidc_state")
            response.delete_cookie("oidc_pkce")
            return response

        return guarded


router = APIRouter(prefix="/api/v1/auth", tags=["auth"], route_class=AuthRoute)


async def login_database(
    org_id: str | None = Form(default=None), db: Session = Depends(get_db)
):
    """Select the credential namespace, then authenticate within that namespace.

    A supplied organization is not authority. It only selects which local
    username/password pair must validate; it grants no platform scope.
    """
    from core.tenant_context import TenantContext, commercial_mode, _validate_org_id

    if commercial_mode():
        try:
            if org_id is None or org_id == "default":
                raise ValueError("Organization required")
            _validate_org_id(org_id)
        except ValueError:
            raise HTTPException(401, "Valid organization required for login") from None
    elif org_id is not None:
        raise HTTPException(400, "OSS login uses the persisted default organization")
    with TenantContext(org_id):
        yield db


@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(login_database),
):
    """Login endpoint - returns JWT token"""
    from sqlalchemy.exc import MultipleResultsFound

    try:
        user = db.query(User).filter(User.username == form_data.username).one_or_none()
    except MultipleResultsFound:
        raise HTTPException(401, "Invalid credentials") from None

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    require_enabled_organization(db, user)

    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()

    # Determine user's organization (for multi-tenancy)
    org_id = user.org_id

    # Create token with organization context (uses session timeout from settings)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": str(user.id),
            "org_id": org_id,
            "role": user.role,
        },
        db=db,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"username": user.username, "role": user.role, "org_id": org_id},
    }


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout endpoint. JWT is stateless so this is a no-op server-side;
    the client clears its token."""
    return {"message": "Logged out"}


@router.post("/refresh")
async def refresh_token(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Refresh access token. Issues a new JWT for the current user."""
    org_id = current_user.org_id
    access_token = create_access_token(
        data={
            "sub": current_user.username,
            "user_id": str(current_user.id),
            "org_id": org_id,
            "role": current_user.role,
        },
        db=db,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Persisted profile only. Optional display fields are explicit JSON nulls."""
    try:
        get_installation_admin(current_user)
        can_manage_installation = True
    except HTTPException as exc:
        if exc.status_code != 403:
            raise
        can_manage_installation = False
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "auth_source": current_user.auth_source,
        "role_source": current_user.role_source,
        "is_platform_admin": current_user.is_platform_admin,
        "can_manage_installation": can_manage_installation,
        "is_active": current_user.is_active,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "last_login": iso_utc(current_user.last_login),
        "oidc_issuer": (
            current_user.oidc_issuer if current_user.auth_source == "oidc" else None
        ),
        "created_at": iso_utc(current_user.created_at),
    }


# ============================================================================
# OIDC AUTHENTICATION ENDPOINTS
# ============================================================================


async def oidc_database(request: Request, db: Session = Depends(get_db)):
    """Bind the deployment's single issuer to one persisted organization.

    The installation currently has one OIDC configuration. Commercial installs
    must explicitly bind that configuration; neither an ID-token org claim nor
    a callback query parameter selects its tenant. Configuration discovery has
    a separate short-lived trusted session, never the JIT user session.
    """
    from database import SessionLocal
    from core.tenant_context import (
        PlatformContext,
        TenantContext,
        commercial_mode,
        resolved_organization,
        _validate_org_id,
    )
    from models import Organization
    from core.oidc_state import consume

    callback = request.url.path.endswith("/callback")
    signed_binding = consume(request) if callback else None

    with PlatformContext(), SessionLocal() as configuration_db:
        config = SettingsService(configuration_db).get_oidc_config()
    service = OIDCService()
    service.configure(config)
    if not service.is_configured:
        config = None
        if callback:
            raise HTTPException(400, "OIDC is not available")
    request.state.oidc_service = service
    request.state.oidc_config = config
    org_id = None
    if config:
        if commercial_mode():
            org_id = os.getenv("OIDC_ORGANIZATION_ID")
            try:
                if not org_id or org_id == "default":
                    raise ValueError("Missing binding")
                _validate_org_id(org_id)
            except ValueError:
                raise HTTPException(
                    503, "OIDC_ORGANIZATION_ID must name a persisted organization"
                ) from None
        else:
            with TenantContext(None):
                org_id = resolved_organization()
        with PlatformContext(), SessionLocal() as configuration_db:
            organization = configuration_db.get(Organization, org_id)
            if organization is None or not organization.enabled:
                raise HTTPException(503, "OIDC organization binding is unavailable")

        if callback and (
            signed_binding["org_id"] != org_id
            or signed_binding["issuer"] != config["issuer"]
            or signed_binding["client_id"] != config["client_id"]
        ):
            raise HTTPException(400, "Invalid or expired OIDC state")
    if callback:
        # The signed, durably consumed organization owns the callback session.
        org_id = signed_binding["org_id"]
    request.state.oidc_org_id = org_id
    with TenantContext(org_id):
        yield db


@router.get("/oidc/status")
async def get_oidc_status(request: Request, db: Session = Depends(oidc_database)):
    """Check if OIDC is enabled and configured.

    Public endpoint - no auth required.
    Frontend uses this to show/hide SSO login button.
    """
    oidc_config = request.state.oidc_config
    oidc_service = request.state.oidc_service

    return {
        "enabled": oidc_service.is_configured,
        "issuer": oidc_config.get("issuer") if oidc_config else None,
    }


class OIDCDiscoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    issuer: str
    # Compatibility input only: discovery cannot validate a client identifier.
    client_id: str = ""


@router.post("/oidc/test")
async def test_oidc_configuration(
    request: Request,
    current_user: User = Depends(get_installation_admin),
    db: Session = Depends(get_db),
):
    """Test OIDC configuration by fetching discovery document.

    Requires persisted installation authority. Tests that the issuer URL is accessible
    and returns valid OIDC discovery metadata.
    """
    import httpx

    try:
        try:
            body = OIDCDiscoveryRequest.model_validate(await request.json())
        except (ValidationError, ValueError, TypeError):
            raise HTTPException(400, "Invalid discovery request") from None
        issuer = body.issuer.strip().rstrip("/")

        if not issuer:
            raise HTTPException(status_code=400, detail="Issuer URL is required")
        try:
            OIDCService.validate_endpoint(issuer, issuer=True)
        except ValueError:
            raise HTTPException(400, "Invalid HTTPS OIDC issuer") from None

        # Audit before outbound IO. A failed audit must not become an unaudited
        # installation-level network request. Never include submitted secrets.
        log_activity(
            db,
            current_user,
            action="oidc_configuration_test",
            resource_type="auth",
            details={"operation": "discovery"},
        )

        # Fetch discovery document
        discovery_url = f"{issuer}/.well-known/openid-configuration"

        # Same verification posture as the live login path in core.oidc_service.
        # This endpoint exists to tell an admin whether their issuer config works,
        # so a laxer client here would report a configuration as good and then have
        # it fail at first login — a test that does not exercise what it certifies.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(discovery_url)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch OIDC discovery document (HTTP {response.status_code})",
            )

        try:
            discovery = response.json()
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON response from OIDC discovery endpoint",
            )

        # Validate required fields
        required_fields = ["issuer", "authorization_endpoint", "token_endpoint"]
        missing = [f for f in required_fields if not discovery.get(f)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"OIDC discovery document missing required fields: {', '.join(missing)}",
            )

        # Verify issuer matches
        if discovery.get("issuer") != issuer:
            raise HTTPException(
                status_code=400,
                detail="OIDC discovery issuer mismatch",
            )
        try:
            OIDCService.validate_discovery(discovery, issuer)
        except ValueError:
            raise HTTPException(400, "Invalid HTTPS OIDC discovery endpoints") from None

        return {
            "status": "ok",
            "check": "discovery_only",
            "credentials_verified": False,
            "issuer": discovery.get("issuer"),
            "authorization_endpoint": discovery.get("authorization_endpoint"),
            "token_endpoint": discovery.get("token_endpoint"),
            "userinfo_endpoint": discovery.get("userinfo_endpoint"),
            "jwks_uri": discovery.get("jwks_uri"),
        }

    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(status_code=400, detail="Cannot connect to OIDC provider")
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=400, detail="Timeout connecting to OIDC provider"
        )
    except Exception:
        logger.error("OIDC configuration test failed")
        raise HTTPException(status_code=500, detail="OIDC configuration test failed")


@router.get("/oidc/login")
async def oidc_login(request: Request, db: Session = Depends(oidc_database)):
    """Initiate OIDC login flow.

    Redirects user to OIDC provider. Frontend should redirect to this URL
    or fetch it and redirect client-side.

    Returns:
        302 redirect to OIDC provider, or 400 if OIDC not configured
    """
    # Configure OIDC from settings
    oidc_config = request.state.oidc_config
    oidc_service = request.state.oidc_service
    if not oidc_config:
        raise HTTPException(status_code=400, detail="OIDC not configured")

    import jwt
    from deps import jwt_secret, JWT_ALGORITHM

    # Signed short-lived binding also detects configuration changes mid-login.
    claims = {
        "aud": "vnbui-oidc-state",
        "purpose": "oidc-login",
        "nonce": secrets.token_urlsafe(32),
        "org_id": request.state.oidc_org_id,
        "issuer": oidc_config["issuer"],
        "client_id": oidc_config["client_id"],
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
    }
    state = jwt.encode(
        claims,
        jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )

    # Generate PKCE code_verifier and code_challenge
    code_verifier, code_challenge = oidc_service.generate_pkce()

    # Build callback URL (handle proxy that terminates TLS)
    base_url = str(request.base_url).rstrip("/")
    # Use X-Forwarded-Proto if behind a proxy
    if request.headers.get("x-forwarded-proto") == "https":
        base_url = base_url.replace("http://", "https://", 1)
    callback_url = f"{base_url}/api/v1/auth/oidc/callback"

    login_url = await oidc_service.get_login_url(callback_url, state, code_challenge)
    if not login_url:
        raise HTTPException(status_code=500, detail="Failed to generate login URL")

    from core.oidc_state import issue

    issue(state, claims)

    # Store state and code_verifier in cookies
    response = RedirectResponse(url=login_url, status_code=302)
    is_secure = (
        request.headers.get("x-forwarded-proto") == "https"
        or request.url.scheme == "https"
    )
    response.set_cookie(
        key="oidc_state",
        value=state,
        max_age=300,  # 5 minutes
        httponly=True,
        secure=is_secure,
        samesite="lax",
    )
    response.set_cookie(
        key="oidc_pkce",
        value=code_verifier,
        max_age=300,  # 5 minutes
        httponly=True,
        secure=is_secure,
        samesite="lax",
    )

    return response


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None,
    error_description: str = None,
    db: Session = Depends(oidc_database),
):
    """Handle OIDC callback after authentication.

    Exchanges code for tokens, creates/updates user, returns JWT.
    Redirects to frontend with token in URL fragment.
    """
    # Check for errors from provider
    if error:
        logger.warning("OIDC provider rejected authentication")
        return HTMLResponse(
            content="<h1>Authentication Error</h1><p>Identity provider rejected authentication.</p>",
            status_code=400,
        )

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Verify state (CSRF protection)
    stored_state = request.cookies.get("oidc_state")
    if not stored_state or stored_state != state:
        logger.warning("OIDC state mismatch - possible CSRF")
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # Get PKCE code_verifier
    code_verifier = request.cookies.get("oidc_pkce")
    if not code_verifier:
        logger.warning("Missing PKCE code_verifier cookie")
        raise HTTPException(status_code=400, detail="Missing PKCE verifier")

    # Configure OIDC
    oidc_config = request.state.oidc_config
    oidc_service = request.state.oidc_service
    if not oidc_config:
        raise HTTPException(status_code=400, detail="OIDC not configured")

    # Build callback URL (same as in login, handle proxy)
    base_url = str(request.base_url).rstrip("/")
    if request.headers.get("x-forwarded-proto") == "https":
        base_url = base_url.replace("http://", "https://", 1)
    callback_url = f"{base_url}/api/v1/auth/oidc/callback"

    # Exchange code for tokens (with PKCE verifier)
    token_data, error_msg = await oidc_service.handle_callback(
        code, callback_url, code_verifier
    )
    if not token_data:
        logger.warning("OIDC code exchange failed")
        return HTMLResponse(
            content="<h1>Authentication Error</h1><p>Identity provider exchange failed.</p>",
            status_code=400,
        )

    # Get or create user
    try:
        user, is_new = await oidc_service.get_or_create_user(
            token_data, db, commit=False
        )
        log_activity(
            db,
            user,
            action="oidc_login",
            resource_type="auth",
            resource_id=user.id,
            details={"new_user": is_new},
            commit=False,
        )
        # Construct before commit, publish only after commit. The external code
        # exchange cannot be rolled back; failures require a new login attempt.
        access_token = create_access_token(
            data={
                "sub": user.username,
                "user_id": str(user.id),
                "org_id": user.org_id,
                "role": user.role,
                "auth_source": "oidc",
            },
            db=db,
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.error("OIDC user provisioning failed")
        return HTMLResponse(
            content="<h1>Authentication Error</h1><p>User provisioning failed</p>",
            status_code=500,
        )

    # Redirect to frontend with token
    frontend_url = os.getenv("FRONTEND_URL", "/")
    redirect_url = f"{frontend_url}#access_token={access_token}"

    response = RedirectResponse(url=redirect_url, status_code=302)
    return response
