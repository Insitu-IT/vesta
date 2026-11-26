"""
Middleware for CORS, rate limiting, logging, and security headers
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
import re
import time
import uuid
import logging

from config import settings
from core import metrics as prom

logger = logging.getLogger(__name__)


_DEMO_ALLOWED_EXACT = {
    "/health",
    "/ready",
    "/metrics",
    "/api/v1/version",
}
_DEMO_DENIED_EXACT = {"/docs", "/redoc", "/openapi.json"}


class DemoPolicyMiddleware(BaseHTTPMiddleware):
    """Fail closed around the dedicated OSS demo API surface."""

    async def dispatch(self, request: Request, call_next):
        if not settings.demo_mode or request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        is_demo_api = path == "/api/v1/demo" or path.startswith("/api/v1/demo/")
        if is_demo_api or path in _DEMO_ALLOWED_EXACT:
            if is_demo_api:
                limited = self._apply_demo_rate_limits(request)
                if limited is not None:
                    return limited
            response = await call_next(request)
            response.headers["X-Vnbui-Environment"] = "demo"
            response.headers["X-Vnbui-Simulated"] = "true"
            return response

        if (
            path.startswith("/api/")
            or path.startswith("/ws")
            or path in _DEMO_DENIED_EXACT
        ):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": {
                        "code": "DEMO_POLICY_DENIED",
                        "message": "This operation is unavailable in the public demo.",
                    },
                    "environment": "demo",
                    "simulated": True,
                },
                headers={
                    "X-Vnbui-Environment": "demo",
                    "X-Vnbui-Simulated": "true",
                },
            )
        return await call_next(request)

    @staticmethod
    def _apply_demo_rate_limits(request: Request):
        from core.tenant_context import DemoContext

        with DemoContext():
            return DemoPolicyMiddleware._demo_rate_limits(request)

    @staticmethod
    def _demo_rate_limits(request: Request):
        from database import SessionLocal
        from demo.limits import DemoLimitError, DemoRateLimiter
        from demo.sessions import COOKIE_NAME

        db = SessionLocal()
        try:
            limiter = DemoRateLimiter(db)
            # Do not trust forwarded headers here. The deployment must preserve a
            # meaningful peer address (or accept a conservative shared bucket).
            source = request.client.host if request.client else "unknown"
            limiter.check("source", source, settings.demo_source_requests_per_minute)
            token = request.cookies.get(COOKIE_NAME)
            if token:
                limiter.check(
                    "session", token, settings.demo_session_requests_per_minute
                )
        except DemoLimitError as exc:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": {"code": exc.code, "message": str(exc)},
                    "environment": "demo",
                    "simulated": True,
                },
                headers={
                    "Retry-After": str(exc.retry_after or 60),
                    "X-Vnbui-Environment": "demo",
                    "X-Vnbui-Simulated": "true",
                },
            )
        finally:
            db.close()
        return None


# Rate limiter instance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri=(
        settings.rate_limit_storage if settings.rate_limit_enabled else "memory://"
    ),
    enabled=settings.rate_limit_enabled,
)


def setup_cors(app):
    """Configure CORS middleware with secure settings"""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,  # Specific origins only
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Request-ID",
            "X-Frontend-Version",
            "Idempotency-Key",
        ],
        expose_headers=[
            "Content-Disposition",
            "X-Request-ID",
            "Idempotency-Key",
            "Idempotency-Replayed",
        ],
        max_age=3600,  # Cache preflight requests for 1 hour
    )


def setup_rate_limiting(app):
    """Configure rate limiting"""
    if settings.rate_limit_enabled:
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Pattern to replace UUIDs and numeric IDs in URL paths to avoid cardinality explosion
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_NUMERIC_ID_RE = re.compile(r"/\d+(?=/|$)")


def _normalize_path(path: str) -> str:
    """Replace UUIDs and numeric IDs in a URL path with placeholders."""
    path = _UUID_RE.sub("{id}", path)
    path = _NUMERIC_ID_RE.sub("/{id}", path)
    return path


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all requests with timing and request ID
    """

    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timer
        start_time = time.time()

        # Log request
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client": request.client.host if request.client else None,
            },
        )

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            # Log error
            logger.error(
                "Request failed",
                exc_info=True,
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                },
            )
            raise

        # Calculate duration
        duration = time.time() - start_time

        # Log response
        logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
            },
        )

        # Prometheus API metrics (skip self-referential paths)
        path = request.url.path
        if path not in ("/metrics", "/api/v1/health"):
            endpoint = _normalize_path(path)
            method = request.method
            prom.api_requests_total.labels(
                method=method, endpoint=endpoint, status=str(response.status_code)
            ).inc()
            prom.api_request_duration_seconds.labels(
                method=method, endpoint=endpoint
            ).observe(duration)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # HSTS for production
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # ReDoc's bundled search runs in a local blob worker. Permit it only on
        # this document; no CDN, remote worker or external connection is allowed.
        root_path = request.scope.get("root_path", "").rstrip("/")
        if request.url.path == root_path + "/redoc":
            response.headers["Content-Security-Policy"] += " worker-src 'self' blob:;"

        return response


def setup_middleware(app):
    """Setup all middleware"""
    # Security headers (first, so they apply to all responses)
    app.add_middleware(SecurityHeadersMiddleware)

    # Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # CORS
    setup_cors(app)

    # Rate limiting
    setup_rate_limiting(app)

    # Added last so it executes first and rejects non-demo APIs before their auth,
    # database, scheduler, or external-integration paths can run.
    app.add_middleware(DemoPolicyMiddleware)
