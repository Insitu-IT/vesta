"""
Custom exceptions and global exception handlers
"""

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
import logging
import traceback
from typing import Optional

logger = logging.getLogger(__name__)


class BaseAPIException(HTTPException):
    """Base exception for all API errors"""

    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: Optional[str] = None,
        headers: Optional[dict] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code or self.__class__.__name__


# Authentication & Authorization
class AuthenticationException(BaseAPIException):
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="AUTH_FAILED",
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationException(BaseAPIException):
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN, detail=detail, error_code="FORBIDDEN"
        )


# Validation
class ValidationException(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            error_code="VALIDATION_ERROR",
        )


# Resources
class ResourceNotFoundException(BaseAPIException):
    def __init__(self, resource: str, resource_id: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} with id {resource_id} not found",
            error_code="NOT_FOUND",
        )


class ConflictException(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT, detail=detail, error_code="CONFLICT"
        )


# Operations
class BackupException(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup operation failed: {detail}",
            error_code="BACKUP_ERROR",
        )


class RestoreException(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Restore operation failed: {detail}",
            error_code="RESTORE_ERROR",
        )


class AgentException(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Agent error: {detail}",
            error_code="AGENT_ERROR",
        )


class DatabaseException(BaseAPIException):
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="DATABASE_ERROR",
        )


# Global exception handlers
async def api_exception_handler(request: Request, exc: BaseAPIException):
    """Handle custom API exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "detail": exc.detail,
            "request_id": getattr(request.state, "request_id", None),
        },
        headers=exc.headers,
    )


async def validation_exception_handler(request: Request, exc):
    """Handle Pydantic validation exceptions"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "detail": "Invalid request data",
            "errors": exc.errors() if hasattr(exc, "errors") else str(exc),
            "request_id": getattr(request.state, "request_id", None),
        },
    )


async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    request_id = getattr(request.state, "request_id", None)

    # Log full exception with traceback
    logger.error(
        f"Unhandled exception in request {request_id}",
        exc_info=True,
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "exception": str(exc),
            "traceback": traceback.format_exc(),
        },
    )

    # Return generic error to client (don't leak internals)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_ERROR",
            "detail": "An unexpected error occurred",
            "request_id": request_id,
        },
    )
