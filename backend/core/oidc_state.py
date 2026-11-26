"""Durable replay custody. Each operation owns a separate short transaction."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
import jwt
from jwt import InvalidTokenError
from sqlalchemy import delete, func, select, text, update

from core.tenant_context import TenantContext, _validate_org_id, resolved_organization
from database import SessionLocal
from deps import JWT_ALGORITHM, jwt_secret
from models import OIDCLoginState

EXPIRY_RETENTION = timedelta(hours=24)
MAX_CLEANUP_BATCH = 128


def reclaim_expired(*, limit=MAX_CLEANUP_BATCH):
    """One bounded maintenance transaction in an already-established tenant scope.

    Retain consumed and unconsumed digests until 24 hours after signed expiry.
    Platform enumeration must end before calling this function. No caller-supplied
    tenant or cutoff can redirect it or shorten retention. Disabled organizations
    remain eligible for maintenance under their persisted identity.
    """
    if type(limit) is not int or not 1 <= limit <= MAX_CLEANUP_BATCH:
        raise ValueError("OIDC cleanup limit must be between 1 and 128")
    org_id = resolved_organization()
    with SessionLocal() as db:
        db.execute(text("SET LOCAL statement_timeout = '5s'"))
        expired = (
            select(OIDCLoginState.digest)
            .where(
                OIDCLoginState.org_id == org_id,
                OIDCLoginState.expires_at <= func.now() - EXPIRY_RETENTION,
            )
            .order_by(OIDCLoginState.expires_at, OIDCLoginState.digest)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .cte("expired_oidc_states")
        )
        removed = db.execute(
            delete(OIDCLoginState)
            .where(
                OIDCLoginState.org_id == org_id,
                OIDCLoginState.digest.in_(select(expired.c.digest)),
            )
            .returning(OIDCLoginState.digest)
            .execution_options(synchronize_session=False)
        ).all()
        db.commit()
        return len(removed)


def state_digest(state):
    return hashlib.sha256(state.encode("ascii")).hexdigest()


def binding(claims):
    return {key: claims[key] for key in ("org_id", "issuer", "client_id", "purpose")}


def issue(state, claims):
    with TenantContext(claims["org_id"]), SessionLocal() as db:
        db.add(
            OIDCLoginState(
                digest=state_digest(state),
                **binding(claims),
                expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
            )
        )
        db.commit()


def consume(request):
    """Authenticate browser state before installing its signed tenant scope."""
    try:
        values = request.query_params.getlist("state")
        cookie_values = [
            part.partition("=")[2].strip()
            for header in request.headers.getlist("cookie")
            for part in header.split(";")
            if part.partition("=")[0].strip() == "oidc_state"
        ]
        if len(values) != 1 or len(cookie_values) != 1:
            raise ValueError("Ambiguous state")
        state = values[0]
        if (
            not state
            or len(state) > 4096
            or not secrets.compare_digest(state, cookie_values[0])
        ):
            raise ValueError("State mismatch")
        claims = jwt.decode(
            state,
            jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            audience="vnbui-oidc-state",
            options={"require": ["exp"]},
        )
        if (
            claims.get("aud") != "vnbui-oidc-state"
            or claims.get("purpose") != "oidc-login"
        ):
            raise ValueError("Wrong state purpose")
        for key in ("org_id", "issuer", "client_id", "nonce"):
            if not isinstance(claims.get(key), str) or not claims[key].strip():
                raise ValueError("Incomplete binding")
        _validate_org_id(claims["org_id"])
        if claims["org_id"] == "default":
            raise ValueError("Signed organization must be persisted")
        digest = state_digest(state)
    except (InvalidTokenError, ValueError, TypeError, UnicodeError, OverflowError):
        raise HTTPException(400, "Invalid or expired OIDC state") from None
    # Commit before any config read or exchange. A later failed login never
    # returns custody of this authorization response to another callback.
    with TenantContext(claims["org_id"]), SessionLocal() as db:
        result = db.execute(
            update(OIDCLoginState)
            .where(
                OIDCLoginState.digest == digest,
                OIDCLoginState.org_id == claims["org_id"],
                OIDCLoginState.issuer == claims["issuer"],
                OIDCLoginState.client_id == claims["client_id"],
                OIDCLoginState.purpose == claims["purpose"],
                OIDCLoginState.consumed_at.is_(None),
                OIDCLoginState.expires_at > func.now(),
            )
            .values(consumed_at=func.now())
        )
        if result.rowcount != 1:
            raise HTTPException(400, "Invalid or expired OIDC state")
        db.commit()
    return claims
