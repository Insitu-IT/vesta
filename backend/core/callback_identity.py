"""Detached callback identities from registered keys or verified TLS peers."""

from dataclasses import dataclass
from datetime import datetime

from fastapi import Header, HTTPException, Request

from core.tenant_context import PlatformContext, TenantContext
from models import Agent


@dataclass(frozen=True)
class CallbackIdentity:
    org_id: str
    agent_id: str
    credential_kind: str
    credential_id: str

    @property
    def proof(self):
        return self.credential_kind, self.credential_id


def validate_identity(db, identity):
    from core.storage_attempt_key import _credential
    from core.s3_ownership import StorageOwnershipError

    agent = (
        db.query(Agent)
        .filter_by(id=identity.agent_id, org_id=identity.org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if agent is None:
        raise StorageOwnershipError("Callback identity unavailable")
    _credential(db, identity.agent_id, identity.proof)
    return agent


async def authenticate_callback(
    x_agent_key: str = Header(None, alias="X-Agent-Key"),
    request: Request = None,
):
    from database import SessionLocal
    from deps import REQUIRE_MTLS, _authenticate_agent, hash_api_key

    from core.verified_tls import verified_peer

    fingerprint = verified_peer(request.scope) if request is not None else None
    # A caller's X-Client-Cert-Fingerprint or forwarded scheme is never proof.
    if REQUIRE_MTLS and fingerprint is None:
        raise HTTPException(401, "Verified certificate transport unavailable")
    with PlatformContext(), SessionLocal() as db:
        agent = _authenticate_agent(
            None if fingerprint else x_agent_key, fingerprint, db
        )
        identity = CallbackIdentity(
            agent.org_id,
            agent.id,
            "certificate" if fingerprint else "api-key",
            fingerprint or hash_api_key(x_agent_key),
        )
    with TenantContext(identity.org_id), SessionLocal() as db:
        from core.s3_ownership import StorageOwnershipError

        try:
            agent = validate_identity(db, identity)
        except StorageOwnershipError:
            raise HTTPException(401, "Callback credential unavailable") from None
        agent.key_last_used_at = datetime.utcnow()
        db.commit()
    return identity


def callback_worker(identity, operation, backup_id, value, *, with_proof=True):
    """Own the session in the worker; never borrow request-thread resources.

    Existing services retain their IO semantics until checkpoint B. This
    ownership migration does not claim that those services are IO-unlocked.
    """
    from database import SessionLocal
    from core.s3_ownership import StorageOwnershipError
    from core.scheduler_scope import ScopeRefused

    with TenantContext(identity.org_id), SessionLocal() as db:
        validate_identity(db, identity)
        db.commit()
        args = (db, backup_id, identity.agent_id, value)
        if with_proof:
            args += (identity.proof,)
        try:
            return operation(*args)
        except ScopeRefused as error:
            raise StorageOwnershipError(
                "Original callback custody unavailable"
            ) from error
