"""One-time staged delivery; only candidate possession can activate a rotation."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import os

from fastapi import Header, HTTPException, Request

from core.operator_requests import begin_admission
from core.task_lifetime import run_owned_worker
from core.tenant_context import PlatformContext, TenantContext
from database import SessionLocal
from models import Agent, AgentAPIKey, AgentKeyRotation, Organization, User
from deps import generate_agent_api_key, hash_api_key, iso_utc, log_activity


def utc(value):
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def ttl_hours():
    try:
        hours = int(os.getenv("AGENT_KEY_ROTATION_TTL_HOURS", "24"))
    except ValueError:
        raise HTTPException(
            500,
            detail={
                "code": "agent_rotation_configuration",
                "message": "Agent key rotation lifetime misconfigured",
            },
        ) from None
    if not 1 <= hours <= 168:
        raise HTTPException(
            500,
            detail={
                "code": "agent_rotation_configuration",
                "message": "Agent key rotation lifetime misconfigured",
            },
        )
    return hours


def metadata(row, *, now=None):
    now = now or datetime.now(timezone.utc)
    state = (
        "expired"
        if row.state == "pending" and utc(row.expires_at) <= now
        else row.state
    )
    return {
        "rotation_id": row.id,
        "agent_id": row.agent_id,
        "state": state,
        "key_prefix": row.key_prefix,
        "created_at": iso_utc(row.created_at),
        "expires_at": iso_utc(row.expires_at),
        "activated_at": iso_utc(row.activated_at),
    }


def lock_authority(db, org_id, actor_id):
    """Keep disable/delete/role changes ordered with the credential transition."""
    organization = (
        db.query(Organization)
        .filter_by(id=org_id)
        .populate_existing()
        .with_for_update(read=True)
        .one_or_none()
    )
    actor = (
        db.query(User)
        .filter_by(id=actor_id, org_id=org_id)
        .populate_existing()
        .with_for_update(read=True)
        .one_or_none()
    )
    if (
        organization is None
        or not organization.enabled
        or actor is None
        or not actor.is_active
        or actor.role != "admin"
    ):
        raise HTTPException(
            403,
            detail={
                "code": "agent_rotation_authority_revoked",
                "message": "Original rotation authority unavailable",
            },
        )
    return actor


def stage(db, actor, agent_id, request_id=None):
    actor = lock_authority(db, actor.org_id, actor.id)
    admission = begin_admission(
        db, actor, "credential.agent.rotate", {"agent_id": agent_id}, request_id
    )
    if admission.replay:
        return admission.response()
    agent = (
        db.query(Agent)
        .filter_by(id=agent_id, org_id=actor.org_id)
        .with_for_update()
        .one_or_none()
    )
    if agent is None:
        raise HTTPException(
            404, detail={"code": "agent_not_found", "message": "Agent not found"}
        )
    if not agent.api_key_hash:
        raise HTTPException(
            409,
            detail={
                "code": "agent_rotation_predecessor_missing",
                "message": "Agent has no predecessor API key",
            },
        )
    now = datetime.now(timezone.utc)
    pending = (
        db.query(AgentKeyRotation)
        .filter_by(agent_id=agent_id, org_id=actor.org_id, state="pending")
        .with_for_update()
        .all()
    )
    for prior in pending:
        if utc(prior.expires_at) > now:
            raise HTTPException(
                409, detail={"code": "agent_rotation_pending", "rotation_id": prior.id}
            )
        prior.state = "expired"
    # Release the partial-unique pending slot before inserting the successor.
    db.flush()
    candidate = generate_agent_api_key()
    row = AgentKeyRotation(
        org_id=actor.org_id,
        agent_id=agent_id,
        request_record_id=admission.row.id,
        predecessor_hash=agent.api_key_hash,
        candidate_hash=hash_api_key(candidate),
        key_prefix=candidate[:8],
        state="pending",
        created_at=now,
        expires_at=now + timedelta(hours=ttl_hours()),
        created_by=actor.id,
    )
    db.add(row)
    db.flush()
    log_activity(
        db,
        actor,
        "agent_key_rotation_staged",
        "agent",
        agent.id,
        {"rotation_id": row.id, "key_prefix": row.key_prefix},
        commit=False,
    )
    return admission.finish(
        dict(metadata(row, now=now), api_key=candidate), secret_fields=("api_key",)
    )


@dataclass(frozen=True)
class CandidateProof:
    org_id: str
    agent_id: str
    rotation_id: str
    candidate_hash: str
    certificate_fingerprint: str | None = None


async def candidate_credential(
    agent_id: str,
    rotation_id: str,
    request: Request,
    x_agent_key: str | None = Header(None, alias="X-Agent-Key"),
):
    """A candidate authorizes this activation only, never normal agent routes."""
    from deps import REQUIRE_MTLS, _verify_agent_cert, agent_key_usable
    from core.verified_tls import verified_peer

    if not x_agent_key or len(x_agent_key) > 1024:
        raise HTTPException(
            401,
            detail={
                "code": "agent_candidate_invalid",
                "message": "Candidate credential unavailable",
            },
        )
    fingerprint = verified_peer(request.scope)
    if REQUIRE_MTLS and fingerprint is None:
        raise HTTPException(
            401,
            detail={
                "code": "verified_certificate_required",
                "message": "Verified certificate transport unavailable",
            },
        )
    digest = hash_api_key(x_agent_key)

    def lookup():
        with PlatformContext(), SessionLocal() as db:
            rows = (
                db.query(AgentKeyRotation)
                .filter_by(id=rotation_id, agent_id=agent_id, candidate_hash=digest)
                .limit(2)
                .all()
            )
            if len(rows) != 1 or rows[0].state not in {"pending", "activated"}:
                raise HTTPException(
                    401,
                    detail={
                        "code": "agent_candidate_invalid",
                        "message": "Candidate credential unavailable",
                    },
                )
            row = rows[0]
            if row.state == "activated":
                agent = (
                    db.query(Agent)
                    .filter_by(id=agent_id, org_id=row.org_id)
                    .one_or_none()
                )
                if not agent_key_usable(db, agent, digest):
                    raise HTTPException(
                        403,
                        detail={
                            "code": "agent_candidate_superseded",
                            "message": "Activated candidate is no longer current",
                        },
                    )
            if fingerprint:
                certified = _verify_agent_cert(fingerprint, db)
                if (
                    certified is None
                    or certified.id != agent_id
                    or certified.org_id != row.org_id
                ):
                    raise HTTPException(
                        401,
                        detail={
                            "code": "agent_candidate_certificate_invalid",
                            "message": "Candidate certificate unavailable",
                        },
                    )
            return CandidateProof(
                row.org_id, agent_id, rotation_id, digest, fingerprint
            )

    proof = await run_owned_worker(lookup)
    with TenantContext(proof.org_id):
        yield proof


def locked_rotation(db, agent_id, rotation_id, org_id):
    # Every lifecycle mutation shares this order, including cancellation/staging.
    agent = (
        db.query(Agent)
        .filter_by(id=agent_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if agent is None:
        raise HTTPException(
            404, detail={"code": "agent_not_found", "message": "Agent not found"}
        )
    row = (
        db.query(AgentKeyRotation)
        .filter_by(id=rotation_id, agent_id=agent_id, org_id=org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(
            404,
            detail={
                "code": "agent_rotation_not_found",
                "message": "Rotation not found",
            },
        )
    return agent, row


def activate(proof):
    """Own the entire activation transaction in its worker and tenant scope."""
    from deps import agent_key_usable

    with TenantContext(proof.org_id), SessionLocal() as db:
        original = (
            db.query(AgentKeyRotation)
            .filter_by(
                id=proof.rotation_id, agent_id=proof.agent_id, org_id=proof.org_id
            )
            .one_or_none()
        )
        if original is None:
            raise HTTPException(404, detail={"code": "agent_rotation_not_found"})
        actor = lock_authority(db, proof.org_id, original.created_by)
        agent, row = locked_rotation(
            db, proof.agent_id, proof.rotation_id, proof.org_id
        )
        if row.org_id != proof.org_id or not hmac.compare_digest(
            row.candidate_hash, proof.candidate_hash
        ):
            raise HTTPException(
                401,
                detail={
                    "code": "agent_candidate_invalid",
                    "message": "Candidate credential unavailable",
                },
            )
        from deps import REQUIRE_MTLS

        if REQUIRE_MTLS and proof.certificate_fingerprint is None:
            raise HTTPException(
                401,
                detail={
                    "code": "verified_certificate_required",
                    "message": "Verified certificate transport unavailable",
                },
            )
        if proof.certificate_fingerprint:
            from core.storage_attempt_key import _credential
            from core.s3_ownership import StorageOwnershipError

            try:
                _credential(
                    db, agent.id, ("certificate", proof.certificate_fingerprint)
                )
            except StorageOwnershipError:
                raise HTTPException(
                    401,
                    detail={
                        "code": "agent_candidate_certificate_invalid",
                        "message": "Candidate certificate unavailable",
                    },
                ) from None
        now = datetime.now(timezone.utc)
        if row.state == "activated":
            if not agent_key_usable(db, agent, proof.candidate_hash, lock=True):
                raise HTTPException(
                    409,
                    detail={
                        "code": "agent_candidate_superseded",
                        "message": "Activated credential is no longer current",
                    },
                )
            return metadata(row, now=now)
        if row.state != "pending":
            raise HTTPException(
                409,
                detail={
                    "code": "agent_rotation_not_pending",
                    "message": "Rotation is no longer pending",
                },
            )
        if utc(row.expires_at) <= now:
            row.state = "expired"
            db.commit()
            raise HTTPException(
                410,
                detail={
                    "code": "agent_candidate_expired",
                    "message": "Candidate credential expired; active key retained",
                },
            )
        if not hmac.compare_digest(agent.api_key_hash or "", row.predecessor_hash):
            raise HTTPException(
                409,
                detail={
                    "code": "agent_rotation_predecessor_changed",
                    "message": "Predecessor credential changed; active key retained",
                },
            )
        key = (
            db.query(AgentAPIKey)
            .filter_by(agent_id=agent.id)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )
        if key is None:
            key = AgentAPIKey(
                agent_id=agent.id, name=agent.display_name or agent.hostname
            )
            db.add(key)
        key.key_hash, key.key_prefix = row.candidate_hash, row.key_prefix
        key.enabled, key.expires_at, key.updated_at = (
            True,
            None,
            now.replace(tzinfo=None),
        )
        agent.api_key_hash = row.candidate_hash
        agent.key_created_at = now.replace(tzinfo=None)
        agent.key_last_used_at = key.last_used_at = now.replace(tzinfo=None)
        row.state, row.activated_at = "activated", now
        log_activity(
            db,
            actor,
            "agent_key_rotation_activated",
            "agent",
            agent.id,
            {"rotation_id": row.id, "key_prefix": row.key_prefix},
            commit=False,
        )
        db.commit()
        return metadata(row, now=now)


def status(db, agent_id, org_id, rotation_id=None):
    if db.query(Agent).filter_by(id=agent_id, org_id=org_id).one_or_none() is None:
        raise HTTPException(
            404, detail={"code": "agent_not_found", "message": "Agent not found"}
        )
    query = db.query(AgentKeyRotation).filter_by(agent_id=agent_id, org_id=org_id)
    if rotation_id is not None:
        row = query.filter_by(id=rotation_id).one_or_none()
        if row is None:
            raise HTTPException(
                404,
                detail={
                    "code": "agent_rotation_not_found",
                    "message": "Rotation not found",
                },
            )
        return metadata(row)
    rows = query.order_by(
        AgentKeyRotation.created_at.desc(), AgentKeyRotation.id.desc()
    ).all()
    return {"items": [metadata(row) for row in rows], "total": len(rows)}


def cancel(db, actor, agent_id, rotation_id):
    actor = lock_authority(db, actor.org_id, actor.id)
    _, row = locked_rotation(db, agent_id, rotation_id, actor.org_id)
    if row.state == "cancelled":
        return metadata(row)
    if row.state != "pending":
        raise HTTPException(
            409,
            detail={
                "code": "agent_rotation_not_pending",
                "message": "Only pending rotations can be cancelled",
            },
        )
    now = datetime.now(timezone.utc)
    row.state = "expired" if utc(row.expires_at) <= now else "cancelled"
    log_activity(
        db,
        actor,
        (
            "agent_key_rotation_cancelled"
            if row.state == "cancelled"
            else "agent_key_rotation_expired"
        ),
        "agent",
        agent_id,
        {"rotation_id": row.id},
        commit=False,
    )
    db.commit()
    return metadata(row, now=now)
