"""
API Key management endpoints: orchestrator keys and agent registration keys.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from core.operator_requests import begin_admission, request_identity
from models import User, OrchestratorAPIKey, AgentRegistrationKey
from deps import (
    get_admin_user,
    log_activity,
    iso_utc,
    generate_agent_api_key,
    hash_api_key,
)
from schemas import (
    OrchestratorAPIKeyCreate,
    OrchestratorAPIKeyUpdate,
    AgentRegistrationKeyCreate,
    AgentRegistrationKeyUpdate,
)

router = APIRouter(prefix="/api/v1", tags=["api-keys"])


# ============================================================================
# ORCHESTRATOR API KEYS (for agent -> orchestrator authentication)
# ============================================================================


@router.get("/orchestrator-keys")
async def list_orchestrator_keys(
    db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)
):
    """List all orchestrator API keys (admin only)"""
    keys = (
        db.query(OrchestratorAPIKey)
        .order_by(OrchestratorAPIKey.created_at.desc())
        .all()
    )

    return {
        "items": [
            {
                "id": key.id,
                "name": key.name,
                "key_prefix": key.key_prefix,
                "expires_at": iso_utc(key.expires_at),
                "enabled": key.enabled,
                "is_expired": key.is_expired(),
                "is_valid": key.is_valid(),
                "last_used_at": iso_utc(key.last_used_at),
                "created_at": iso_utc(key.created_at),
                "created_by": key.user.username if key.user else None,
            }
            for key in keys
        ],
        "total": len(keys),
    }


@router.post("/orchestrator-keys", status_code=status.HTTP_201_CREATED)
def create_orchestrator_key(
    key_data: OrchestratorAPIKeyCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
    request_id: str | None = Depends(request_identity),
):
    """Create new orchestrator API key (admin only)"""
    admission = begin_admission(
        db, admin_user, "credential.orchestrator.create", key_data, request_id
    )
    if admission.replay:
        return admission.response()
    # Generate key
    api_key = generate_agent_api_key()
    key_hash = hash_api_key(api_key)
    key_prefix = api_key[:8]

    # Create record
    key = OrchestratorAPIKey(
        name=key_data.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=key_data.expires_at,
        created_by=admin_user.id,
    )

    db.add(key)
    db.flush()

    # Log activity
    log_activity(
        db,
        admin_user,
        action="orchestrator_key_created",
        resource_type="orchestrator_key",
        resource_id=key.id,
        details={"name": key.name, "key_prefix": key_prefix},
        commit=False,
    )

    # Return key (ONLY TIME IT'S SENT IN PLAINTEXT)
    # Include snippet showing how to use in agent.env
    usage_snippet = f"""# Add to agent.env on all KVM hosts:
ORCHESTRATOR_API_KEY={api_key}
"""

    return admission.finish(
        {
            "id": key.id,
            "name": key.name,
            "api_key": api_key,  # Store this securely!
            "key_prefix": key_prefix,
            "expires_at": iso_utc(key.expires_at),
            "created_at": iso_utc(key.created_at),
            "usage_snippet": usage_snippet,
            "message": "API key created successfully. Save this key - it will not be shown again!",
        },
        status=201,
        secret_fields=("api_key", "usage_snippet"),
    )


@router.patch("/orchestrator-keys/{key_id}")
async def update_orchestrator_key(
    key_id: str,
    key_data: OrchestratorAPIKeyUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Update orchestrator API key (admin only)"""
    key = db.query(OrchestratorAPIKey).filter(OrchestratorAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Update fields
    if key_data.name is not None:
        key.name = key_data.name
    if key_data.expires_at is not None:
        key.expires_at = key_data.expires_at
    if key_data.enabled is not None:
        key.enabled = key_data.enabled

    db.commit()
    db.refresh(key)

    log_activity(
        db,
        admin_user,
        action="orchestrator_key_updated",
        resource_type="orchestrator_key",
        resource_id=key.id,
        details={"name": key.name},
    )

    return {
        "id": key.id,
        "name": key.name,
        "key_prefix": key.key_prefix,
        "expires_at": iso_utc(key.expires_at),
        "enabled": key.enabled,
        "is_valid": key.is_valid(),
        "message": "Key updated successfully",
    }


@router.delete("/orchestrator-keys/{key_id}")
async def delete_orchestrator_key(
    key_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Delete orchestrator API key (admin only)"""
    key = db.query(OrchestratorAPIKey).filter(OrchestratorAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key_name = key.name
    db.delete(key)
    db.commit()

    log_activity(
        db,
        admin_user,
        action="orchestrator_key_deleted",
        resource_type="orchestrator_key",
        resource_id=key_id,
        details={"name": key_name},
    )

    return {"message": f"Orchestrator API key '{key_name}' deleted successfully"}


# ============================================================================
# AGENT REGISTRATION KEYS (for one-time agent registration)
# ============================================================================


@router.get("/registration-keys")
async def list_registration_keys(
    db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)
):
    """List all agent registration keys (admin only)"""
    keys = (
        db.query(AgentRegistrationKey)
        .order_by(AgentRegistrationKey.created_at.desc())
        .all()
    )

    return {
        "items": [
            {
                "id": key.id,
                "name": key.name,
                "agent_hostname": key.agent_hostname,
                "key_prefix": key.key_prefix,
                "expires_at": iso_utc(key.expires_at),
                "enabled": key.enabled,
                "max_uses": key.max_uses,
                "use_count": key.use_count,
                "is_expired": key.is_expired(),
                "is_max_uses_reached": key.is_max_uses_reached(),
                "is_valid": key.is_valid(),
                "last_used_at": iso_utc(key.last_used_at),
                "created_at": iso_utc(key.created_at),
                "created_by": key.user.username if key.user else None,
            }
            for key in keys
        ],
        "total": len(keys),
    }


@router.post("/registration-keys", status_code=status.HTTP_201_CREATED)
def create_registration_key(
    key_data: AgentRegistrationKeyCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
    request_id: str | None = Depends(request_identity),
):
    """Create new agent registration key (admin only)"""
    admission = begin_admission(
        db, admin_user, "credential.registration.create", key_data, request_id
    )
    if admission.replay:
        return admission.response()
    # Generate key
    api_key = generate_agent_api_key()
    key_hash = hash_api_key(api_key)
    key_prefix = api_key[:8]

    # Create record
    key = AgentRegistrationKey(
        name=key_data.name,
        agent_hostname=key_data.agent_hostname,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=key_data.expires_at,
        max_uses=key_data.max_uses if key_data.max_uses is not None else 1,
        created_by=admin_user.id,
    )

    db.add(key)
    db.flush()

    log_activity(
        db,
        admin_user,
        action="registration_key_created",
        resource_type="registration_key",
        resource_id=key.id,
        details={"name": key.name, "key_prefix": key_prefix, "max_uses": key.max_uses},
        commit=False,
    )

    # Return key (ONLY TIME IT'S SENT IN PLAINTEXT)
    return admission.finish(
        {
            "id": key.id,
            "name": key.name,
            "agent_hostname": key.agent_hostname,
            "api_key": api_key,  # Store this securely!
            "key_prefix": key_prefix,
            "expires_at": iso_utc(key.expires_at),
            "max_uses": key.max_uses,
            "created_at": iso_utc(key.created_at),
            "message": "Registration key created successfully. Save this key - it will not be shown again!",
        },
        status=201,
        secret_fields=("api_key",),
    )


@router.patch("/registration-keys/{key_id}")
async def update_registration_key(
    key_id: str,
    key_data: AgentRegistrationKeyUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Update agent registration key (admin only)"""
    key = (
        db.query(AgentRegistrationKey).filter(AgentRegistrationKey.id == key_id).first()
    )
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Update fields
    if key_data.name is not None:
        key.name = key_data.name
    if key_data.expires_at is not None:
        key.expires_at = key_data.expires_at
    if key_data.max_uses is not None:
        key.max_uses = key_data.max_uses
    if key_data.enabled is not None:
        if key_data.enabled and not key.agent_hostname:
            raise HTTPException(
                status_code=409,
                detail="Unscoped registration key cannot be re-enabled; issue a new key",
            )
        key.enabled = key_data.enabled

    db.commit()
    db.refresh(key)

    log_activity(
        db,
        admin_user,
        action="registration_key_updated",
        resource_type="registration_key",
        resource_id=key.id,
        details={"name": key.name},
    )

    return {
        "id": key.id,
        "name": key.name,
        "key_prefix": key.key_prefix,
        "expires_at": iso_utc(key.expires_at),
        "max_uses": key.max_uses,
        "use_count": key.use_count,
        "enabled": key.enabled,
        "is_valid": key.is_valid(),
        "message": "Key updated successfully",
    }


@router.delete("/registration-keys/{key_id}")
async def delete_registration_key(
    key_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user),
):
    """Delete agent registration key (admin only)"""
    key = (
        db.query(AgentRegistrationKey).filter(AgentRegistrationKey.id == key_id).first()
    )
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key_name = key.name
    db.delete(key)
    db.commit()

    log_activity(
        db,
        admin_user,
        action="registration_key_deleted",
        resource_type="registration_key",
        resource_id=key_id,
        details={"name": key_name},
    )

    return {"message": f"Registration key '{key_name}' deleted successfully"}
