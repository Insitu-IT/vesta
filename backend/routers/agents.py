"""
Agent management endpoints: registration, sync, list, heartbeat.
"""

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, select
from datetime import datetime
from typing import Optional, Annotated
import os
import logging
import uuid

from database import get_db
from models import (
    Agent,
    VM,
    Backup,
    AgentAPIKey,
    AgentRegistrationKey,
    OrchestratorAPIKey,
    AgentCertificate,
)
from deps import (
    get_current_user,
    get_admin_user,
    verify_agent_api_key,
    registration_database,
    generate_agent_api_key,
    hash_api_key,
    iso_utc,
    log_activity,
    REQUIRE_MTLS,
)
from core.backup_service import BackupService
from core.vm_inventory import identity_fields
from core.vm_backup_guidance import BackupGuidance, backup_guidance
from core.pki import get_pki_manager, is_ca_initialized, retire_agent_certificates
from schemas import AgentUpdateRequest, AgentSettingsUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["agents"])


@router.post("/agents/register")
async def register_agent(
    agent_data: dict,
    request: Request,
    api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(registration_database),
):
    """
    Agent self-registration endpoint with secure key generation.

    Requires valid registration key from AgentRegistrationKey table.
    Validates key expiration, max uses, and enabled status.
    """
    # Validate registration key
    if not api_key:
        raise HTTPException(
            status_code=401, detail="Registration key required. Set X-API-Key header."
        )

    # Check against database registration keys
    key_hash = hash_api_key(api_key)
    reg_key = (
        db.query(AgentRegistrationKey)
        .filter(AgentRegistrationKey.key_hash == key_hash)
        .with_for_update()
        .one_or_none()
    )

    if not reg_key:
        raise HTTPException(status_code=401, detail="Invalid registration key.")
    # Re-check while holding the row lock; concurrent one-use registrations
    # cannot both spend the same key after the initial identity lookup.
    if not reg_key.is_valid():
        reasons = []
        if not reg_key.enabled:
            reasons.append("disabled")
        if reg_key.is_expired():
            reasons.append("expired")
        if reg_key.is_max_uses_reached():
            reasons.append("max uses reached")

        raise HTTPException(
            status_code=401, detail=f"Registration key is {', '.join(reasons)}."
        )

    hostname = agent_data.get("hostname")
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname is required")
    if not reg_key.agent_hostname or hostname != reg_key.agent_hostname:
        raise HTTPException(
            status_code=403, detail="Registration key is not authorized for this agent"
        )

    # A key-only registration is the one bootstrap exception to strict mTLS.
    # It must issue a client identity in the same transaction; otherwise the
    # agent cannot make its first authenticated callback after spending the key.
    if REQUIRE_MTLS and not is_ca_initialized(db):
        raise HTTPException(503, "Agent certificate issuance unavailable")

    reg_key.use_count += 1
    reg_key.last_used_at = datetime.utcnow()

    # Extract agent details
    from core.file_backups import FILE_CAPABILITY_FIELDS

    supplied = agent_data.get("capabilities")
    capabilities = (
        {
            key: value
            for key, value in supplied.items()
            if key not in FILE_CAPABILITY_FIELDS
        }
        if isinstance(supplied, dict)
        else {}
    )
    ip_address = agent_data.get("ip_address")
    port = agent_data.get("port")
    version = agent_data.get("version")
    libvirt_uri = agent_data.get("libvirt_uri")

    # Derive platform from libvirt URI or capabilities
    platform = capabilities.get("platform") or (
        "KubeVirt"
        if capabilities.get("provider") == "kubevirt"
        else "KVM/QEMU" if libvirt_uri and "qemu" in libvirt_uri else None
    )

    # Check for existing agent
    existing = db.query(Agent).filter(Agent.hostname == hostname).first()

    if existing:
        # Re-registration: update agent details
        agent = existing
        agent.status = "online"
        agent.last_heartbeat = datetime.utcnow()
        agent.ip_address = ip_address
        agent.port = port
        agent.version = version
        agent.platform = platform
    else:
        # New agent registration
        agent = Agent(
            hostname=hostname,
            status="online",
            last_heartbeat=datetime.utcnow(),
            ip_address=ip_address,
            port=port,
            version=version,
            platform=platform,
        )
        db.add(agent)
        db.flush()

    # Generate new secure API key for this agent
    agent_api_key = generate_agent_api_key()
    key_hash = hash_api_key(agent_api_key)
    key_prefix = agent_api_key[:8]

    # Create or update AgentAPIKey
    if agent.api_key:
        agent.api_key.key_hash = key_hash
        agent.api_key.key_prefix = key_prefix
        agent.api_key.updated_at = datetime.utcnow()
    else:
        agent_api_key_obj = AgentAPIKey(
            agent_id=agent.id,
            name=agent.display_name or hostname,
            key_hash=key_hash,
            key_prefix=key_prefix,
        )
        db.add(agent_api_key_obj)

    # Update legacy fields (backward compatibility)
    agent.api_key_hash = key_hash
    agent.key_created_at = datetime.utcnow()
    if not agent.display_name and isinstance(agent_data.get("display_name"), str):
        agent.display_name = agent_data["display_name"][:255]
    agent.capabilities = capabilities

    # Registration key use, agent API key and optional certificate replacement
    # commit together. A failed certificate issue must not spend a one-use key
    # or rotate the agent's API key without delivering the new credential.
    tls_data = None
    if is_ca_initialized(db):
        try:
            pki = get_pki_manager(db)
            if pki is None:
                raise RuntimeError("CA material is unavailable")
            # The registration request cannot authorize additional server SANs.
            cert_result = pki.issue_agent_cert(hostname)
            retire_agent_certificates(db, agent.id)
            db.add(
                AgentCertificate(
                    agent_id=agent.id,
                    serial_number=cert_result["serial"],
                    fingerprint=cert_result["fingerprint"],
                    common_name=hostname,
                    expires_at=cert_result["expires_at"],
                )
            )
            agent.cert_fingerprint = cert_result["fingerprint"]
            agent.cert_expires_at = cert_result["expires_at"]
            agent.mtls_enabled = True
            tls_data = {
                "ca_cert": pki.get_ca_cert_pem(),
                "agent_cert": cert_result["cert_pem"],
                "agent_key": cert_result["key_pem"],
                "fingerprint": cert_result["fingerprint"],
                "expires_at": cert_result["expires_at"].isoformat() + "Z",
            }
        except Exception:
            db.rollback()
            logger.exception("Failed to issue TLS certificate during registration")
            raise HTTPException(503, "Agent certificate issuance unavailable") from None

    db.commit()
    db.refresh(agent)

    # Get first enabled orchestrator API key for agent.env snippet
    orch_key = (
        db.query(OrchestratorAPIKey)
        .filter(OrchestratorAPIKey.enabled.is_(True))
        .first()
    )

    orchestrator_url = os.getenv("PUBLIC_API_URL", str(request.base_url))

    env_snippet = f"""# Agent Configuration for {hostname}
ORCHESTRATOR_URL={orchestrator_url}
AGENT_API_KEY={agent_api_key}
ORCHESTRATOR_API_KEY={orch_key.key_prefix + '...' if orch_key else '(generate in UI)'}
BACKUP_STORAGE_PATH=/var/lib/vnbui/backups
LIBVIRT_URI=qemu:///system
LOG_FORMAT=json
LOG_LEVEL=INFO
"""

    return {
        "agent_id": agent.id,
        "hostname": hostname,
        "api_key": agent_api_key,
        "key_prefix": key_prefix,
        "orchestrator_url": orchestrator_url,
        "orchestrator_api_key_required": orch_key is not None,
        "heartbeat_interval": 30,
        "env_snippet": env_snippet,
        "tls": tls_data,
        "message": (
            "Agent re-registered successfully"
            if existing
            else "Agent registered successfully. Save the API key - it will not be shown again!"
        ),
    }


@router.post("/agents/{hostname}/vms")
async def sync_agent_vms(
    hostname: str,
    vms_data: dict,
    agent: Agent = Depends(verify_agent_api_key),
    db: Session = Depends(get_db),
):
    """
    Sync VMs from agent - requires agent API key authentication.
    """
    if agent.hostname != hostname:
        raise HTTPException(
            status_code=403,
            detail=f"Hostname mismatch. Authenticated agent '{agent.hostname}' cannot sync VMs for '{hostname}'.",
        )

    from core.vm_inventory import sync_inventory

    synced_count = sync_inventory(db, agent, vms_data)

    return {
        "synced": synced_count,
        "agent_hostname": hostname,
        "message": f"Synced {synced_count} VMs",
    }


@router.get("/agents")
async def list_agents(
    db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """List all agents (protected)"""
    agents = db.query(Agent).all()
    return [
        {
            "id": agent.id,
            "hostname": agent.hostname,
            "display_name": agent.display_name,
            "status": agent.status,
            "ip_address": agent.ip_address,
            "port": agent.port,
            "version": agent.version,
            "last_heartbeat": iso_utc(agent.last_heartbeat),
            "vm_count": sum(vm.inventory_present for vm in agent.vms),
            "metrics": agent.metrics or {},
        }
        for agent in agents
    ]


VALID_VM_SORT_COLUMNS = {
    "name",
    "state",
    "memory_kb",
    "vcpu_count",
    "created_at",
    "agent_hostname",
}


def _build_vm_query(db: Session, search=None, agent_id=None, state=None, group_id=None):
    """Build filtered VM query (shared between list and ids-by-filter)."""
    from models import vm_group_association

    query = db.query(VM)

    if search:
        query = query.filter(VM.name.ilike(f"%{search}%"))
    if agent_id:
        query = query.filter(VM.agent_id == agent_id)
    if state:
        query = query.filter(VM.state == state)
    if group_id:
        query = query.join(vm_group_association).filter(
            vm_group_association.c.group_id == group_id
        )

    return query


@router.get("/vms")
async def list_vms(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    search: Optional[str] = None,
    agent_id: Optional[str] = None,
    state: Optional[str] = None,
    group_id: Optional[str] = None,
    sort_by: str = "name",
    sort_order: str = "asc",
    inventory_present: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List all VMs with pagination, filtering, and sorting (protected)"""
    limit = min(limit, 100)

    if sort_by not in VALID_VM_SORT_COLUMNS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by: {sort_by}. Must be one of: {', '.join(sorted(VALID_VM_SORT_COLUMNS))}",
        )
    if sort_order not in ("asc", "desc"):
        raise HTTPException(
            status_code=400, detail="sort_order must be 'asc' or 'desc'"
        )

    query = _build_vm_query(
        db, search=search, agent_id=agent_id, state=state, group_id=group_id
    )
    if inventory_present is not None:
        query = query.filter(VM.inventory_present == inventory_present)

    # Apply sorting
    if sort_by == "agent_hostname":
        sort_col = Agent.hostname
        query = query.join(Agent, VM.agent_id == Agent.id)
    else:
        sort_col = getattr(VM, sort_by)

    query = query.order_by(
        sort_col.desc() if sort_order == "desc" else sort_col.asc(), VM.id
    )

    total = query.count()
    vms = query.offset(skip).limit(limit).all()

    # Subquery: most recent completed/failed backup per VM
    vm_ids = [vm.id for vm in vms]
    last_backup_map = {}
    if vm_ids:
        # Find the latest backup (by created_at) for each VM
        latest_created_sq = (
            select(
                Backup.vm_id,
                func.max(Backup.created_at).label("max_created_at"),
            )
            .where(
                Backup.vm_id.in_(vm_ids),
                Backup.status.in_(["completed", "failed"]),
            )
            .group_by(Backup.vm_id)
            .subquery()
        )
        last_backups = (
            db.query(Backup)
            .join(
                latest_created_sq,
                (Backup.vm_id == latest_created_sq.c.vm_id)
                & (Backup.created_at == latest_created_sq.c.max_created_at),
            )
            .all()
        )
        for b in last_backups:
            last_backup_map[b.vm_id] = b

    items = [
        {
            "id": vm.id,
            "name": vm.name,
            "state": vm.state,
            "uuid": vm.uuid,
            "memory_kb": vm.memory_kb,
            "vcpu_count": vm.vcpu_count,
            "disks": vm.disks or [],
            "metadata": vm.vm_metadata or {},
            **identity_fields(vm),
            "agent_id": vm.agent_id,
            "agent_hostname": vm.agent.hostname,
            "created_at": iso_utc(vm.created_at),
            "last_backup_type": (
                last_backup_map[vm.id].backup_type if vm.id in last_backup_map else None
            ),
            "last_backup_status": (
                last_backup_map[vm.id].status if vm.id in last_backup_map else None
            ),
            "last_backup_at": (
                iso_utc(last_backup_map[vm.id].created_at)
                if vm.id in last_backup_map
                else None
            ),
            "backup_eligibility": BackupService.check_disk_eligibility(vm),
        }
        for vm in vms
    ]

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@router.post("/vms/ids-by-filter")
async def get_vm_ids_by_filter(
    body: dict, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """Get VM IDs matching filter criteria (for 'select all matching' across pages)."""
    query = _build_vm_query(
        db,
        search=body.get("search"),
        agent_id=body.get("agent_id"),
        state=body.get("state"),
        group_id=body.get("group_id"),
    )
    vm_ids = [
        vm.id
        for vm in query.filter(VM.inventory_present.is_(True))
        .with_entities(VM.id)
        .all()
    ]
    return {"vm_ids": vm_ids, "count": len(vm_ids)}


@router.get("/vms/{vm_id}")
async def get_vm(
    vm_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """Get VM details (protected)"""
    from models import Backup

    vm = db.query(VM).filter(VM.id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    backup_count = db.query(Backup).filter(Backup.vm_id == vm_id).count()

    return {
        "id": vm.id,
        "name": vm.name,
        "uuid": vm.uuid,
        "state": vm.state,
        "agent_id": vm.agent_id,
        "agent_hostname": vm.agent.hostname,
        "memory_kb": vm.memory_kb,
        "vcpu_count": vm.vcpu_count,
        "disks": vm.disks or [],
        "vm_metadata": vm.vm_metadata or {},
        **identity_fields(vm),
        "backup_count": backup_count,
        "created_at": iso_utc(vm.created_at),
        "backup_eligibility": BackupService.check_disk_eligibility(vm),
    }


# ============================================================================
# AGENT MANAGEMENT ENDPOINTS (UI -> Backend)
# These endpoints are called by the frontend to manage agents.
# NOTE: Must be defined AFTER specific routes to avoid route conflicts.
# ============================================================================


@router.get("/agents/{agent_id}")
async def get_agent_details(
    agent_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """Get agent details by ID"""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Get agent API key info
    agent_key_info = None
    if agent.api_key:
        agent_key_info = {
            "key_prefix": agent.api_key.key_prefix,
            "expires_at": iso_utc(agent.api_key.expires_at),
            "enabled": agent.api_key.enabled,
            "is_valid": agent.api_key.is_valid(),
            "last_used_at": iso_utc(agent.api_key.last_used_at),
        }

    return {
        "id": agent.id,
        "hostname": agent.hostname,
        "display_name": agent.display_name,
        "status": agent.status,
        "ip_address": agent.ip_address,
        "port": agent.port,
        "version": agent.version,
        "platform": agent.platform,
        "last_heartbeat": iso_utc(agent.last_heartbeat),
        "created_at": iso_utc(agent.created_at),
        "vm_count": sum(vm.inventory_present for vm in agent.vms),
        "vms": [
            {
                "id": vm.id,
                "name": vm.name,
                "state": vm.state,
                "uuid": vm.uuid,
                "memory_kb": vm.memory_kb,
                "vcpu_count": vm.vcpu_count,
                "disks": vm.disks or [],
                "metadata": vm.vm_metadata or {},
                **identity_fields(vm),
            }
            for vm in agent.vms
        ],
        "capabilities": agent.capabilities or {},
        "metrics": agent.metrics or {},
        "config": agent.config or {},
        "api_key": agent_key_info,
    }


@router.patch("/agents/{agent_id}")
async def update_agent(
    agent_id: str,
    agent_data: AgentUpdateRequest,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """Update agent settings (admin only)"""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Update fields
    if agent_data.display_name is not None:
        agent.display_name = agent_data.display_name
    if agent_data.status is not None:
        agent.status = agent_data.status

    db.commit()
    db.refresh(agent)

    log_activity(
        db,
        admin_user,
        action="agent_updated",
        resource_type="agent",
        resource_id=agent.id,
        details={"hostname": agent.hostname, "display_name": agent.display_name},
    )

    return {
        "id": agent.id,
        "hostname": agent.hostname,
        "display_name": agent.display_name,
        "status": agent.status,
        "message": "Agent updated successfully",
    }


@router.patch("/agents/{agent_id}/settings")
async def update_agent_settings(
    agent_id: str,
    settings: AgentSettingsUpdate,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """
    Update agent runtime settings (admin only).

    Settings are delivered to agent via heartbeat response and applied
    unless overridden by local agent.env configuration.

    Pre-condition: No active backups on agent (returns 409 if busy).
    """
    agent = db.query(Agent).filter(Agent.id == agent_id).with_for_update().first()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    from core.agent_scope import validate_settings

    requested_settings = {
        k: v
        for k, v in settings.model_dump(exclude_unset=True).items()
        if v is not None
    }
    validate_settings(agent, requested_settings)

    # Check for active backups on this agent's VMs
    active_backups = (
        db.query(Backup)
        .join(VM)
        .filter(VM.agent_id == agent_id, Backup.status.in_(["pending", "running"]))
        .count()
    )

    if active_backups > 0 and set(requested_settings) != {"selected_source_namespaces"}:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot update settings while {active_backups} backup(s) are running on this agent",
        )

    # Build config dict from provided settings (only non-None values)
    config_update = {}
    for field, value in settings.model_dump(exclude_unset=True).items():
        if value is not None:
            config_update[field] = value

    if "selected_source_namespaces" in config_update:
        config_update["scope_revision"] = str(uuid.uuid4())

    # Merge with existing config (preserve unspecified settings)
    current_config = dict(agent.config or {})
    current_config.update(config_update)
    agent.config = current_config

    db.commit()
    db.refresh(agent)

    log_activity(
        db,
        admin_user,
        action="agent_settings_updated",
        resource_type="agent",
        resource_id=agent.id,
        details={"hostname": agent.hostname, "settings": config_update},
    )

    return {
        "id": agent.id,
        "hostname": agent.hostname,
        "config": agent.config,
        "message": "Agent settings updated. Will be applied on next heartbeat.",
    }


@router.delete("/agents/{agent_id}")
async def delete_agent(
    agent_id: str,
    cascade: bool = False,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """
    Delete agent (admin only).

    Args:
        agent_id: Agent ID to delete
        cascade: If True, delete VMs only when they have no backup custody
    """
    agent = db.query(Agent).filter(Agent.id == agent_id).first()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Get VMs for logging and cascade check
    vms = db.query(VM).filter(VM.agent_id == agent_id).all()
    vm_count = len(vms)

    if vm_count > 0 and not cascade:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete agent with {vm_count} VMs. Use cascade=true to delete VMs too.",
        )

    # Backup records are the durable custody for payloads, chains and retention.
    # Agent deletion must not bypass the backup deletion workflow or orphan S3.
    if (
        vms
        and db.query(Backup.id).filter(Backup.vm_id.in_([vm.id for vm in vms])).first()
    ):
        raise HTTPException(
            status_code=409,
            detail="Cannot delete agent with backups. Retire backups first.",
        )

    deleted_items = {"vms": 0, "backups": 0, "certificates": 0}

    # Cascade only zero-backup VMs.
    if cascade and vm_count > 0:
        for vm in vms:
            db.delete(vm)
            deleted_items["vms"] += 1

    # An enrolled mTLS agent has non-nullable certificate FKs. Removing every
    # certificate in this transaction also invalidates its future TLS identity.
    for certificate in db.query(AgentCertificate).filter_by(agent_id=agent_id).all():
        db.delete(certificate)
        deleted_items["certificates"] += 1

    # Delete API key (FK constraint)
    if agent.api_key:
        db.delete(agent.api_key)

    # Delete agent
    hostname = agent.hostname
    db.delete(agent)

    log_activity(
        db,
        admin_user,
        action="agent_deleted",
        resource_type="agent",
        resource_id=agent_id,
        details={
            "hostname": hostname,
            "cascade": cascade,
            "deleted_vms": deleted_items["vms"],
            "deleted_backups": deleted_items["backups"],
            "deleted_certificates": deleted_items["certificates"],
        },
        commit=False,
    )
    db.commit()

    message = f"Agent {hostname} deleted"
    if cascade and vm_count > 0:
        message += f" with {deleted_items['vms']} VMs"

    return {"message": message, "deleted": deleted_items}


from core.operator_requests import request_identity  # noqa: E402
from core.agent_key_rotation import candidate_credential, CandidateProof  # noqa: E402
from core import agent_key_rotation  # noqa: E402
from core.task_lifetime import run_owned_worker  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402


@router.post("/agents/{agent_id}/rotate-key")
async def rotate_agent_key(
    agent_id: str,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
    request_id: str | None = Depends(request_identity),
):
    """Stage a one-time candidate; the current agent key remains active until proof."""
    try:
        return agent_key_rotation.stage(db, admin_user, agent_id, request_id)
    except Exception:
        db.rollback()
        raise


@router.post("/agents/{agent_id}/key-rotations/{rotation_id}/activate")
async def activate_agent_key(proof: CandidateProof = Depends(candidate_credential)):
    """Candidate proof is limited to this exact rotation; no user Bearer substitute."""
    result = await run_owned_worker(agent_key_rotation.activate, proof)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/agents/{agent_id}/key-rotations")
async def list_agent_key_rotations(
    agent_id: str,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    return agent_key_rotation.status(db, agent_id, admin_user.org_id)


@router.get("/agents/{agent_id}/key-rotations/{rotation_id}")
async def get_agent_key_rotation(
    agent_id: str,
    rotation_id: str,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    return agent_key_rotation.status(db, agent_id, admin_user.org_id, rotation_id)


@router.delete("/agents/{agent_id}/key-rotations/{rotation_id}")
async def cancel_agent_key_rotation(
    agent_id: str,
    rotation_id: str,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    try:
        return agent_key_rotation.cancel(db, admin_user, agent_id, rotation_id)
    except Exception:
        db.rollback()
        raise


@router.get("/vms/{vm_id}/backup-guidance", response_model=BackupGuidance)
def get_vm_backup_guidance(
    vm_id: str,
    exclude_disk: Annotated[
        list[Annotated[str, Query(min_length=1, max_length=128)]] | None,
        Query(
            max_length=256,
            description="Repeat for each explicitly excluded disk target.",
        ),
    ] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Assess the selected disks using recorded observations. This read creates no backup or reservation."""
    vm = (
        db.query(VM)
        .filter_by(id=vm_id, org_id=current_user.org_id)
        .options(
            joinedload(VM.agent).load_only(
                Agent.org_id, Agent.metrics, Agent.capabilities, Agent.config
            )
        )
        .one_or_none()
    )
    if vm is None:
        raise HTTPException(404, "VM not found")
    return backup_guidance(db, vm, exclude_disk or [])
