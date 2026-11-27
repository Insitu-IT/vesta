"""
Health monitoring endpoints: agent health, heartbeat, system health, pending jobs.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from core import metrics as prom
from core.callback_identity import (
    CallbackIdentity,
    authenticate_callback,
    callback_worker,
)
from core.agent_health import assess_agent_health
from core.backup_event_custody import generic_event_backups
from core.native_hold_observation import observe_native_hold
from core.storage_hold_observation import observe_storage_hold
from core.storage_progress_observation import observe_storage_progress
from core.notifications import notify_backup_failure, notify_backup_success
from core.settings_reader import get_setting
from core.settings_service import SettingsService
from core.websocket import websocket_manager
from database import get_db
from deps import get_admin_user, get_current_user, iso_utc, verify_agent_api_key
from fastapi import APIRouter, Depends, HTTPException, Request
from models import VM, ActivityLog, Agent, Backup, Schedule, SystemEvent, User
from core.vm_inventory import legacy_event_vm
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from version import __version__
from starlette.concurrency import run_in_threadpool

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health/diagnostics")
def support_diagnostics(
    backup_id: UUID | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """Admin-only, organization-scoped download; collection never repairs state."""
    from core.support_diagnostics import collect
    from starlette.responses import JSONResponse

    report = collect(
        db, current_user.org_id, backup_id=str(backup_id) if backup_id else None
    )
    return JSONResponse(
        report,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Disposition": 'attachment; filename="vesta-diagnostics.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/agents/backups/{backup_id}/storage-retirement")
async def storage_retirement(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    """Reveal only the exact reviewed release to its original agent."""
    from core.storage_retirement import retirement_proof
    from core.storage_receipt_v2 import decode
    from core.s3_ownership import StorageOwnershipError
    from starlette.responses import JSONResponse

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 2048:
            raise HTTPException(413, "Retirement binding too large")
        body.extend(chunk)
    try:
        binding = decode(body)
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Invalid retirement binding") from None
    try:
        result = await run_in_threadpool(
            callback_worker, identity, retirement_proof, backup_id, binding
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    except StorageOwnershipError:
        raise HTTPException(409, "Reviewed retirement unavailable") from None


@router.post("/agents/backups/{backup_id}/transaction-key")
async def transaction_key(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    """Authenticated, no-store, memory-only key delivery for exact live custody."""
    from core.storage_attempt_key import resolve_attempt_key
    from core.storage_receipt_v2 import decode
    from core.s3_ownership import StorageOwnershipError
    from starlette.responses import JSONResponse

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 2048:
            raise HTTPException(413, "Transaction binding too large")
        body.extend(chunk)
    try:
        binding = decode(body)
        if not isinstance(binding, dict):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Invalid transaction binding") from None
    try:
        result = await run_in_threadpool(
            callback_worker, identity, resolve_attempt_key, backup_id, binding
        )
        return JSONResponse(
            result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )
    except StorageOwnershipError:
        raise HTTPException(409, "Transaction key unavailable") from None


@router.post("/agents/backups/{backup_id}/storage-control")
async def storage_control(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    """Finite, authenticated control; signed authority never enters durable state."""
    from core.storage_control import resolve_control
    from core.storage_receipt_v2 import decode
    from core.s3_ownership import StorageOwnershipError
    from starlette.responses import JSONResponse

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 2 * 1024 * 1024:
            raise HTTPException(413, "Transaction control too large")
        body.extend(chunk)
    try:
        value = decode(body)
        if not isinstance(value, dict):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Invalid transaction control") from None
    try:
        result = await run_in_threadpool(
            callback_worker, identity, resolve_control, backup_id, value
        )
        return JSONResponse(
            result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )
    except StorageOwnershipError:
        raise HTTPException(409, "Transaction control unavailable") from None


async def _checkpoint_control(
    request,
    backup_id,
    operation,
    response_status=200,
    max_body=65536,
    *,
    identity,
):
    from core.storage_receipt_v2 import decode
    from core.s3_ownership import StorageOwnershipError
    from starlette.responses import JSONResponse

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_body:
            raise HTTPException(413, "Checkpoint evidence too large")
        body.extend(chunk)
    try:
        value = decode(body)
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Invalid checkpoint evidence") from None
    try:
        result = await run_in_threadpool(
            callback_worker, identity, operation, backup_id, value
        )
        return JSONResponse(
            result, status_code=response_status, headers={"Cache-Control": "no-store"}
        )
    except StorageOwnershipError:
        raise HTTPException(
            409, "Checkpoint evidence refused; retain journal"
        ) from None
    except Exception:
        raise HTTPException(
            503, "Checkpoint evidence unavailable; retain journal"
        ) from None


@router.post("/agents/backups/{backup_id}/native-admission")
async def native_admission(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_job import admit_producer

    return await _checkpoint_control(
        request, backup_id, admit_producer, identity=identity
    )


@router.post("/agents/backups/{backup_id}/native-inventory")
async def native_inventory(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_job import accept_inventory

    return await _checkpoint_control(
        request,
        backup_id,
        accept_inventory,
        max_body=4 * 1024 * 1024,
        identity=identity,
    )


@router.post("/agents/backups/{backup_id}/native-no-effect")
async def native_no_effect(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_no_effect import settle

    return await _checkpoint_control(
        request, backup_id, settle, max_body=256 * 1024, identity=identity
    )


@router.post("/agents/backups/{backup_id}/native-closed-failure")
async def native_closed_failure(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_closed_failure import settle

    return await _checkpoint_control(
        request, backup_id, settle, max_body=4 * 1024 * 1024, identity=identity
    )


@router.post("/agents/backups/{backup_id}/native-fenced-failure")
async def native_fenced_failure(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_fenced_failure import settle

    return await _checkpoint_control(
        request, backup_id, settle, max_body=512 * 1024, identity=identity
    )


@router.post("/agents/backups/{backup_id}/native-transaction")
async def native_transaction(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_storage_plan import resolve_native_transaction

    return await _checkpoint_control(
        request, backup_id, resolve_native_transaction, identity=identity
    )


@router.post("/agents/backups/{backup_id}/native-publication")
async def native_publication(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.native_publication import publish_native_backup

    return await _checkpoint_control(
        request, backup_id, publish_native_backup, identity=identity
    )


@router.post("/agents/backups/{backup_id}/finalize-intent")
async def transaction_finalize_intent(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.storage_finalize import finalize_intent

    return await _checkpoint_control(
        request, backup_id, finalize_intent, identity=identity
    )


@router.post("/agents/backups/{backup_id}/checkpoint-proof")
async def transaction_checkpoint_proof(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    from core.storage_finalize import checkpoint_proof

    return await _checkpoint_control(
        request, backup_id, checkpoint_proof, 202, identity=identity
    )


@router.post("/agents/backups/{backup_id}/prepared-receipt")
async def prepared_receipt(
    backup_id: str,
    request: Request,
    identity: CallbackIdentity = Depends(authenticate_callback),
):
    """A durable acceptance permits finalize, never completion or visibility.

    The agent must retain its prepared journal until this response is received.
    Authentication installs persisted tenant identity before any reservation read.
    """
    from core.storage_transaction import accept_prepared_receipt
    from core.s3_ownership import StorageOwnershipError
    from core.storage_receipt_v2 import decode

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 4 * 1024 * 1024:
            raise HTTPException(413, "Prepared receipt exceeds 4 MiB")
        body.extend(chunk)
    try:
        receipt = decode(body)
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Prepared receipt must be JSON")
    try:
        # Worker owns its tenant context and session through cancellation cleanup.
        return await run_in_threadpool(
            callback_worker,
            identity,
            accept_prepared_receipt,
            backup_id,
            receipt,
            with_proof=False,
        )
    except StorageOwnershipError:
        raise HTTPException(409, "Prepared receipt refused; retain cleanup journal")
    except Exception:
        # Provider exceptions can include request details. Never echo them or
        # acknowledge an acceptance whose transaction did not commit.
        raise HTTPException(503, "Prepared acceptance unavailable; retain journal")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


async def _get_agent_health_data(db: Session):
    """Get health status of all agents (helper function)"""
    agents = db.query(Agent).all()
    now = datetime.utcnow()
    health_threshold = timedelta(minutes=5)  # Consider offline if no heartbeat in 5 min

    agent_health = []
    online_count = 0
    offline_count = 0

    for agent in agents:
        time_since_heartbeat = now - (agent.last_heartbeat or agent.created_at)
        is_online = time_since_heartbeat < health_threshold

        if is_online:
            online_count += 1
        else:
            offline_count += 1

        agent_health.append(
            {
                "id": agent.id,
                "hostname": agent.hostname,
                "status": "online" if is_online else "offline",
                "last_heartbeat": iso_utc(agent.last_heartbeat),
                "time_since_heartbeat_seconds": int(
                    time_since_heartbeat.total_seconds()
                ),
                "vm_count": len(agent.vms),
            }
        )

    return {
        "summary": {
            "total_agents": len(agents),
            "online": online_count,
            "offline": offline_count,
            "health_percentage": round(
                (online_count / len(agents) * 100) if agents else 100, 2
            ),
        },
        "agents": agent_health,
    }


def _check_s3_for_backup(backup, db: Session) -> str | None:
    """Check if backup data exists in S3. Returns s3:// location or None."""
    try:
        from core.settings_service import SettingsService

        svc = SettingsService(db)
        s3_config = svc.get_s3_config()
        if not s3_config or not s3_config.get("bucket"):
            return None

        import boto3

        s3 = boto3.client(
            "s3",
            endpoint_url=s3_config.get("endpoint") or None,
            aws_access_key_id=s3_config.get("access_key"),
            aws_secret_access_key=s3_config.get("secret_key"),
            region_name=s3_config.get("region", "us-east-1"),
        )

        prefix = (
            s3_config.get("prefix", "backups").strip("/") + "/" + str(backup.id) + "/"
        )
        bucket = s3_config["bucket"]

        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        objects = resp.get("Contents", [])

        # Need at least a vmconfig and a data file to consider it valid
        has_vmconfig = any("vmconfig" in o["Key"] for o in objects)
        has_data = any(
            o["Key"].endswith((".data", ".data.enc", ".raw", ".raw.enc"))
            for o in objects
        )

        if has_vmconfig and has_data:
            return f"s3://{bucket}/{prefix.rstrip('/')}"

        return None
    except ImportError:
        logger.debug("boto3 not installed, skipping S3 verification")
        return None
    except Exception as e:
        logger.warning(f"S3 verification failed for backup {backup.id}: {e}")
        return None


async def _process_agent_events(agent: Agent, events: list, db: Session):
    """Process libvirt events from agent heartbeat.

    Handles:
    - backup_job: Update backup status on completion/failure
    - vm_lifecycle: Update VM state (started, stopped, etc.)
    - backup_reconciled: Agent startup reconciliation status update
    - orphan_backup_detected: Agent found block job with no orchestrator record

    Args:
        agent: The authenticated agent
        events: List of event dicts from agent
        db: Database session
    """
    logger.info(f"Processing {len(events)} events from agent {agent.hostname}")
    progress_updates = []

    for event in events:
        try:
            event_type = event.get("type")
            vm_name = event.get("vm_name")

            if event_type == "storage_transaction_progress":
                observation = observe_storage_progress(db, agent, event)
                if observation:
                    progress_updates.append(observation)

            elif event_type == "storage_transaction_held":
                # Exact immutable reservation/plan bound negative observation.
                # No publication, capacity release or cleanup permission.
                observe_storage_hold(db, agent, event)

            elif event_type == "native_attempt_held":
                # Repeatable exact-intent display only. Never terminal status,
                # capacity release, producer control or publication evidence.
                observe_native_hold(db, agent, event)

            elif event_type == "backup_job":
                status = event.get("status")  # completed, failed, cancelled
                disk = event.get("disk")

                logger.info(f"Backup job event: {vm_name}:{disk} -> {status}")

                # Find running backup for this VM
                vm = legacy_event_vm(db, agent.id, vm_name)

                if vm:
                    # Find most recent running backup for this VM
                    backup = (
                        generic_event_backups(db)
                        .filter(Backup.vm_id == vm.id, Backup.status == "running")
                        .order_by(Backup.created_at.desc())
                        .first()
                    )

                    if backup:
                        if status == "completed":
                            backup.status = "completed"
                            backup.completed_at = datetime.utcnow()
                            backup.progress = 100
                            logger.info(
                                f"Backup {backup.id} marked completed via libvirt event"
                            )

                            # Prometheus
                            duration = (
                                backup.completed_at - backup.created_at
                            ).total_seconds()
                            prom.record_backup_completed(duration, backup.size_bytes)

                            # WebSocket notification
                            await websocket_manager.broadcast(
                                {
                                    "type": "backup_completed",
                                    "backup_id": str(backup.id),
                                    "vm_name": vm_name,
                                }
                            )

                        elif status == "failed":
                            backup.status = "failed"
                            error_msg = f"Block job failed on {disk}"
                            backup.tags = backup.tags or {}
                            backup.tags["error"] = error_msg
                            logger.warning(
                                f"Backup {backup.id} marked failed via libvirt event"
                            )
                            prom.record_backup_failed()

                            await websocket_manager.broadcast(
                                {
                                    "type": "backup_failed",
                                    "backup_id": str(backup.id),
                                    "vm_name": vm_name,
                                    "error": error_msg,
                                }
                            )

                        elif status == "cancelled":
                            backup.status = "cancelled"
                            logger.info(
                                f"Backup {backup.id} marked cancelled via libvirt event"
                            )
                            prom.record_backup_cancelled()

                # Log system event
                _log_system_event(
                    db, "backup_job", "agent", str(agent.id), "backup", None, event
                )

            elif event_type == "vm_lifecycle":
                state = event.get("state")  # started, stopped, crashed, etc.

                logger.info(f"VM lifecycle event: {vm_name} -> {state}")

                # Update VM state in database
                vm = legacy_event_vm(db, agent.id, vm_name)

                if vm:
                    # Map libvirt states to our state names
                    state_map = {
                        "started": "running",
                        "resumed": "running",
                        "stopped": "stopped",
                        "shutdown": "stopped",
                        "crashed": "crashed",
                        "suspended": "paused",
                        "pmsuspended": "paused",
                    }
                    vm.state = state_map.get(state, state)
                    logger.debug(f"Updated VM {vm_name} state to {vm.state}")

                # WebSocket notification
                await websocket_manager.broadcast(
                    {
                        "type": "vm_state_changed",
                        "vm_name": vm_name,
                        "state": state,
                        "agent_id": str(agent.id),
                    }
                )

                # Log system event
                _log_system_event(
                    db,
                    "vm_lifecycle",
                    "agent",
                    str(agent.id),
                    "vm",
                    vm.id if vm else None,
                    event,
                )

            elif event_type == "backup_reconciled":
                # Agent startup reconciliation: agent determined true status of a backup
                backup_id = event.get("backup_id")
                new_status = event.get("new_status")
                old_status = event.get("old_status")
                reason = event.get("reason", "Reconciled by agent")

                logger.info(
                    f"Backup reconciled: {backup_id} {old_status} -> {new_status}"
                )
                prom.record_reconciliation_event(event_type="status_corrected")

                backup = (
                    generic_event_backups(db).filter(Backup.id == backup_id).first()
                )
                if backup:
                    # Verify backup belongs to this agent's VMs
                    vm = (
                        db.query(VM)
                        .filter(VM.id == backup.vm_id, VM.agent_id == agent.id)
                        .first()
                    )
                    if vm:
                        from core.checkpoint_state import apply_checkpoint_state

                        new_status = apply_checkpoint_state(backup, event, new_status)
                        # Don't regress from upload-phase states back to
                        # "completed".  This happens when the backup-phase
                        # completion event arrives via heartbeat AFTER the
                        # monitor has already triggered execute_upload and
                        # moved the status to "uploading".
                        if (
                            backup.status
                            in (
                                "uploading",
                                "upload_failed",
                            )
                            and new_status == "completed"
                            and not (backup.tags or {}).get("checkpoint_required")
                        ):
                            logger.info(
                                f"Ignoring stale 'completed' event for backup "
                                f"{backup_id} (currently {backup.status})"
                            )
                            _log_system_event(
                                db,
                                "backup_reconciled",
                                "agent",
                                str(agent.id),
                                "backup",
                                backup_id,
                                event,
                            )
                            continue

                        # Upload-phase backup declared failed by agent
                        # (e.g. local data missing after restart).  The
                        # upload may have actually succeeded — local files
                        # get cleaned up after a successful S3 upload.
                        # Verify S3 before accepting the failure.
                        if (
                            not (backup.tags or {}).get("checkpoint_required")
                            and new_status == "failed"
                            and old_status
                            in (
                                "uploading",
                                "upload_failed",
                            )
                        ):
                            s3_loc = _check_s3_for_backup(backup, db)
                            if s3_loc:
                                logger.info(
                                    f"Backup {backup_id} declared failed by agent "
                                    f"but found in S3: {s3_loc}"
                                )
                                new_status = "completed"

                        backup.status = new_status
                        if new_status == "completed":
                            backup.completed_at = (
                                backup.completed_at or datetime.utcnow()
                            )
                            backup.progress = 100

                            # Persist S3 location and size from event
                            s3_loc = event.get("s3_location")
                            if (
                                not s3_loc
                                and backup.storage_path
                                and backup.storage_path.startswith("s3://")
                            ):
                                s3_loc = backup.storage_path
                            if not s3_loc:
                                s3_loc = _check_s3_for_backup(backup, db)
                            if s3_loc:
                                backup.storage_path = s3_loc
                            size_bytes = event.get("size_bytes")
                            if size_bytes:
                                backup.size_bytes = size_bytes
                        elif new_status in ("failed", "cleanup_required"):
                            # Store error in tags for notifications
                            backup.tags = backup.tags or {}
                            if not backup.tags.get("error"):
                                backup.tags["error"] = reason

                        logger.info(
                            f"Backup {backup_id} status updated to {new_status}"
                        )

                        # Notification for reconciled failures/successes
                        if new_status in ("failed", "cleanup_required"):
                            await notify_backup_failure(
                                backup=backup,
                                vm_name=vm.name,
                                error=reason,
                                db=db,
                            )
                        elif new_status == "completed":
                            await notify_backup_success(
                                backup=backup,
                                vm_name=vm.name,
                                db=db,
                            )

                        # WebSocket notification
                        await websocket_manager.broadcast(
                            {
                                "type": "backup_reconciled",
                                "backup_id": backup_id,
                                "status": new_status,
                                "reconciled": True,
                            }
                        )
                    else:
                        logger.warning(
                            f"Backup {backup_id} does not belong to agent {agent.hostname}"
                        )
                else:
                    logger.warning(f"Backup {backup_id} not found for reconciliation")

                # Log system event
                _log_system_event(
                    db,
                    "backup_reconciled",
                    "agent",
                    str(agent.id),
                    "backup",
                    backup_id,
                    event,
                )

            elif event_type == "orphan_backup_detected":
                # Agent found a block job that orchestrator doesn't know about
                logger.warning(
                    f"Agent {agent.hostname} detected orphan backup for VM {vm_name}"
                )

                # Log system event for visibility
                _log_system_event(
                    db,
                    "orphan_backup_detected",
                    "agent",
                    str(agent.id),
                    "vm",
                    None,
                    event,
                )

                # WebSocket notification for admin awareness
                await websocket_manager.broadcast(
                    {
                        "type": "orphan_backup_detected",
                        "agent_id": str(agent.id),
                        "agent_name": agent.hostname,
                        "vm_name": vm_name,
                        "progress_percent": event.get("progress_percent", 0),
                    }
                )

            elif event_type == "orphan_systemd_unit_detected":
                # Agent found a systemd unit that orchestrator doesn't know about (v2.10+)
                unit_name = event.get("unit_name", "unknown")
                backup_id = event.get("backup_id")
                logger.warning(
                    f"Agent {agent.hostname} detected orphan systemd unit {unit_name}"
                )

                # Log system event for visibility
                _log_system_event(
                    db,
                    "orphan_systemd_unit_detected",
                    "agent",
                    str(agent.id),
                    "systemd_unit",
                    backup_id,
                    event,
                )

                # WebSocket notification for admin awareness
                await websocket_manager.broadcast(
                    {
                        "type": "orphan_systemd_unit_detected",
                        "agent_id": str(agent.id),
                        "agent_name": agent.hostname,
                        "unit_name": unit_name,
                        "backup_id": backup_id,
                    }
                )

        except Exception as e:
            logger.error(f"Error processing event {event}: {e}")
    return progress_updates


def _log_system_event(
    db: Session,
    event_type: str,
    source: str,
    source_id: str,
    resource_type: str,
    resource_id: str | None,
    details: dict,
):
    """Log a system event to the database.

    System events are generated by agents, schedulers, and the system itself,
    as opposed to ActivityLog which tracks user actions.
    """
    # Unknown IDs from an agent are evidence in the payload, not authoritative
    # links to resources. Keep the event on the authenticated agent's tenant.
    resource_models = {
        "backup": Backup,
        "vm": VM,
        "agent": Agent,
        "schedule": Schedule,
        "user": User,
    }
    model = resource_models.get(resource_type)
    if resource_id and model and db.get(model, resource_id) is None:
        details = {**details, "reported_resource_id": resource_id}
        resource_id = None
    system_event = SystemEvent(
        event_type=event_type,
        source=source,
        source_id=source_id,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    db.add(system_event)


# ============================================================================
# HEALTH MONITORING ENDPOINTS
# ============================================================================


# DEPRECATED: Use /api/v1/health instead. Will be removed in v4.0.
@router.get("/health/agents")
async def get_agent_health_deprecated(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """DEPRECATED: Use /api/v1/health instead. This endpoint will be removed in v4.0."""
    return await _get_agent_health_data(db)


@router.post("/health/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request,
    agent: Agent = Depends(verify_agent_api_key),
    db: Session = Depends(get_db),
):
    """
    Agent heartbeat endpoint - requires agent API key authentication.

    Called by agent every 30 seconds to report it's alive and send metrics.

    Args:
        agent_id: Agent ID from URL path
        request: Request body with metrics
        agent: Authenticated agent (from X-Agent-Key header)
        db: Database session

    Returns:
        dict: Status and timestamp
    """
    # Verify agent ID matches authenticated agent (security check)
    if agent.id != agent_id:
        raise HTTPException(
            status_code=403,
            detail="Agent ID mismatch. Cannot update heartbeat for different agent.",
        )

    # Parse heartbeat data from body
    try:
        heartbeat_data = await request.json()
    except Exception:
        heartbeat_data = {}

    from core.file_backups import bind_file_capabilities, certified_file_fingerprint
    from core.verified_tls import verified_peer

    fingerprint = verified_peer(request.scope)
    trusted_file_observation = False
    if fingerprint:
        enrolled = db.get(Agent, agent.id, populate_existing=True, with_for_update=True)
        if enrolled is None or enrolled.org_id != agent.org_id:
            raise HTTPException(401, "Verified agent enrollment is no longer available")
        agent = enrolled
        trusted_file_observation = fingerprint == certified_file_fingerprint(
            db, agent, datetime.now(timezone.utc)
        )

    progress_updates = []
    agent.last_heartbeat = datetime.utcnow()
    agent.status = heartbeat_data.get("status", "online")
    capabilities = heartbeat_data.get("capabilities")
    reported = (
        capabilities
        if isinstance(capabilities, dict)
        and capabilities.get("provider") in {"kubevirt", "libvirt", "none"}
        else {}
    )
    agent.capabilities = bind_file_capabilities(
        agent.capabilities, reported, trusted=trusted_file_observation
    )
    provider = agent.capabilities.get("provider")
    if provider in {"kubevirt", "libvirt", "none"}:
        agent.platform = {
            "kubevirt": "KubeVirt",
            "libvirt": "KVM/QEMU",
            "none": "Linux",
        }[provider]

    # Store metrics if provided
    if heartbeat_data:
        # Backup storage metrics
        backup_storage_free = heartbeat_data.get("backup_storage_free_bytes")
        backup_storage_total = heartbeat_data.get("backup_storage_total_bytes")
        cpu_cores = heartbeat_data.get("cpu_cores") or 1
        load_avg_15m = heartbeat_data.get("load_average_15m")

        # Calculate load percentage (load_avg / cores * 100)
        load_percent = None
        if load_avg_15m is not None:
            load_percent = (load_avg_15m / cpu_cores) * 100

        agent.metrics = {
            "cpu_usage_percent": heartbeat_data.get("cpu_usage_percent"),
            "memory_usage_percent": heartbeat_data.get("memory_usage_percent"),
            "cpu_cores": cpu_cores,
            "load_average_15m": load_avg_15m,
            "load_percent": load_percent,
            "disk_usage_percent": heartbeat_data.get("disk_usage_percent"),
            "backup_storage_path": heartbeat_data.get("backup_storage_path"),
            "provider": heartbeat_data.get("provider"),
            "backup_method": (
                capabilities.get("backup_method")
                if isinstance(capabilities, dict)
                else None
            ),
            "supports_incremental": (
                capabilities.get("incremental")
                if isinstance(capabilities, dict)
                else None
            ),
            "scope": heartbeat_data.get("scope"),
            "provider_accessible": heartbeat_data.get("provider_accessible"),
            "storage_role": heartbeat_data.get("storage_role"),
            "storage_measurement_error": heartbeat_data.get(
                "storage_measurement_error"
            ),
            "backup_storage_free_bytes": backup_storage_free,
            "backup_storage_total_bytes": backup_storage_total,
            "active_backups": heartbeat_data.get("active_backups", 0),
            "active_restores": heartbeat_data.get("active_restores", 0),
            "libvirt_accessible": heartbeat_data.get("libvirt_accessible"),
            "updated_at": iso_utc(datetime.utcnow()),
        }

        # Get configurable thresholds from settings (with defaults)
        storage_free_gb_threshold = float(
            get_setting(db, "health_storage_free_gb", "10") or 10
        )
        storage_free_percent_threshold = float(
            get_setting(db, "health_storage_free_percent", "10") or 10
        )
        load_percent_threshold = float(
            get_setting(db, "health_load_percent", "80") or 80
        )
        health_issues, health_reasons = assess_agent_health(
            heartbeat_data,
            storage_free_gb_threshold=storage_free_gb_threshold,
            storage_free_percent_threshold=storage_free_percent_threshold,
            load_percent_threshold=load_percent_threshold,
        )

        # Determine health status
        if health_issues:
            agent.metrics["health_status"] = "degraded"
            agent.metrics["health_issues"] = health_issues
            agent.metrics["health_reasons"] = health_reasons
        else:
            agent.metrics["health_status"] = "healthy"
            agent.metrics["health_issues"] = []
            agent.metrics["health_reasons"] = []

        # Update version if provided (allows updating without re-registration)
        if heartbeat_data.get("version"):
            agent.version = heartbeat_data.get("version")

        # Update IP address and port if provided
        if heartbeat_data.get("ip_address"):
            agent.ip_address = heartbeat_data.get("ip_address")
        if heartbeat_data.get("port"):
            agent.port = heartbeat_data.get("port")

        # Process libvirt events (Phase 2: Event-driven architecture)
        events = heartbeat_data.get("events", [])
        if events:
            progress_updates = await _process_agent_events(agent, events, db)

    db.commit()

    # Only announce committed observations, scoped to the authenticated agent.
    # One shared notification budget keeps a slow browser from holding up the
    # agent's heartbeat. Polling can recover every committed snapshot.
    try:
        async with asyncio.timeout(2):
            for observation in progress_updates:
                await websocket_manager.send_scoped(
                    {
                        "type": "backup_progress",
                        "payload": observation,
                        "timestamp": iso_utc(datetime.utcnow()),
                    },
                    agent.org_id,
                )
    except Exception:
        logger.warning("Storage progress notification unavailable")

    # Prometheus: count heartbeat
    prom.agent_heartbeats_total.labels(agent_id=agent_id).inc()

    from core.agent_requests import build_heartbeat_response

    # File and VM dispatch identity comes only from installation custody.
    config = dict(agent.config or {})
    config.pop("file_controller_sha256", None)
    config.pop("vm_controller_sha256", None)
    advertised = agent.capabilities or {}
    identity_fields = []
    if advertised.get("managed_file_sets"):
        identity_fields.append("file_controller_sha256")
    if trusted_file_observation and advertised.get("provider") in {
        "libvirt",
        "kubevirt",
    }:
        identity_fields.append("vm_controller_sha256")
    if identity_fields:
        from core.file_controller_identity import current_file_controller_fingerprint

        try:
            fingerprint = current_file_controller_fingerprint(SettingsService(db))
        except Exception:
            logger.warning("Agent dispatch certificate unavailable")
            fingerprint = ""
        for field in identity_fields:
            config[field] = fingerprint
    return build_heartbeat_response(
        agent_id=agent.id,
        timestamp=iso_utc(agent.last_heartbeat),
        config=config,
    )


@router.get("/agents/{agent_id}/pending-jobs")
def get_agent_pending_jobs(
    agent_id: str,
    agent: Agent = Depends(verify_agent_api_key),
    db: Session = Depends(get_db),
):
    """
    Get backup jobs orchestrator believes are running on this agent.

    Used by agent on startup to reconcile state - determine which backups
    the orchestrator thinks are running so agent can verify reality.

    Returns:
        dict: backups list with id, vm_name, storage_path, started_at
    """
    # Verify agent ID matches authenticated agent
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    # Get VMs for this agent
    vms = db.query(VM).filter(VM.agent_id == agent_id).all()
    vm_ids = [vm.id for vm in vms]
    vm_names = {vm.id: vm.name for vm in vms}

    if not vm_ids:
        return {"backups": []}

    # Get running/pending/uploading backups for these VMs
    running_backups = (
        db.query(Backup)
        .filter(
            Backup.vm_id.in_(vm_ids),
            Backup.status.in_(["running", "pending", "uploading", "upload_failed"]),
        )
        .all()
    )

    return {
        "backups": [
            {
                "id": str(b.id),
                "vm_name": vm_names.get(b.vm_id),
                "storage_path": b.storage_path,
                "started_at": iso_utc(b.created_at),
                "status": b.status,
            }
            for b in running_backups
        ]
    }


# DEPRECATED: Use /api/v1/health instead. Will be removed in v4.0.
@router.get("/health/backups")
async def get_backup_health_deprecated(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """DEPRECATED: Use /api/v1/health instead. This endpoint will be removed in v4.0."""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Total backups
    total_backups = db.query(func.count(Backup.id)).scalar()

    # Backups by status
    completed_count = (
        db.query(func.count(Backup.id)).filter(Backup.status == "completed").scalar()
    )
    failed_count = (
        db.query(func.count(Backup.id)).filter(Backup.status == "failed").scalar()
    )
    running_count = (
        db.query(func.count(Backup.id)).filter(Backup.status == "running").scalar()
    )
    pending_count = (
        db.query(func.count(Backup.id)).filter(Backup.status == "pending").scalar()
    )

    # Recent failures (last 24h)
    recent_failures = (
        db.query(func.count(Backup.id))
        .filter(Backup.status == "failed", Backup.created_at >= last_24h)
        .scalar()
    )

    # Recent completions (last 24h)
    recent_completions = (
        db.query(func.count(Backup.id))
        .filter(Backup.status == "completed", Backup.created_at >= last_24h)
        .scalar()
    )

    # Old backups (past retention period)
    old_backups = (
        db.query(Backup)
        .filter(Backup.completed_at.isnot(None), Backup.status == "completed")
        .all()
    )

    old_backup_count = 0
    for backup in old_backups:
        if backup.completed_at:
            days_old = (now - backup.completed_at).days
            if days_old > backup.retention_days:
                old_backup_count += 1

    # Success rate (last 7 days)
    backups_7d = (
        db.query(func.count(Backup.id))
        .filter(
            Backup.created_at >= last_7d, Backup.status.in_(["completed", "failed"])
        )
        .scalar()
    )

    completed_7d = (
        db.query(func.count(Backup.id))
        .filter(Backup.created_at >= last_7d, Backup.status == "completed")
        .scalar()
    )

    success_rate_7d = round(
        (completed_7d / backups_7d * 100) if backups_7d > 0 else 100, 2
    )

    # Average backup size
    avg_size = (
        db.query(func.avg(Backup.size_bytes))
        .filter(Backup.size_bytes.isnot(None))
        .scalar()
        or 0
    )

    # Total storage used
    total_storage = (
        db.query(func.sum(Backup.size_bytes))
        .filter(Backup.size_bytes.isnot(None), Backup.status == "completed")
        .scalar()
        or 0
    )

    # Get recent failures for details
    recent_failed_backups = (
        db.query(Backup)
        .filter(Backup.status == "failed", Backup.created_at >= last_24h)
        .order_by(Backup.created_at.desc())
        .limit(10)
        .all()
    )

    failed_details = [
        {
            "id": b.id,
            "vm_id": b.vm_id,
            "vm_name": b.vm.name if b.vm else "Unknown",
            "created_at": iso_utc(b.created_at),
            "error": "Backup failed",  # Would contain actual error in production
        }
        for b in recent_failed_backups
    ]

    return {
        "summary": {
            "total_backups": total_backups,
            "completed": completed_count,
            "failed": failed_count,
            "running": running_count,
            "pending": pending_count,
        },
        "health_metrics": {
            "recent_failures_24h": recent_failures,
            "recent_completions_24h": recent_completions,
            "old_backups_past_retention": old_backup_count,
            "success_rate_7d": success_rate_7d,
            "avg_backup_size_bytes": int(avg_size),
            "total_storage_bytes": int(total_storage),
        },
        "recent_failures": failed_details,
        "health_status": (
            "healthy" if recent_failures < 5 and success_rate_7d > 80 else "warning"
        ),
    }


# DEPRECATED: Use /api/v1/health instead. Will be removed in v4.0.
@router.get("/health/system")
async def get_system_health_deprecated(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """DEPRECATED: Use /api/v1/health instead. This endpoint will be removed in v4.0."""
    now = datetime.utcnow()

    # Get counts of all entities
    total_agents = db.query(func.count(Agent.id)).scalar()
    total_vms = db.query(func.count(VM.id)).scalar()
    total_backups = db.query(func.count(Backup.id)).scalar()
    total_schedules = db.query(func.count(Schedule.id)).scalar()
    total_users = db.query(func.count(User.id)).scalar()

    # Active schedules
    active_schedules = (
        db.query(func.count(Schedule.id)).filter(Schedule.enabled.is_(True)).scalar()
    )

    # Running backups
    running_backups = (
        db.query(func.count(Backup.id)).filter(Backup.status == "running").scalar()
    )

    # Agent health
    online_agents = 0
    for agent in db.query(Agent).all():
        time_since_heartbeat = now - (agent.last_heartbeat or agent.created_at)
        if time_since_heartbeat < timedelta(minutes=5):
            online_agents += 1

    # Recent activity (last hour)
    last_hour = now - timedelta(hours=1)
    recent_activity = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.created_at >= last_hour)
        .scalar()
    )

    # Storage usage (mocked for MVP)
    total_storage = (
        db.query(func.sum(Backup.size_bytes))
        .filter(Backup.size_bytes.isnot(None), Backup.status == "completed")
        .scalar()
        or 0
    )

    # Determine overall health
    agent_health_ok = (
        (online_agents / total_agents) >= 0.8 if total_agents > 0 else True
    )

    failed_backups_24h = (
        db.query(func.count(Backup.id))
        .filter(
            Backup.status == "failed", Backup.created_at >= (now - timedelta(hours=24))
        )
        .scalar()
    )

    backup_health_ok = failed_backups_24h < 5

    overall_health = "healthy" if agent_health_ok and backup_health_ok else "warning"

    return {
        "status": overall_health,
        "timestamp": iso_utc(now),
        "metrics": {
            "agents": {
                "total": total_agents,
                "online": online_agents,
                "offline": total_agents - online_agents,
            },
            "vms": {"total": total_vms},
            "backups": {"total": total_backups, "running": running_backups},
            "schedules": {
                "total": total_schedules,
                "active": active_schedules,
                "inactive": total_schedules - active_schedules,
            },
            "users": {"total": total_users},
            "storage": {
                "total_bytes": int(total_storage),
                "total_gb": round(total_storage / (1024**3), 2),
            },
        },
        "activity": {"recent_actions_1h": recent_activity},
    }


@router.get("/health")
async def get_health(
    include: (
        str | None
    ) = None,  # Comma-separated: "database,agents,storage,s3,api,metrics,services" or None for all
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Consolidated system health endpoint.

    Returns comprehensive health data for all system components. Use the `include`
    parameter to request specific sections only.

    Args:
        include: Comma-separated list of sections to include. Options:
                 database, agents, storage, s3, api, metrics, services.
                 If not specified, all sections are included.

    Returns:
        Health data for requested sections.
    """
    import time

    now = datetime.utcnow()

    # Database health
    db_response_time = 0
    db_connections = 0
    db_max_connections = 0
    try:
        db_start = time.time()
        # Simple ping query for response time
        db.execute(text("SELECT 1"))
        db_response_time = int((time.time() - db_start) * 1000)
        db_status = "healthy"
        # Get actual connection count from PostgreSQL
        conn_result = db.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
            )
        )
        db_connections = conn_result.scalar() or 0
        # Get max connections setting
        max_result = db.execute(text("SHOW max_connections"))
        db_max_connections = int(max_result.scalar() or 100)
    except Exception:
        db_status = "unhealthy"
        db_connections = 0
        db_max_connections = 0

    # Agent health - count online, healthy, degraded
    total_agents = db.query(Agent).count()
    online_agents = 0
    healthy_agents = 0
    degraded_agents = []  # List of agent names with issues
    for agent in db.query(Agent).all():
        time_since_heartbeat = now - (agent.last_heartbeat or agent.created_at)
        if time_since_heartbeat < timedelta(minutes=5):
            online_agents += 1
            # Check agent health status from metrics
            metrics = agent.metrics or {}
            health_status = metrics.get("health_status", "unknown")
            if health_status == "healthy":
                healthy_agents += 1
            elif health_status == "degraded":
                issues = metrics.get("health_issues", [])
                display_name = agent.display_name or agent.hostname
                degraded_agents.append({"name": display_name, "issues": issues})

    # Storage health - show backup storage used from database
    # Note: Actual storage is on agents (KVM hosts), backend tracks usage
    storage_status = "healthy"
    storage_used = (
        db.query(func.sum(Backup.size_bytes))
        .filter(Backup.size_bytes.isnot(None), Backup.status == "completed")
        .scalar()
        or 0
    )
    backup_count = db.query(Backup).filter(Backup.status == "completed").count()

    # Current inventory, matching the dashboard rather than retained VM history.
    total_vms = (
        db.query(VM)
        .filter(VM.org_id == current_user.org_id, VM.inventory_present.is_(True))
        .count()
    )

    # Total backups
    total_backups = db.query(Backup).count()

    # Failed jobs in last 24h
    failed_jobs_24h = (
        db.query(Backup)
        .filter(
            Backup.status == "failed", Backup.created_at >= (now - timedelta(hours=24))
        )
        .count()
    )

    # Active backups (running)
    active_backups = db.query(Backup).filter(Backup.status == "running").count()

    # Determine agents status
    if online_agents == 0 and total_agents > 0:
        agents_status = "offline"
    elif degraded_agents or online_agents < total_agents:
        agents_status = "degraded"
    else:
        agents_status = "healthy"

    # S3 health check
    s3_status = "not_configured"
    s3_endpoint = None
    s3_bucket = None
    s3_error = None
    s3_last_check = None
    s3_configured = False

    try:
        svc = SettingsService(db)
        s3_config = svc.get_s3_config()

        if s3_config and s3_config.get("bucket"):
            s3_configured = True
            s3_endpoint = s3_config.get("endpoint") or "AWS S3"
            s3_bucket = s3_config.get("bucket")
            s3_last_check = iso_utc(now)

            # If we have credentials, test connection
            access_key = s3_config.get("access_key")
            secret_key = s3_config.get("secret_key")

            if access_key and secret_key:
                try:
                    import boto3
                    from botocore.config import Config

                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=s3_config.get("endpoint") or None,
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name=s3_config.get("region", "us-east-1"),
                        config=Config(
                            connect_timeout=5,
                            read_timeout=5,
                            retries={"max_attempts": 1},
                        ),
                    )
                    # Quick head_bucket check
                    s3_client.head_bucket(Bucket=s3_bucket)
                    s3_status = "healthy"
                except Exception as e:
                    s3_status = "unhealthy"
                    s3_error = str(e)[:100]
            else:
                s3_status = "degraded"
                s3_error = "Credentials not configured"
    except Exception as e:
        logger.debug(f"S3 health check error: {e}")

    # Overall status
    overall_status = "healthy"
    if db_status != "healthy":
        overall_status = "unhealthy"
    elif agents_status == "degraded" or agents_status == "offline":
        overall_status = "degraded"

    # Build services list
    services_list = [
        {"name": "Database", "description": "PostgreSQL", "status": db_status},
        {
            "name": "Agents",
            "description": f"{healthy_agents}/{online_agents} healthy, {online_agents}/{total_agents} online",
            "status": agents_status,
        },
        {"name": "Storage", "description": "Backup storage", "status": storage_status},
    ]
    if s3_configured:
        services_list.append(
            {"name": "S3 Storage", "description": s3_bucket, "status": s3_status}
        )

    # Build full response
    full_response = {
        "status": overall_status,
        "timestamp": iso_utc(now),
        "database": {
            "status": db_status,
            "response_time": db_response_time,
            "connections": db_connections,
            "max_connections": db_max_connections,
        },
        "agents": {
            "status": agents_status,
            "total": total_agents,
            "online": online_agents,
            "healthy": healthy_agents,
            "degraded": degraded_agents,  # List of {name, issues}
        },
        "storage": {
            "status": storage_status,
            "used_space": storage_used,
            "backup_count": backup_count,
            "note": "Storage managed by agents",
        },
        "s3": {
            "configured": s3_configured,
            "status": s3_status,
            "endpoint": s3_endpoint,
            "bucket": s3_bucket,
            "last_check": s3_last_check,
            "error": s3_error,
        },
        "api": {"status": "healthy", "version": __version__},
        "metrics": {
            "active_backups": active_backups,
            "pending_jobs": 0,
            "failed_jobs_24h": failed_jobs_24h,
            "online_agents": online_agents,
            "total_vms": total_vms,
            "total_backups": total_backups,
        },
        "services": services_list,
    }

    # Filter response if include parameter is specified
    if include:
        sections = [s.strip().lower() for s in include.split(",")]
        filtered_response = {
            "status": full_response["status"],
            "timestamp": full_response["timestamp"],
        }
        for section in sections:
            if section in full_response:
                filtered_response[section] = full_response[section]
        return filtered_response

    return full_response


# Backwards compatibility alias - will be removed in v4.0
@router.get("/health/detailed")
async def get_detailed_health_deprecated(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """DEPRECATED: Use /api/v1/health instead. This endpoint will be removed in v4.0."""
    return await get_health(include=None, current_user=current_user, db=db)
