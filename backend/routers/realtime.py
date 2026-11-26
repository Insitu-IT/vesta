"""
Real-time updates via WebSocket and polling fallback.
"""

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    Depends,
    Query,
    HTTPException,
)
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel
import os
import logging
from functools import wraps

from core.websocket import websocket_manager
from core.realtime import realtime
from deps import get_current_user
from models import User
from database import SessionLocal
from core.tenant_context import TenantContext, commercial_mode, extract_org_from_jwt

logger = logging.getLogger(__name__)

router = APIRouter(tags=["realtime"])


def owned_socket_route(handler):
    @wraps(handler)
    async def call(*args, **kwargs):
        with websocket_manager.dispatch_lifetime.admission():
            return await handler(*args, **kwargs)

    return call


async def connect_authenticated(websocket, backup_id=None):
    """WebSockets do not run HTTP middleware; authenticate before accepting."""
    from models import Backup
    from jwt import InvalidTokenError

    protocols = websocket.headers.get("sec-websocket-protocol", "").split(",")
    credentials = [p.strip()[7:] for p in protocols if p.strip().startswith("bearer.")]
    token = credentials[0] if len(credentials) == 1 else ""
    if websocket.query_params.get("token"):
        token = ""  # Credential-bearing URLs are not a supported 6.0 transport.
    try:
        org = extract_org_from_jwt(token) if commercial_mode() else None
        with TenantContext(org), SessionLocal() as db:
            user = get_current_user(token, db)
            if backup_id is not None and db.get(Backup, backup_id) is None:
                raise HTTPException(404, "Backup unavailable")
            metadata = {
                "org_id": user.org_id,
                "role": user.role,
                "backup_id": backup_id,
            }
            user_id = user.id
        return await websocket_manager.connect(
            websocket,
            user_id,
            metadata,
            subprotocol="vnbui" if "vnbui" in [p.strip() for p in protocols] else None,
        )
    except (HTTPException, InvalidTokenError, ValueError):
        await websocket.close(code=1008, reason="Invalid credentials or subscription")
        return False


@router.get("/api/v1/config/realtime")
async def get_realtime_config(current_user: User = Depends(get_current_user)):
    """Get real-time configuration for the client."""
    config = {
        "enableWebSocket": True,
        "enablePolling": True,
        "pollingInterval": 5000,
        "wsReconnectDelay": 5000,
        "wsMaxReconnectAttempts": 3,
    }

    if os.getenv("DISABLE_WEBSOCKET", "false").lower() == "true":
        config["enableWebSocket"] = False

    if current_user.role == "viewer":
        config["pollingInterval"] = 10000

    return config


@router.websocket("/ws")
@owned_socket_route
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time updates.

    Clients connect here to receive live updates about:
    - Backup progress
    - Backup completion/failure
    - Agent status changes
    - VM lifecycle events

    Authentication uses a bearer subprotocol offer, never a credential-bearing URL.
    """
    if not await connect_authenticated(websocket):
        return
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()

            # Handle ping/pong for connection health
            if data == "ping":
                await websocket_manager.send_socket(websocket, text="pong")
            else:
                # Echo back or handle other messages
                await websocket_manager.send_socket(
                    websocket, message={"type": "ack", "message": data}
                )

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception:
        logger.error("WebSocket session failed")
    finally:
        await websocket_manager.disconnect(websocket)


@router.websocket("/ws/backups/{backup_id}")
@owned_socket_route
async def backup_progress_websocket(websocket: WebSocket, backup_id: str):
    """
    WebSocket endpoint for specific backup progress updates.

    Provides real-time progress updates for a specific backup job.
    """
    if not await connect_authenticated(websocket, backup_id):
        return
    try:
        # Send initial connection confirmation
        await websocket_manager.send_socket(
            websocket,
            message={
                "type": "connected",
                "backup_id": backup_id,
                "message": f"Subscribed to backup {backup_id} updates",
            },
        )

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket_manager.send_socket(websocket, text="pong")

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.error("Backup WebSocket session failed")
    finally:
        await websocket_manager.disconnect(websocket)


class LegacyRealtimeEvent(BaseModel):
    type: str
    payload: Dict[str, Any]
    timestamp: datetime


class CursorRealtimeEvent(LegacyRealtimeEvent):
    sequence: int


class RealtimePage(BaseModel):
    items: List[CursorRealtimeEvent]
    next_cursor: str
    has_more: bool
    reset_required: bool
    reset_reason: Optional[
        Literal[
            "initial",
            "process_changed",
            "scope_changed",
            "cursor_expired",
            "history_lost",
        ]
    ]
    retention_seconds: Literal[300]
    delivery: Literal["best_effort"]


class RealtimeErrorDetail(BaseModel):
    code: Literal[
        "realtime_contract_unsupported",
        "realtime_parameters_conflict",
        "realtime_cursor_invalid",
        "realtime_cursor_contract_required",
        "realtime_timestamp_invalid",
    ]
    message: str


class RealtimeErrorResponse(BaseModel):
    detail: RealtimeErrorDetail


@router.get(
    "/api/v1/updates",
    response_model=Union[RealtimePage, List[LegacyRealtimeEvent]],
    responses={
        400: {
            "model": RealtimeErrorResponse,
            "description": "Stable coded contract, cursor or timestamp refusal; no cursor content is echoed.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_cursor": {
                            "value": {
                                "detail": {
                                    "code": "realtime_cursor_invalid",
                                    "message": "Invalid realtime cursor",
                                }
                            }
                        },
                        "unsupported_contract": {
                            "value": {
                                "detail": {
                                    "code": "realtime_contract_unsupported",
                                    "message": "Unsupported realtime contract",
                                }
                            }
                        },
                    }
                }
            },
        }
    },
)
async def get_updates(
    since: Optional[str] = Query(
        None,
        description="Deprecated aware ISO8601 timestamp; oldest-first limited array, no completeness guarantee",
    ),
    limit: int = Query(100, ge=1, le=500),
    contract: Optional[int] = Query(None, description="Set 2 for the cursor envelope"),
    cursor: Optional[str] = Query(
        None, max_length=2048, description="Opaque continuation from contract=2"
    ),
    current_user: User = Depends(get_current_user),
):
    """Best-effort process-local invalidations, not lossless history.

    contract=2 returns ordered items and an opaque continuation bound to this
    process and authenticated organization/user/role. History retains at most
    1000 events for 300 seconds. Initial/missing, expired, overflowed, restarted
    or different-worker/scope cursors explicitly require authoritative full-state
    resynchronization. Capture next_cursor, read snapshots, then continue from
    that cursor. Socket messages are hints; use this feed for continuation.

    The legacy since array is deprecated. It returns the oldest matching limit
    with strict greater-than timestamps; ties and limits cannot prove completeness.
    since requires Z or an explicit UTC offset; malformed/naive values return 400.
    """
    if contract is not None and contract != 2:
        raise HTTPException(
            400,
            detail={
                "code": "realtime_contract_unsupported",
                "message": "Unsupported realtime contract",
            },
        )
    if contract == 2:
        if since is not None:
            raise HTTPException(
                400,
                detail={
                    "code": "realtime_parameters_conflict",
                    "message": "since cannot be combined with contract=2",
                },
            )
        try:
            return realtime.get_event_page(
                cursor=cursor,
                user_id=current_user.id,
                role=current_user.role,
                limit=limit,
            )
        except ValueError:
            raise HTTPException(
                400,
                detail={
                    "code": "realtime_cursor_invalid",
                    "message": "Invalid realtime cursor",
                },
            ) from None
    if cursor is not None:
        raise HTTPException(
            400,
            detail={
                "code": "realtime_cursor_contract_required",
                "message": "cursor requires contract=2",
            },
        )
    timestamp = None
    if since is not None:
        try:
            timestamp = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError()
            timestamp = timestamp.astimezone(timezone.utc)
        except ValueError:
            raise HTTPException(
                400,
                detail={
                    "code": "realtime_timestamp_invalid",
                    "message": "since requires an ISO8601 timestamp with a UTC offset",
                },
            ) from None
    return realtime.get_events_since(
        timestamp=timestamp,
        user_id=current_user.id,
        limit=limit,
        role=current_user.role,
    )
