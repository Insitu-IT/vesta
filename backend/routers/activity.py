"""
Activity logs endpoints: unified activity feed combining user actions and system events.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, Annotated
import logging

from database import get_db
from models import User, ActivityLog, SystemEvent, Agent
from deps import get_current_user, iso_utc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["activity"])


@router.get("/activity")
async def get_activity(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    source: Optional[str] = None,  # "user", "system", or None for both
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Unified activity feed combining user actions and system events.

    Merges ActivityLog (user actions) and SystemEvent (agent/system events)
    into a single chronological feed.

    Args:
        skip: Number of records to skip
        limit: Max records to return (max 100)
        source: Filter by source - "user" for ActivityLog, "system" for SystemEvent, None for both
        action: Filter by action type (e.g., "backup_created") - applies to user events only
        resource_type: Filter by resource type (e.g., "backup", "vm_group")

    Returns:
        Combined activity list sorted by timestamp
    """
    limit = min(limit, 100)
    results = []
    total = 0
    # Each source needs at most this prefix to resolve the merged page.
    prefix = skip + limit

    # Get user activity logs
    if source in (None, "user", "all"):
        query = db.query(ActivityLog)
        if action:
            query = query.filter(ActivityLog.action == action)
        if resource_type:
            query = query.filter(ActivityLog.resource_type == resource_type)

        total += query.count()
        user_logs = (
            query.order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc())
            .limit(prefix)
            .all()
        )

        for log in user_logs:
            results.append(
                {
                    "id": log.id,
                    "source": "user",
                    "source_name": log.user.username if log.user else "Unknown",
                    "event_type": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "details": log.details or {},
                    "created_at": iso_utc(log.created_at),
                }
            )

    # Get system events
    if source in (None, "system", "all"):
        query = db.query(SystemEvent)
        if resource_type:
            query = query.filter(SystemEvent.resource_type == resource_type)

        total += query.count()
        system_events = (
            query.order_by(SystemEvent.created_at.desc(), SystemEvent.id.desc())
            .limit(prefix)
            .all()
        )

        for event in system_events:
            # Get source name (agent hostname, schedule name, etc.)
            source_name = "System"
            if event.source == "agent" and event.source_id:
                agent = db.query(Agent).filter(Agent.id == event.source_id).first()
                if agent:
                    source_name = agent.get_display_name()

            results.append(
                {
                    "id": event.id,
                    "source": "system",
                    "source_name": source_name,
                    "event_type": event.event_type,
                    "attribution": event.attribution,
                    "org_id": event.org_id,
                    "resource_type": event.resource_type,
                    "resource_id": event.resource_id,
                    "details": event.details or {},
                    "created_at": iso_utc(event.created_at),
                }
            )

    # Sort by timestamp (newest first) and apply pagination
    results.sort(
        key=lambda x: (x["created_at"] or "", x["source"], x["id"]), reverse=True
    )
    paginated = results[skip : skip + limit]

    return {
        "activities": paginated,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": total > skip + limit,
    }


# Backwards compatibility alias - will be removed in v4.0
@router.get("/activity/unified")
async def get_unified_activity_deprecated(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, description="Clamped to 100 per page")] = 50,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """DEPRECATED: Use /api/v1/activity instead. This endpoint will be removed in v4.0."""
    return await get_activity(
        skip=skip,
        limit=limit,
        source=source,
        action=None,
        resource_type=None,
        db=db,
        current_user=current_user,
    )
