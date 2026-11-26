"""
Advanced search and saved searches endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import SavedSearch, Backup, VM
from deps import get_current_user, log_activity, iso_utc

router = APIRouter(prefix="/api/v1", tags=["search"])


@router.post("/search")
async def global_search(
    search_data: dict,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cross-entity search for VMs and backups by name."""
    query = (search_data.get("query") or "").strip()
    filters = search_data.get("filters", {})
    if not query:
        return {"vms": [], "backups": []}

    pattern = f"%{query}%"
    results = {"vms": [], "backups": []}

    if filters.get("vms", True):
        vms = db.query(VM).filter(VM.name.ilike(pattern)).limit(10).all()
        results["vms"] = [
            {
                "id": v.id,
                "name": v.name,
                "state": v.state,
                "hostname": v.agent.hostname if v.agent else None,
            }
            for v in vms
        ]

    if filters.get("backups", True):
        backups = (
            db.query(Backup)
            .join(VM, Backup.vm_id == VM.id)
            .filter(VM.name.ilike(pattern))
            .order_by(Backup.created_at.desc())
            .limit(10)
            .all()
        )
        results["backups"] = [
            {
                "id": b.id,
                "vm_name": b.vm.name if b.vm else "Unknown",
                "status": b.status,
                "created_at": iso_utc(b.created_at),
            }
            for b in backups
        ]

    return results


@router.post("/saved-searches")
async def create_saved_search(
    search_data: dict,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a saved search"""
    search = SavedSearch(
        name=search_data.get("name"),
        description=search_data.get("description"),
        search_type=search_data.get("search_type", "backup"),
        filters=search_data.get("filters", {}),
        created_by=current_user.id,
        is_public=search_data.get("is_public", False),
    )
    db.add(search)
    db.commit()
    db.refresh(search)

    log_activity(
        db,
        current_user,
        action="saved_search_created",
        resource_type="saved_search",
        resource_id=search.id,
        details={"name": search.name},
    )

    return {
        "id": search.id,
        "name": search.name,
        "search_type": search.search_type,
        "filters": search.filters,
        "is_public": search.is_public,
        "created_at": iso_utc(search.created_at),
    }


@router.get("/saved-searches")
async def list_saved_searches(
    search_type: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List saved searches"""
    query = db.query(SavedSearch).filter(
        (SavedSearch.created_by == current_user.id) | (SavedSearch.is_public.is_(True))
    )
    if search_type:
        query = query.filter(SavedSearch.search_type == search_type)

    searches = query.order_by(SavedSearch.created_at.desc()).all()

    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "search_type": s.search_type,
            "filters": s.filters,
            "is_public": s.is_public,
            "created_at": iso_utc(s.created_at),
            "is_owner": s.created_by == current_user.id,
        }
        for s in searches
    ]


@router.get("/saved-searches/{search_id}")
async def get_saved_search(
    search_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get saved search details"""
    search = db.query(SavedSearch).filter(SavedSearch.id == search_id).first()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    if not search.is_public and search.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "id": search.id,
        "name": search.name,
        "description": search.description,
        "search_type": search.search_type,
        "filters": search.filters,
        "is_public": search.is_public,
        "created_at": iso_utc(search.created_at),
    }


@router.delete("/saved-searches/{search_id}")
async def delete_saved_search(
    search_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a saved search"""
    search = db.query(SavedSearch).filter(SavedSearch.id == search_id).first()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    if search.created_by != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    db.delete(search)
    db.commit()

    log_activity(
        db,
        current_user,
        action="saved_search_deleted",
        resource_type="saved_search",
        resource_id=search_id,
        details={"name": search.name},
    )

    return {"message": "Saved search deleted"}


@router.post("/saved-searches/{search_id}/execute")
async def execute_saved_search(
    search_id: str,
    skip: int = 0,
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Execute a saved search and return results"""
    search = db.query(SavedSearch).filter(SavedSearch.id == search_id).first()
    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    if not search.is_public and search.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    filters = search.filters or {}

    # Build query based on search type
    if search.search_type == "backup":
        query = db.query(Backup)
        if filters.get("status"):
            query = query.filter(Backup.status == filters["status"])
        if filters.get("vm_id"):
            query = query.filter(Backup.vm_id == filters["vm_id"])

        total = query.count()
        results = query.offset(skip).limit(limit).all()

        items = [
            {
                "id": b.id,
                "vm_name": b.vm.name if b.vm else "Unknown",
                "status": b.status,
                "created_at": iso_utc(b.created_at),
            }
            for b in results
        ]
    elif search.search_type == "vm":
        query = db.query(VM)
        if filters.get("state"):
            query = query.filter(VM.state == filters["state"])

        total = query.count()
        results = query.offset(skip).limit(limit).all()

        items = [
            {
                "id": v.id,
                "name": v.name,
                "state": v.state,
                "agent_hostname": v.agent.hostname if v.agent else None,
            }
            for v in results
        ]
    else:
        return {"items": [], "total": 0, "skip": skip, "limit": limit}

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "search_name": search.name,
    }
