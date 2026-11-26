"""
VM Groups endpoints: list, create, update, delete, manage membership, and dynamic groups.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
import logging

from database import get_db
from models import VMGroup, VM, User
from deps import get_current_user, get_operator_or_admin, iso_utc
from schemas import VMGroupCreate, VMGroupUpdate, VMGroupAddVMs
from core.group_rules import resolve_group_members, validate_rules, build_rule_query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["groups"])


def _serialize_group_summary(group, vm_count=None):
    """Serialize group for list view."""
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "tags": group.tags or [],
        "group_type": group.group_type or "static",
        "vm_count": vm_count if vm_count is not None else len(group.vms),
        "created_at": iso_utc(group.created_at),
    }


@router.get("/groups")
async def list_groups(
    skip: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    group_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all VM groups with pagination"""
    limit = min(limit, 100)

    query = db.query(VMGroup)

    if search:
        query = query.filter(VMGroup.name.ilike(f"%{search}%"))
    if group_type:
        query = query.filter(VMGroup.group_type == group_type)

    total = query.count()
    groups = query.order_by(VMGroup.name).offset(skip).limit(limit).all()

    items = []
    for group in groups:
        if group.group_type in ("dynamic", "hybrid") and group.rules:
            vm_count = len(resolve_group_members(db, group))
        else:
            vm_count = len(group.vms)
        items.append(_serialize_group_summary(group, vm_count))

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@router.post("/groups")
async def create_group(
    group_data: VMGroupCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Create a new VM group (operator or admin only)"""
    existing = db.query(VMGroup).filter(VMGroup.name == group_data.name).first()
    if existing:
        raise HTTPException(
            status_code=409, detail=f"Group '{group_data.name}' already exists"
        )

    # Validate group type
    if group_data.group_type not in ("static", "dynamic", "hybrid"):
        raise HTTPException(
            status_code=400,
            detail="group_type must be 'static', 'dynamic', or 'hybrid'",
        )

    # Validate rules if provided
    if group_data.rules:
        errors = validate_rules(group_data.rules)
        if errors:
            raise HTTPException(
                status_code=400, detail=f"Invalid rules: {'; '.join(errors)}"
            )

    if group_data.rules_match not in ("all", "any"):
        raise HTTPException(
            status_code=400, detail="rules_match must be 'all' or 'any'"
        )

    group = VMGroup(
        name=group_data.name,
        description=group_data.description,
        tags=group_data.tags or [],
        group_type=group_data.group_type or "static",
        rules=group_data.rules,
        rules_match=group_data.rules_match or "all",
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    logger.info(
        f"User {current_user.username} created {group.group_type} group '{group.name}' (id={group.id})"
    )

    return _serialize_group_summary(group, vm_count=0)


@router.get("/groups/{group_id}")
async def get_group(
    group_id: str,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get group details with paginated VM list"""
    group = db.query(VMGroup).filter(VMGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    limit = min(limit, 100)

    # Resolve VMs (dynamic or static)
    all_vms = resolve_group_members(db, group)
    total_vms = len(all_vms)
    paged_vms = all_vms[skip : skip + limit]

    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "tags": group.tags or [],
        "group_type": group.group_type or "static",
        "rules": group.rules,
        "rules_match": group.rules_match or "all",
        "created_at": iso_utc(group.created_at),
        "vms": {
            "items": [
                {
                    "id": vm.id,
                    "name": vm.name,
                    "state": vm.state,
                    "agent_hostname": vm.agent.hostname,
                }
                for vm in paged_vms
            ],
            "total": total_vms,
            "skip": skip,
            "limit": limit,
            "has_more": (skip + limit) < total_vms,
        },
    }


@router.put("/groups/{group_id}")
async def update_group(
    group_id: str,
    group_data: VMGroupUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Update group name, description, tags, type, and rules (operator or admin only)"""
    group = db.query(VMGroup).filter(VMGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group_data.name and group_data.name != group.name:
        existing = db.query(VMGroup).filter(VMGroup.name == group_data.name).first()
        if existing:
            raise HTTPException(
                status_code=409, detail=f"Group '{group_data.name}' already exists"
            )
        group.name = group_data.name

    if group_data.description is not None:
        group.description = group_data.description

    if group_data.tags is not None:
        group.tags = group_data.tags

    if group_data.group_type is not None:
        if group_data.group_type not in ("static", "dynamic", "hybrid"):
            raise HTTPException(
                status_code=400,
                detail="group_type must be 'static', 'dynamic', or 'hybrid'",
            )
        group.group_type = group_data.group_type

    if group_data.rules is not None:
        errors = validate_rules(group_data.rules)
        if errors:
            raise HTTPException(
                status_code=400, detail=f"Invalid rules: {'; '.join(errors)}"
            )
        group.rules = group_data.rules

    if group_data.rules_match is not None:
        if group_data.rules_match not in ("all", "any"):
            raise HTTPException(
                status_code=400, detail="rules_match must be 'all' or 'any'"
            )
        group.rules_match = group_data.rules_match

    db.commit()
    db.refresh(group)

    logger.info(
        f"User {current_user.username} updated group '{group.name}' (id={group.id})"
    )

    vm_count = (
        len(resolve_group_members(db, group))
        if group.group_type != "static"
        else len(group.vms)
    )
    return _serialize_group_summary(group, vm_count)


@router.delete("/groups/{group_id}")
async def delete_group(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Delete a VM group (operator or admin only)"""
    group = db.query(VMGroup).filter(VMGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    group_name = group.name
    db.delete(group)
    db.commit()

    logger.info(
        f"User {current_user.username} deleted group '{group_name}' (id={group_id})"
    )

    return {"message": f"Group '{group_name}' deleted", "deleted_id": group_id}


@router.post("/groups/{group_id}/vms")
async def add_vms_to_group(
    group_id: str,
    vm_data: VMGroupAddVMs,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Add VMs to a group (operator or admin only). Only for static/hybrid groups."""
    group = db.query(VMGroup).filter(VMGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.group_type == "dynamic":
        raise HTTPException(
            status_code=400,
            detail="Cannot manually add VMs to a dynamic group. Use rules instead.",
        )

    added_vms = []
    already_in_group = []
    not_found = []

    for vm_id in vm_data.vm_ids:
        vm = db.query(VM).filter(VM.id == vm_id).first()
        if not vm:
            not_found.append(vm_id)
            continue

        if vm in group.vms:
            already_in_group.append(vm.name)
            continue

        group.vms.append(vm)
        added_vms.append(vm.name)

    db.commit()

    if added_vms:
        logger.info(
            f"User {current_user.username} added {len(added_vms)} VMs to group '{group.name}'"
        )

    return {
        "group_id": group_id,
        "group_name": group.name,
        "added": added_vms,
        "already_in_group": already_in_group,
        "not_found": not_found,
        "total_vms": len(resolve_group_members(db, group)),
    }


@router.delete("/groups/{group_id}/vms/{vm_id}")
async def remove_vm_from_group(
    group_id: str,
    vm_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_operator_or_admin),
):
    """Remove a VM from a group (operator or admin only)"""
    group = db.query(VMGroup).filter(VMGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.group_type == "dynamic":
        raise HTTPException(
            status_code=400,
            detail="Cannot manually remove VMs from a dynamic group. Modify rules instead.",
        )

    vm = db.query(VM).filter(VM.id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    if vm not in group.vms:
        raise HTTPException(
            status_code=404, detail=f"VM '{vm.name}' is not in group '{group.name}'"
        )

    group.vms.remove(vm)
    db.commit()

    logger.info(
        f"User {current_user.username} removed VM '{vm.name}' from group '{group.name}'"
    )

    return {
        "message": f"VM '{vm.name}' removed from group '{group.name}'",
        "group_id": group_id,
        "vm_id": vm_id,
    }


@router.post("/groups/{group_id}/preview")
async def preview_group_rules(
    group_id: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Preview which VMs match given rules (without saving)."""
    rules = body.get("rules", [])
    rules_match = body.get("rules_match", "all")

    if not rules:
        raise HTTPException(status_code=400, detail="rules list is required")

    errors = validate_rules(rules)
    if errors:
        raise HTTPException(
            status_code=400, detail=f"Invalid rules: {'; '.join(errors)}"
        )

    query = build_rule_query(db, rules, rules_match)
    vms = query.limit(200).all()
    total = query.count()

    return {
        "vms": [
            {
                "id": vm.id,
                "name": vm.name,
                "state": vm.state,
                "agent_hostname": vm.agent.hostname,
            }
            for vm in vms
        ],
        "total": total,
        "truncated": total > 200,
    }
