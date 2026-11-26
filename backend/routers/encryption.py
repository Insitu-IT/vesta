"""
Encryption key management endpoints.

Manages KEKs (Key Encryption Keys) for envelope encryption.
Key material is never exposed via API — only metadata.
"""

import logging
import hashlib
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user, check_role, log_activity
from core.kms import get_kms_provider
from core.kms.local import LocalKMSProvider, StaleKeyRotation
from core.operator_requests import begin_admission, request_identity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/encryption", tags=["encryption"])


# ── Request/Response models ──────────────────────────────────────────────


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    algorithm: str = Field(default="aes-256-gcm")


class RotateKeyRequest(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=255)


class ExportKeysRequest(BaseModel):
    key_ids: list[str]
    password: str = Field(..., min_length=8)


class ImportKeysRequest(BaseModel):
    password: str = Field(..., min_length=8)


class KeyResponse(BaseModel):
    id: str
    name: str
    algorithm: str
    key_hash: str
    status: str
    provider: str
    created_at: str
    created_by: Optional[str] = None
    rotated_at: Optional[str] = None
    replaced_by_id: Optional[str] = None
    backed_up: bool
    backed_up_at: Optional[str] = None
    backed_up_locations: list[str] = []
    backup_count: int = 0


def _key_to_response(meta, backup_count: int = 0) -> dict:
    return {
        "id": meta.id,
        "name": meta.name,
        "algorithm": meta.algorithm,
        "key_hash": meta.key_hash,
        "status": meta.status,
        "provider": meta.provider,
        "created_at": meta.created_at.isoformat() + "Z" if meta.created_at else None,
        "created_by": meta.created_by,
        "rotated_at": meta.rotated_at.isoformat() + "Z" if meta.rotated_at else None,
        "replaced_by_id": meta.replaced_by_id,
        "backed_up": meta.backed_up,
        "backed_up_at": (
            meta.backed_up_at.isoformat() + "Z" if meta.backed_up_at else None
        ),
        "backed_up_locations": meta.backed_up_locations or [],
        "backup_count": backup_count,
    }


# ── Endpoints ────────────────────────────────────────────────────────────


@router.post("/keys")
def create_key(
    req: CreateKeyRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: str | None = Depends(request_identity),
):
    """Create a local KEK and its nonsecret admission receipt atomically."""
    check_role(current_user, ["admin"])
    kms = get_kms_provider()
    if not isinstance(kms, LocalKMSProvider):
        raise HTTPException(
            409, detail={"code": "provider_admission_contract_unavailable"}
        )
    admission = begin_admission(db, current_user, "encryption.create", req, request_id)
    if admission.replay:
        return admission.response()
    try:
        meta = kms.create_key_flush(db, req.name, req.algorithm, current_user.id)
    except ValueError as error:
        raise HTTPException(400, detail=str(error)) from None
    log_activity(
        db,
        current_user,
        "encryption_key_created",
        "encryption_key",
        meta.id,
        {"name": req.name, "algorithm": req.algorithm},
        commit=False,
    )
    return admission.finish(_key_to_response(meta))


@router.get("/keys")
async def list_keys(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all encryption keys (metadata only, never key material)"""
    check_role(current_user, ["admin"])

    kms = get_kms_provider()
    keys = await kms.list_keys()
    result = []
    for meta in keys:
        count = await kms.get_backup_count(meta.id)
        result.append(_key_to_response(meta, count))
    return {"items": result, "total": len(result)}


@router.get("/keys/{key_id}")
async def get_key(
    key_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get encryption key details + backup count"""
    check_role(current_user, ["admin"])

    try:
        kms = get_kms_provider()
        meta = await kms.get_key(key_id)
        count = await kms.get_backup_count(key_id)
        return _key_to_response(meta, count)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/keys/{key_id}/rotate")
def rotate_key(
    key_id: str,
    req: RotateKeyRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: str | None = Depends(request_identity),
):
    """Replay names the same successor; a new request for a stale key conflicts."""
    check_role(current_user, ["admin"])
    kms = get_kms_provider()
    if not isinstance(kms, LocalKMSProvider):
        raise HTTPException(
            409, detail={"code": "provider_admission_contract_unavailable"}
        )
    admission = begin_admission(
        db,
        current_user,
        "encryption.rotate",
        {"key_id": key_id, **req.model_dump(mode="json")},
        request_id,
    )
    if admission.replay:
        return admission.response()
    try:
        meta = kms.rotate_key_flush(db, key_id, req.new_name, current_user.id)
    except StaleKeyRotation:
        raise HTTPException(409, detail={"code": "stale_key_predecessor"}) from None
    except ValueError as error:
        raise HTTPException(400, detail=str(error)) from None
    log_activity(
        db,
        current_user,
        "encryption_key_rotated",
        "encryption_key",
        key_id,
        {"new_key_id": meta.id, "new_name": req.new_name},
        commit=False,
    )
    return admission.finish(_key_to_response(meta))


@router.post("/keys/{key_id}/revoke")
async def revoke_key(
    key_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke a key (soft delete). Fails if backups still reference it."""
    check_role(current_user, ["admin"])

    try:
        kms = get_kms_provider()
        await kms.revoke_key(key_id)
        log_activity(
            db, current_user, "encryption_key_revoked", "encryption_key", key_id, {}
        )
        return {"status": "revoked", "key_id": key_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/keys/export")
async def export_keys(
    req: ExportKeysRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export keys as password-protected file (local provider only)"""
    check_role(current_user, ["admin"])

    kms = get_kms_provider()
    if not kms.supports_export:
        raise HTTPException(
            status_code=400, detail="Current KMS provider does not support key export"
        )

    try:
        data = await kms.export_keys(req.key_ids, req.password)
        log_activity(
            db,
            current_user,
            "encryption_keys_exported",
            "encryption_key",
            None,
            {"key_count": len(req.key_ids)},
        )
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="vesta-keys-{datetime.utcnow().strftime("%Y%m%d")}.bin"'
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/keys/import")
async def import_keys(
    file: UploadFile = File(...),
    password: str = Form(""),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Import keys from password-protected export file"""
    check_role(current_user, ["admin"])

    kms = get_kms_provider()
    if not kms.supports_export:
        raise HTTPException(
            status_code=400, detail="Current KMS provider does not support key import"
        )

    if not password or len(password) < 8:
        raise HTTPException(
            status_code=400, detail="Password must be at least 8 characters"
        )

    try:
        data = await file.read()
        imported_ids = await kms.import_keys(data, password)
        log_activity(
            db,
            current_user,
            "encryption_keys_imported",
            "encryption_key",
            None,
            {"imported_count": len(imported_ids)},
        )
        return {"imported_key_ids": imported_ids, "count": len(imported_ids)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/keys/confirm-export")
async def confirm_export_custody(
    file: UploadFile = File(...),
    password: str = Form(...),
    location: str = Form(...),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify a saved encrypted export and record the admin's custody attestation."""
    check_role(current_user, ["admin"])
    kms = get_kms_provider()
    if not kms.supports_export:
        raise HTTPException(
            status_code=400, detail="Current KMS provider has no export"
        )
    data = await file.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Key export exceeds 4 MiB")
    try:
        key_ids = await kms.confirm_export_custody(data, password, location)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    digest = hashlib.sha256(data).hexdigest()
    log_activity(
        db,
        current_user,
        "encryption_export_custody_confirmed",
        "encryption_key",
        None,
        {"key_ids": key_ids, "sha256": digest, "location": location.strip()},
    )
    return {"key_ids": key_ids, "sha256": digest, "location": location.strip()}


@router.get("/provider")
async def get_provider_info(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get current KMS provider info"""
    check_role(current_user, ["admin"])

    try:
        kms = get_kms_provider()
        active_key = await kms.get_active_key()
        keys = await kms.list_keys()
        not_backed_up = sum(
            1 for k in keys if not k.backed_up and k.status != "revoked"
        )

        return {
            "provider": "local",
            "supports_export": kms.supports_export,
            "active_key": _key_to_response(active_key) if active_key else None,
            "total_keys": len(keys),
            "keys_not_backed_up": not_backed_up,
        }
    except ValueError:
        return {
            "provider": "local",
            "supports_export": True,
            "active_key": None,
            "total_keys": 0,
            "keys_not_backed_up": 0,
            "error": "KMS not configured — set VESTA_ENCRYPTION_KEY",
        }
