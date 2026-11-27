"""Installation-generated public trust for authenticated offsite recovery."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from core.recovery_signing import RecoveryUnavailable, recovery_trust
from database import get_db
from deps import get_admin_user

router = APIRouter(prefix="/api/v1/recovery", tags=["recovery"])


class RecoveryTrust(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema: Literal["vesta-recovery-trust/1"]
    installation_id: UUID
    org_id: UUID
    key_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


@router.get(
    "/trust",
    response_model=RecoveryTrust,
    openapi_extra={"x-required-roles": ["admin"]},
    responses={
        503: {
            "description": "Installation recovery trust unavailable",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["detail"],
                        "properties": {"detail": {"type": "string"}},
                    }
                }
            },
        }
    },
)
def get_recovery_trust(
    response: Response,
    db: Session = Depends(get_db),
    administrator=Depends(get_admin_user),
):
    """Download the public recovery trust document for the active organization."""
    try:
        result = recovery_trust(db, administrator.org_id)
    except RecoveryUnavailable:
        raise HTTPException(503, "Recovery trust is not available") from None
    response.headers["Cache-Control"] = "no-store"
    return result
