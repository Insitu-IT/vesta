"""Offline registration administration and authenticated advisory summaries."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationError,
)
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from core.license_registration import (
    LicensingActor,
    LicensingService,
    RegistrationError,
    _json,
)
from database import get_db
from deps import get_current_user, get_installation_admin, get_installation_db

router = APIRouter(prefix="/api/v1/licensing", tags=["licensing"])


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImportRequest(StrictRequest):
    envelope: StrictStr = Field(max_length=65536)


class RegistrationURLRequest(StrictRequest):
    url: StrictStr = Field(max_length=2048)


class PrepareRequest(StrictRequest):
    confirm: StrictBool


class ConfirmRequest(PrepareRequest):
    challenge: StrictStr = Field(min_length=16, max_length=128)
    phrase: StrictStr = Field(max_length=128)


def _request_schema(model):
    # Publish typed bodies without decoding them ahead of installation authority.
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }


def _service(db, user):
    return LicensingService(db, LicensingActor(user.id, user.username, "user"))


def _invoke(method, *args):
    try:
        return method(*args)
    except RegistrationError as exc:
        raise HTTPException(
            exc.status_code, {"code": exc.code, "message": exc.message}
        ) from exc


async def _body(request, model):
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 135168:
            raise HTTPException(
                413,
                {
                    "code": "request_too_large",
                    "message": "Registration request is too large",
                },
            )
        chunks.append(chunk)
    try:
        data = _json(b"".join(chunks).decode("utf-8"), 135168)
        return model.model_validate(data)
    except (RegistrationError, UnicodeError, ValidationError) as exc:
        raise HTTPException(
            422, {"code": "invalid_request", "message": "Invalid registration request"}
        ) from exc


@router.get("/status")
def licensing_status(
    current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    return _invoke(_service(db, current_user).status)


@router.get("")
def licensing_details(
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    return _invoke(_service(db, current_user).details)


@router.post("/import", openapi_extra=_request_schema(ImportRequest))
async def import_registration(
    request: Request,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    data = await _body(request, ImportRequest)
    return await run_in_threadpool(
        _invoke, _service(db, current_user).import_certificate, data.envelope
    )


@router.put("/registration-url", openapi_extra=_request_schema(RegistrationURLRequest))
async def registration_url(
    request: Request,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    data = await _body(request, RegistrationURLRequest)
    return await run_in_threadpool(
        _invoke, _service(db, current_user).set_registration_url, data.url
    )


@router.post("/acknowledgement/prepare", openapi_extra=_request_schema(PrepareRequest))
async def prepare_acknowledgement(
    request: Request,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    data = await _body(request, PrepareRequest)
    return await run_in_threadpool(
        _invoke, _service(db, current_user).prepare_acknowledgement, data.confirm
    )


@router.post("/acknowledgement/confirm", openapi_extra=_request_schema(ConfirmRequest))
async def confirm_acknowledgement(
    request: Request,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    data = await _body(request, ConfirmRequest)
    return await run_in_threadpool(
        _invoke,
        _service(db, current_user).confirm_acknowledgement,
        data.challenge,
        data.phrase,
        data.confirm,
    )


@router.delete("/acknowledgement")
def clear_acknowledgement(
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    return _invoke(_service(db, current_user).clear_acknowledgement)
