"""Anonymous, synthetic-only endpoints for the OSS public demo mode."""

from config import settings
from database import get_db
from core.tenant_context import DemoContext
from demo.journey import DemoJourney, DemoJourneyError
from demo.sessions import COOKIE_NAME, DemoSessionError, DemoSessionService
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


class GroupRule(BaseModel):
    field: str = Field(pattern=r"^(name|state|agent_id|metadata\.environment)$")
    op: str = Field(pattern=r"^(eq|neq|in)$")
    value: str | list[str]


class GroupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    rules: list[GroupRule] = Field(min_length=1, max_length=5)
    rules_match: str = Field(default="all", pattern=r"^(all|any)$")


class ScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    vm_id: str | None = None
    vm_group_id: str | None = None
    cron_expression: str = Field(min_length=5, max_length=80)
    retention_days: int = Field(default=30, ge=1, le=90)
    backup_type: str = Field(default="full", pattern=r"^(full|incremental)$")
    enabled: bool = True

    @model_validator(mode="after")
    def exactly_one_target(self):
        if bool(self.vm_id) == bool(self.vm_group_id):
            raise ValueError("choose exactly one VM or group target")
        return self


class BackupRequest(BaseModel):
    vm_id: str
    backup_type: str = Field(default="full", pattern=r"^(full|incremental)$")
    scenario: str = Field(default="success", pattern=r"^(success|upload_failure)$")


class RestoreRequest(BaseModel):
    backup_id: str


def _enabled() -> None:
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="Not found")


async def _demo_db(db: Session = Depends(get_db)):
    _enabled()
    with DemoContext():
        yield db


def _service(db: Session = Depends(_demo_db)) -> DemoSessionService:
    return DemoSessionService(
        db,
        idle_minutes=settings.demo_session_idle_minutes,
        absolute_minutes=settings.demo_session_absolute_minutes,
        max_sessions=settings.demo_max_sessions,
    )


def _require(service: DemoSessionService, token: str | None):
    try:
        return service.require(token)
    except DemoSessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _journey(service: DemoSessionService, token: str | None) -> DemoJourney:
    return DemoJourney(_require(service, token), service.db)


def _run(action):
    try:
        return action()
    except DemoJourneyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _summary(session) -> dict:
    return {
        "session_id": session.id,
        "fixture_version": session.fixture_version,
        "expires_at": session.expires_at.isoformat() + "Z",
        "absolute_expires_at": session.absolute_expires_at.isoformat() + "Z",
        "environment": "demo",
        "simulated": True,
    }


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def create_session(response: Response, service: DemoSessionService = Depends(_service)):
    _enabled()
    try:
        created = service.create()
    except DemoSessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    response.set_cookie(
        COOKIE_NAME,
        created.token,
        max_age=settings.demo_session_absolute_minutes * 60,
        secure=settings.demo_cookie_secure,
        httponly=True,
        samesite="strict",
        path="/api/v1/demo",
    )
    return _summary(created.session)


@router.get("/sessions/current")
def current_session(
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _summary(_require(service, token))


@router.get("/state")
def get_state(
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    session = _require(service, token)
    return session.state


@router.post("/groups/preview")
def preview_group(
    request: GroupRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    journey = _journey(service, token)
    members = _run(
        lambda: journey.preview_group(
            [rule.model_dump() for rule in request.rules], request.rules_match
        )
    )
    return {"items": members, "total": len(members), "simulated": True}


@router.post("/groups", status_code=status.HTTP_201_CREATED)
def create_group(
    request: GroupRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    journey = _journey(service, token)
    return _run(
        lambda: journey.create_group(
            request.name,
            [rule.model_dump() for rule in request.rules],
            request.rules_match,
        )
    )


@router.put("/groups/{group_id}")
def update_group(
    group_id: str,
    request: GroupRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(
        lambda: _journey(service, token).update_group(
            group_id,
            request.name,
            [rule.model_dump() for rule in request.rules],
            request.rules_match,
        )
    )


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(
    request: ScheduleRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(
        lambda: _journey(service, token).create_schedule(
            request.model_dump(exclude_none=True)
        )
    )


@router.post("/backups", status_code=status.HTTP_201_CREATED)
def create_backup(
    request: BackupRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(
        lambda: _journey(service, token).create_backup(
            request.vm_id, request.backup_type, request.scenario
        )
    )


@router.post("/schedules/{schedule_id}/run", status_code=status.HTTP_201_CREATED)
def run_schedule(
    schedule_id: str,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(lambda: _journey(service, token).run_schedule(schedule_id))


@router.post("/backups/{backup_id}/retry")
def retry_backup(
    backup_id: str,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(lambda: _journey(service, token).retry_backup(backup_id))


@router.post("/restores", status_code=status.HTTP_201_CREATED)
def create_restore(
    request: RestoreRequest,
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    return _run(lambda: _journey(service, token).create_restore(request.backup_id))


@router.post("/reset")
def reset_session(
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    try:
        session = service.reset(token or "")
    except DemoSessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    return {**_summary(session), "state": session.state}


@router.delete("/sessions/current", status_code=status.HTTP_204_NO_CONTENT)
def destroy_session(
    token: str | None = Cookie(None, alias=COOKIE_NAME),
    service: DemoSessionService = Depends(_service),
):
    _enabled()
    service.destroy(token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(COOKIE_NAME, path="/api/v1/demo")
    return response
