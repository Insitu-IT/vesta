"""Opaque, expiring session storage for the OSS public demo mode."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from models import DemoSession
from sqlalchemy import or_
from sqlalchemy import text
from sqlalchemy.orm import Session

from .fixture import FIXTURE_VERSION, build_fixture

COOKIE_NAME = "vnbui_demo_session"


class DemoSessionError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class CreatedSession:
    token: str
    session: DemoSession


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class DemoSessionService:
    """Manage session-local JSON state without commercial tenant machinery."""

    def __init__(
        self,
        db: Session,
        *,
        idle_minutes: int,
        absolute_minutes: int,
        max_sessions: int | None = None,
        now_fn=datetime.utcnow,
    ):
        if idle_minutes <= 0 or absolute_minutes <= 0:
            raise ValueError("demo session lifetimes must be positive")
        if idle_minutes > absolute_minutes:
            raise ValueError("demo idle lifetime cannot exceed absolute lifetime")
        self.db = db
        self.idle = timedelta(minutes=idle_minutes)
        self.absolute = timedelta(minutes=absolute_minutes)
        self.max_sessions = max_sessions
        self.now_fn = now_fn

    def create(self) -> CreatedSession:
        now = self.now_fn()
        if self.max_sessions is not None:
            # Serialize capacity admission in PostgreSQL so two simultaneous
            # anonymous arrivals cannot both observe the last free slot.
            if self.db.bind.dialect.name == "postgresql":
                self.db.execute(
                    text("SELECT pg_advisory_xact_lock(:key)"),
                    {"key": 0x564E42554944454D},
                )
            active = (
                self.db.query(DemoSession)
                .filter(
                    DemoSession.expires_at > now,
                    DemoSession.absolute_expires_at > now,
                )
                .count()
            )
            if active >= self.max_sessions:
                raise DemoSessionError(
                    "DEMO_CAPACITY_REACHED",
                    "The public demo is at session capacity; try again later.",
                )
        token = secrets.token_urlsafe(32)
        session = DemoSession(
            token_hash=_token_hash(token),
            fixture_version=FIXTURE_VERSION,
            state=build_fixture(now).as_dict(),
            created_at=now,
            last_seen_at=now,
            expires_at=now + self.idle,
            absolute_expires_at=now + self.absolute,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return CreatedSession(token=token, session=session)

    def require(self, token: str | None, *, touch: bool = True) -> DemoSession:
        if not token:
            raise DemoSessionError(
                "DEMO_SESSION_REQUIRED", "Start a demo session first."
            )
        session = (
            self.db.query(DemoSession)
            .filter(DemoSession.token_hash == _token_hash(token))
            .first()
        )
        if session is None:
            raise DemoSessionError("DEMO_SESSION_INVALID", "Demo session is not valid.")

        now = self.now_fn()
        if session.expires_at <= now or session.absolute_expires_at <= now:
            self.db.delete(session)
            self.db.commit()
            raise DemoSessionError("DEMO_SESSION_EXPIRED", "Demo session has expired.")

        if touch:
            session.last_seen_at = now
            session.expires_at = min(now + self.idle, session.absolute_expires_at)
            self.db.commit()
            self.db.refresh(session)
        return session

    def reset(self, token: str) -> DemoSession:
        session = self.require(token)
        now = self.now_fn()
        session.fixture_version = FIXTURE_VERSION
        session.state = build_fixture(now).as_dict()
        self.db.commit()
        self.db.refresh(session)
        return session

    def destroy(self, token: str | None) -> bool:
        if not token:
            return False
        session = (
            self.db.query(DemoSession)
            .filter(DemoSession.token_hash == _token_hash(token))
            .first()
        )
        if session is None:
            return False
        self.db.delete(session)
        self.db.commit()
        return True

    def cleanup_expired(self) -> int:
        now = self.now_fn()
        count = (
            self.db.query(DemoSession)
            .filter(
                or_(
                    DemoSession.expires_at <= now,
                    DemoSession.absolute_expires_at <= now,
                )
            )
            .delete(synchronize_session=False)
        )
        self.db.commit()
        return count
