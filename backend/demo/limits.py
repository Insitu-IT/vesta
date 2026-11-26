"""Persistent rate limits and object quotas for public demo sessions."""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256

from models import DemoRateBucket
from sqlalchemy.exc import IntegrityError


class DemoLimitError(ValueError):
    def __init__(self, code: str, message: str, retry_after: int | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(message)


class DemoRateLimiter:
    def __init__(self, db, now_fn=datetime.utcnow):
        self.db = db
        self.now_fn = now_fn

    def check(self, namespace: str, value: str, limit: int, window_seconds: int = 60):
        if limit <= 0:
            raise ValueError("demo rate limit must be positive")
        now = self.now_fn()
        key_hash = sha256(f"{namespace}:{value}".encode()).hexdigest()
        bucket = (
            self.db.query(DemoRateBucket)
            .filter(DemoRateBucket.key_hash == key_hash)
            .with_for_update()
            .first()
        )
        if bucket is None:
            bucket = DemoRateBucket(
                key_hash=key_hash, window_started_at=now, request_count=1
            )
            self.db.add(bucket)
            try:
                self.db.commit()
                return
            except IntegrityError:
                # Another request created the same first-window bucket. Roll back
                # and re-enter through the row-locking path instead of failing open.
                self.db.rollback()
                return self.check(namespace, value, limit, window_seconds)
        elapsed = (now - bucket.window_started_at).total_seconds()
        if elapsed >= window_seconds:
            bucket.window_started_at = now
            bucket.request_count = 1
            self.db.commit()
            return
        if bucket.request_count >= limit:
            retry_after = max(1, int(window_seconds - elapsed))
            raise DemoLimitError(
                "DEMO_RATE_LIMITED",
                "Public demo request limit reached; retry after the current window.",
                retry_after,
            )
        bucket.request_count += 1
        self.db.commit()

    def cleanup(self, older_than_seconds: int = 300) -> int:
        cutoff = self.now_fn() - timedelta(seconds=older_than_seconds)
        count = (
            self.db.query(DemoRateBucket)
            .filter(DemoRateBucket.window_started_at < cutoff)
            .delete(synchronize_session=False)
        )
        self.db.commit()
        return count
