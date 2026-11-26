"""
Redis caching service with automatic reconnection
"""

import redis
import json
import pickle
import time
from typing import Optional, Any
import logging

from config import settings

logger = logging.getLogger(__name__)


class CacheService:
    """Redis caching service with automatic serialization and reconnection"""

    # Reconnection settings
    RECONNECT_BASE_DELAY = 1.0  # Initial delay in seconds
    RECONNECT_MAX_DELAY = 60.0  # Max delay between attempts
    RECONNECT_BACKOFF = 2.0  # Exponential backoff multiplier

    def __init__(self):
        self.redis_client = None
        self.enabled = False
        self.default_ttl = 300  # 5 minutes

        # Reconnection state
        self._last_reconnect_attempt = 0
        self._reconnect_delay = self.RECONNECT_BASE_DELAY
        self._consecutive_failures = 0

        # Initial connection attempt
        self._connect()

    def _connect(self) -> bool:
        """Attempt to connect to Redis"""
        try:
            self.redis_client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            self.redis_client.ping()
            self.enabled = True
            self._reconnect_delay = self.RECONNECT_BASE_DELAY
            self._consecutive_failures = 0
            logger.info(
                f"Connected to Redis at {settings.redis_host}:{settings.redis_port}"
            )
            return True
        except Exception as e:
            self.redis_client = None
            self.enabled = False
            self._consecutive_failures += 1
            if self._consecutive_failures == 1:
                logger.warning(f"Redis not available: {e}. Caching disabled.")
            return False

    def _try_reconnect(self) -> bool:
        """Attempt reconnection with exponential backoff"""
        if self.enabled:
            return True

        now = time.time()
        if now - self._last_reconnect_attempt < self._reconnect_delay:
            return False  # Too soon to retry

        self._last_reconnect_attempt = now

        if self._connect():
            logger.info("Redis reconnection successful")
            return True
        else:
            # Increase delay with exponential backoff
            self._reconnect_delay = min(
                self._reconnect_delay * self.RECONNECT_BACKOFF, self.RECONNECT_MAX_DELAY
            )
            if self._consecutive_failures % 10 == 0:
                logger.warning(
                    f"Redis reconnection failed ({self._consecutive_failures} attempts), "
                    f"next retry in {self._reconnect_delay:.0f}s"
                )
            return False

    def _ensure_connection(self) -> bool:
        """Ensure we have a connection, attempting reconnect if needed"""
        if self.enabled:
            return True
        return self._try_reconnect()

    def _make_key(self, *args) -> str:
        """Generate cache key from arguments"""
        key_parts = [str(arg) for arg in args]
        return ":".join(key_parts)

    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            return json.dumps(value).encode("utf-8")
        except (TypeError, ValueError):
            return pickle.dumps(value)

    def _deserialize(self, value: bytes) -> Any:
        """Deserialize value from storage"""
        if value is None:
            return None

        try:
            return json.loads(value.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return pickle.loads(value)

    async def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if not self._ensure_connection():
            return None

        try:
            value = self.redis_client.get(key)
            return self._deserialize(value)
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection lost during get: {e}")
            self.enabled = False
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set cached value with TTL"""
        if not self._ensure_connection():
            return False

        try:
            serialized = self._serialize(value)
            return bool(
                self.redis_client.setex(key, ttl or self.default_ttl, serialized)
            )
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection lost during set: {e}")
            self.enabled = False
            return False
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete cached value"""
        if not self._ensure_connection():
            return False

        try:
            return bool(self.redis_client.delete(key))
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection lost during delete: {e}")
            self.enabled = False
            return False
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False

    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern"""
        if not self._ensure_connection():
            return 0

        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection lost during invalidation: {e}")
            self.enabled = False
            return 0
        except Exception as e:
            logger.error(f"Cache invalidation error: {e}")
            return 0

    def get_stats(self) -> dict:
        """Get cache connection statistics"""
        return {
            "enabled": self.enabled,
            "consecutive_failures": self._consecutive_failures,
            "reconnect_delay": self._reconnect_delay,
            "host": settings.redis_host,
            "port": settings.redis_port,
        }
