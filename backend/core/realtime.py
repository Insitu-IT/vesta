"""
Real-time event broadcasting system
Supports both WebSocket push and polling fallback
"""

import asyncio
import inspect
import logging
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Dict, Optional, List
from dataclasses import dataclass
from collections import deque
from core.task_lifetime import DispatchLifetime, owned_dispatch

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Represents a real-time event"""

    type: str  # backup_started, backup_completed, agent_offline, etc.
    payload: dict
    timestamp: datetime
    org_id: str
    user_id: Optional[str] = None  # None = broadcast to all
    role: Optional[str] = None  # Send to specific role
    sequence: int = 0
    ttl: int = 300  # Time to live in seconds for polling


class RealtimeManager:
    """
    Manages real-time events and distribution
    Supports both WebSocket push and polling
    """

    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        # Store recent events for polling (circular buffer)
        self.event_history: deque = deque(maxlen=1000)
        self.event_history_ttl = 300  # 5 minutes
        self.process_id = str(uuid.uuid4())
        self.cursor_key = secrets.token_bytes(32)
        self.sequence = 0
        self.retired_sequence = 0

        # Event listeners (for other components to subscribe)
        self.listeners = []

    def start(self):
        if self.dispatch_lifetime.tasks:
            raise RuntimeError("Realtime delivery custody remains unresolved")
        if (
            self.dispatch_lifetime.loop is not None
            and not self.dispatch_lifetime.closed
        ):
            raise RuntimeError("Realtime delivery owner is already started")
        self.dispatch_lifetime = DispatchLifetime()
        self.dispatch_lifetime.loop = asyncio.get_running_loop()

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    async def cleanup(self):
        self.close_admission()
        if (
            self.dispatch_lifetime.loop is not None
            and self.dispatch_lifetime.loop is not asyncio.get_running_loop()
        ):
            raise RuntimeError("Realtime delivery requires its owning event loop")
        tasks = set(self.dispatch_lifetime.tasks)
        if asyncio.current_task() in tasks:
            raise RuntimeError("Realtime cannot drain its own delivery")
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=5)
            if pending:
                raise RuntimeError("Realtime delivery custody remains unresolved")
        self.event_history.clear()
        self.retired_sequence = self.sequence
        self.process_id = str(uuid.uuid4())

    @owned_dispatch
    async def emit_event(
        self,
        event_type: str,
        payload: dict,
        user_id: Optional[str] = None,
        role: Optional[str] = None,
    ):
        """
        Emit an event to connected clients
        """
        from core.tenant_context import resolved_organization

        self._clean_expired_events()
        self.sequence += 1
        event = Event(
            type=event_type,
            payload=payload,
            timestamp=datetime.now(timezone.utc),
            sequence=self.sequence,
            org_id=resolved_organization(),
            user_id=user_id,
            role=role,
        )

        # Store in history for polling
        if len(self.event_history) == self.event_history.maxlen:
            self.retired_sequence = max(
                self.retired_sequence, self.event_history[0].sequence
            )
        self.event_history.append(event)

        # Send via WebSocket if available
        await self._broadcast_websocket(event)

        # Notify internal listeners
        await self._notify_listeners(event)

        logger.debug(f"Event emitted: {event_type}")

    async def _broadcast_websocket(self, event: Event):
        """Send event via WebSocket"""
        # Import here to avoid circular dependency
        try:
            from .websocket import websocket_manager

            message = {
                "type": event.type,
                "payload": event.payload,
                "timestamp": event.timestamp.isoformat(),
            }

            await websocket_manager.send_scoped(
                message, event.org_id, user_id=event.user_id, role=event.role
            )

        except ImportError:
            # WebSocket manager not available yet
            pass
        except Exception as e:
            logger.warning(f"WebSocket broadcast failed: {e}")

    async def _notify_listeners(self, event: Event):
        """Notify internal listeners"""
        # Registry edits affect the next delivery, not an admitted snapshot.
        for listener in tuple(self.listeners):
            try:
                result = listener(event)
                if (
                    isinstance(result, asyncio.Future)
                    and result.get_loop() is not asyncio.get_running_loop()
                ):
                    # Its owner must settle it; never cancel or adopt foreign work.
                    raise RuntimeError("Foreign listener loop")
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.error("Realtime listener failed")

    def get_events_since(
        self,
        timestamp: Optional[datetime] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
        role: Optional[str] = None,
    ) -> List[Dict]:
        """
        Get events since timestamp (for polling)
        """
        if self.dispatch_lifetime.closed:
            raise RuntimeError("Dispatch admission is closed")
        if (
            self.dispatch_lifetime.loop is not None
            and self.dispatch_lifetime.loop is not asyncio.get_running_loop()
        ):
            raise RuntimeError("Realtime polling requires its owning event loop")
        # Clean expired events first
        self._clean_expired_events()

        # Filter events
        from core.tenant_context import resolved_organization

        org_id = resolved_organization()
        events = [e for e in self.event_history if e.org_id == org_id]
        events = [e for e in events if e.role is None or e.role == role]

        if timestamp:
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("Timestamp requires a UTC offset")
            timestamp = timestamp.astimezone(timezone.utc)
            events = [e for e in events if self._utc(e.timestamp) > timestamp]

        events = [e for e in events if e.user_id is None or e.user_id == user_id]

        # Limit results
        events = events[:limit]

        # Convert to dict format
        return [
            {"type": e.type, "payload": e.payload, "timestamp": e.timestamp.isoformat()}
            for e in events
        ]

    @staticmethod
    def _utc(value):
        # Historical in-process events used naive UTC; all new events are aware.
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )

    def _clean_expired_events(self):
        """Maintain actual TTL as well as the deque's hard capacity."""
        now = datetime.now(timezone.utc)
        retained = []
        for event in self.event_history:
            age = (now - self._utc(event.timestamp)).total_seconds()
            if age >= min(event.ttl, self.event_history_ttl):
                self.retired_sequence = max(self.retired_sequence, event.sequence)
            else:
                retained.append(event)
        self.event_history.clear()
        self.event_history.extend(retained)

    def _cursor(self, sequence, scope):
        body = json.dumps(
            {"v": 2, "p": self.process_id, "s": scope, "n": sequence, "t": time.time()},
            separators=(",", ":"),
        ).encode()
        signature = hmac.new(self.cursor_key, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body + signature).decode().rstrip("=")

    def get_event_page(self, cursor=None, user_id=None, role=None, limit=100):
        """A bounded process-local invalidation feed, never a durable event ledger.

        A reset boundary is captured before authoritative snapshot reads. Clients
        resynchronize then continue from that boundary, catching concurrent events.
        Different workers intentionally force a visible reset rather than skip data.
        """
        from core.tenant_context import resolved_organization

        # Keep the same lifetime/loop admission checks as legacy reads.
        self.get_events_since(user_id=user_id, role=role, limit=1)
        org_id = resolved_organization()
        scope = hashlib.sha256(
            json.dumps(
                [str(org_id), str(user_id), role], separators=(",", ":")
            ).encode()
        ).hexdigest()
        reason, sequence = None, self.sequence
        if cursor is None:
            reason = "initial"
        else:
            try:
                if len(cursor) > 2048:
                    raise ValueError()
                raw = base64.b64decode(
                    cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
                )
                body, signature = raw[:-32], raw[-32:]
                data = json.loads(body)
                if (
                    not isinstance(data, dict)
                    or data.get("v") != 2
                    or not isinstance(data.get("p"), str)
                ):
                    raise ValueError()
                if data["p"] != self.process_id:
                    reason = "process_changed"
                else:
                    if not hmac.compare_digest(
                        signature,
                        hmac.new(self.cursor_key, body, hashlib.sha256).digest(),
                    ):
                        raise ValueError()
                    if (
                        type(data.get("n")) is not int
                        or data["n"] < 0
                        or type(data.get("t")) not in (int, float)
                        or data["t"] > time.time() + 1
                    ):
                        raise ValueError()
                    if data.get("s") != scope:
                        reason = "scope_changed"
                    elif time.time() - data["t"] >= self.event_history_ttl:
                        reason = "cursor_expired"
                    elif data["n"] < self.retired_sequence:
                        reason = "history_lost"
                    elif data["n"] > self.sequence:
                        raise ValueError()
                    else:
                        sequence = data["n"]
            except (ValueError, TypeError, KeyError, UnicodeDecodeError):
                raise ValueError("Invalid realtime cursor") from None
        items, has_more = [], False
        if reason is None:
            visible = [
                e
                for e in self.event_history
                if e.sequence > sequence
                and e.org_id == org_id
                and (e.role is None or e.role == role)
                and (e.user_id is None or e.user_id == user_id)
            ]
            selected = visible[:limit]
            has_more = len(visible) > limit
            sequence = selected[-1].sequence if has_more else self.sequence
            items = [
                {
                    "type": e.type,
                    "payload": e.payload,
                    "timestamp": self._utc(e.timestamp).isoformat(),
                    "sequence": e.sequence,
                }
                for e in selected
            ]
        else:
            sequence = self.sequence
        return {
            "items": items,
            "next_cursor": self._cursor(sequence, scope),
            "has_more": has_more,
            "reset_required": reason is not None,
            "reset_reason": reason,
            "retention_seconds": self.event_history_ttl,
            "delivery": "best_effort",
        }

    def add_listener(self, listener):
        """Add an internal event listener"""
        self.listeners.append(listener)

    def remove_listener(self, listener):
        """Remove an internal event listener"""
        if listener in self.listeners:
            self.listeners.remove(listener)


# Global realtime manager instance
realtime = RealtimeManager()


# Helper functions for emitting common events
async def emit_backup_event(backup_id: str, status: str, **kwargs):
    """Emit backup-related event"""
    await realtime.emit_event(
        event_type=f"backup_{status}",
        payload={"backup_id": backup_id, "status": status, **kwargs},
    )


async def emit_agent_event(agent_id: str, status: str, **kwargs):
    """Emit agent-related event"""
    await realtime.emit_event(
        event_type=f"agent_{status}",
        payload={"agent_id": agent_id, "status": status, **kwargs},
    )


async def emit_vm_event(vm_id: str, event_type: str, **kwargs):
    """Emit VM-related event"""
    await realtime.emit_event(
        event_type=f"vm_{event_type}", payload={"vm_id": vm_id, **kwargs}
    )
