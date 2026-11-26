"""
WebSocket connection management
Handles real-time client connections with automatic polling fallback
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Set
from fastapi import WebSocket
from starlette.websockets import WebSocketState
from core.task_lifetime import DispatchLifetime, owned_dispatch

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and broadcasting"""

    # Connection limits to prevent resource exhaustion
    MAX_CONNECTIONS_PER_USER = 5  # Max tabs/windows per user
    MAX_TOTAL_CONNECTIONS = 500  # Max total connections

    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        self._closing = {}
        self._close_tasks = {}
        self.DRAIN_TIMEOUT = 5.0
        # Store active connections by user_id
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Store connection metadata
        self.connection_meta: Dict[WebSocket, dict] = {}
        # Track rejected connections for monitoring
        self._rejected_count = 0

    def start(self):
        if (
            self.dispatch_lifetime.tasks
            or self.connection_meta
            or self._closing
            or self._close_tasks
        ):
            raise RuntimeError("Realtime socket custody remains unresolved")
        if (
            self.dispatch_lifetime.loop is not None
            and not self.dispatch_lifetime.closed
        ):
            raise RuntimeError("Realtime socket owner is already started")
        self.dispatch_lifetime = DispatchLifetime()
        self.dispatch_lifetime.loop = asyncio.get_running_loop()

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    def _owner(self):
        if (
            self.dispatch_lifetime.loop is not None
            and self.dispatch_lifetime.loop is not asyncio.get_running_loop()
        ):
            raise RuntimeError("Realtime socket requires its owning event loop")

    @owned_dispatch
    async def send_socket(self, socket, *, message=None, text=None):
        if socket not in self.connection_meta:
            raise RuntimeError("Realtime socket is not registered")
        try:
            if text is not None:
                await socket.send_text(text)
            else:
                await socket.send_json(message)
        except BaseException:
            await self.disconnect(socket)
            raise

    async def cleanup(self):
        self.close_admission()
        self._owner()
        # Retain socket custody even when cancelled route finally blocks unregister.
        self._closing.update(self.connection_meta)
        tasks = set(self.dispatch_lifetime.tasks)
        if asyncio.current_task() in tasks:
            raise RuntimeError("Realtime cannot drain its own delivery")
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=self.DRAIN_TIMEOUT)
            if pending:
                raise RuntimeError("Realtime socket work remains unresolved")
        for socket in self._closing:
            if socket not in self._close_tasks:
                self._close_tasks[socket] = asyncio.create_task(
                    socket.close(code=1001, reason="Server shutdown")
                )
        if self._close_tasks:
            await asyncio.wait(
                set(self._close_tasks.values()), timeout=self.DRAIN_TIMEOUT
            )
        for socket, task in list(self._close_tasks.items()):
            if not task.done():
                task.cancel()
                continue
            del self._close_tasks[socket]
            if task.cancelled() or task.exception() is not None:
                continue
            await self.disconnect(socket, closed=True)
            self._closing.pop(socket, None)
        if self._closing or self._close_tasks:
            raise RuntimeError("Realtime socket close remains unresolved")

    @owned_dispatch
    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        metadata: dict = None,
        *,
        subprotocol: str = None,
    ):
        """Accept and register new connection with limit enforcement"""
        from core.tenant_context import _validate_org_id

        if websocket in self.connection_meta or websocket in self._closing:
            raise RuntimeError("Realtime socket custody is already owned")
        if (
            not metadata
            or not metadata.get("org_id")
            or metadata["org_id"] == "default"
        ):
            await websocket.close(
                code=1008, reason="Authenticated organization required"
            )
            return False
        _validate_org_id(metadata["org_id"])
        # Check total connection limit
        total_connections = self.get_connection_count() + len(self._closing)
        if total_connections >= self.MAX_TOTAL_CONNECTIONS:
            self._rejected_count += 1
            logger.warning(
                f"WebSocket rejected: max total connections ({self.MAX_TOTAL_CONNECTIONS}) reached"
            )
            await websocket.close(code=1013, reason="Server at capacity")
            return False

        # Check per-user connection limit
        user_connections = len(self.active_connections.get(user_id, set())) + sum(
            meta["user_id"] == user_id for meta in self._closing.values()
        )
        if user_connections >= self.MAX_CONNECTIONS_PER_USER:
            self._rejected_count += 1
            logger.warning(
                f"WebSocket rejected for user {user_id}: max per-user connections "
                f"({self.MAX_CONNECTIONS_PER_USER}) reached"
            )
            await websocket.close(code=1013, reason="Too many connections")
            return False

        # Only the public protocol may be selected, never a credential offer.
        if subprotocol not in (None, "vnbui"):
            raise ValueError("Unsupported public WebSocket protocol")

        # Claim before accept so shutdown owns even an interrupted handshake.
        self._closing[websocket] = {"user_id": user_id}
        if subprotocol is None:
            await websocket.accept()
        else:
            await websocket.accept(subprotocol=subprotocol)
        if self.dispatch_lifetime.closed:
            raise RuntimeError("Dispatch admission is closed")

        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()

        self.active_connections[user_id].add(websocket)
        self.connection_meta[websocket] = {
            "user_id": user_id,
            "connected_at": datetime.utcnow(),
            "metadata": metadata or {},
        }
        self._closing.pop(websocket, None)

        logger.info(f"WebSocket connected for user {user_id}")

        # Send initial connection confirmation
        try:
            await websocket.send_json(
                {
                    "type": "connection",
                    "payload": {
                        "status": "connected",
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                }
            )
        except BaseException:
            # Registration precedes confirmation; the route has not entered its
            # receive-loop finally yet. Remove delivery admission, not custody.
            await self.disconnect(websocket)
            raise
        return True

    @owned_dispatch
    async def send_scoped(
        self, message, org_id, user_id=None, role=None, exclude_user=None
    ):
        """Match authenticated connection metadata, never a message's claims."""
        for socket, meta in list(self.connection_meta.items()):
            identity = meta["metadata"]
            if identity.get("org_id") != org_id:
                continue
            if exclude_user is not None and meta["user_id"] == exclude_user:
                continue
            if user_id is not None and meta["user_id"] != user_id:
                continue
            if role is not None and identity.get("role") != role:
                continue
            backup_id = identity.get("backup_id")
            if (
                backup_id is not None
                and message.get("payload", {}).get("backup_id") != backup_id
            ):
                continue
            try:
                await self.send_socket(socket, message=message)
            except Exception:
                await self.disconnect(socket)

    async def disconnect(self, websocket: WebSocket, *, closed=False):
        """Deregister delivery; retain custody until close or peer-disconnect proof."""
        self._owner()
        meta = self.connection_meta.get(websocket)
        if meta:
            self._closing.setdefault(websocket, meta)
            user_id = meta["user_id"]
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]

            del self.connection_meta[websocket]
            logger.info(f"WebSocket disconnected for user {user_id}")
        # A send exception (including cancellation) is not closure proof. Only
        # successful owned close or an observed ASGI disconnect retires custody.
        if closed or (
            getattr(websocket, "client_state", None) is WebSocketState.DISCONNECTED
        ):
            self._closing.pop(websocket, None)

    async def send_personal_message(self, message: dict, user_id: str):
        """Send message to specific user's connections"""
        from core.tenant_context import resolved_organization

        await self.send_scoped(message, resolved_organization(), user_id=user_id)

    async def broadcast(self, message: dict, exclude_user: str = None):
        """Broadcast within the authenticated producer's organization."""
        from core.tenant_context import resolved_organization

        await self.send_scoped(
            message, resolved_organization(), exclude_user=exclude_user
        )

    async def send_to_role(self, message: dict, role: str):
        """Role delivery is also bounded by producer organization."""
        from core.tenant_context import resolved_organization

        await self.send_scoped(message, resolved_organization(), role=role)

    def get_connection_count(self) -> int:
        """Get total number of active connections"""
        return sum(len(conns) for conns in self.active_connections.values())

    def get_user_count(self) -> int:
        """Get number of connected users"""
        return len(self.active_connections)

    def get_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": self.get_connection_count(),
            "unique_users": self.get_user_count(),
            "users": list(self.active_connections.keys()),
            "max_connections": self.MAX_TOTAL_CONNECTIONS,
            "max_per_user": self.MAX_CONNECTIONS_PER_USER,
            "rejected_count": self._rejected_count,
        }


# Global WebSocket manager instance
websocket_manager = WebSocketManager()
